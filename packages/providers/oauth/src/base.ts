import { Context, Inject, Service } from 'cordis'
import type { Database } from '@cordisjs/plugin-database'
import type { Request } from '@cordisjs/plugin-server'
import { RedirectProvider, Sso, ssoError } from '@cordisjs/plugin-sso'
import { callbackResponse, handleOAuthCallback, PkceEntry, PkceStore, StateEntry, StateStore } from './utils'
import z from 'schemastery'

export type { PkceEntry, StateEntry } from './utils'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.oauth': SsoOAuth
  }
}

/**
 * Row shape of the shared `sso.oauth` table. Every OAuth-like provider
 * (github / google / … / apple / twitter / qq / wechat) writes here; the
 * `provider` column is the discriminator.
 *
 * - `name` mirrors `sso.user.name` (handle; github login, twitter username).
 * - `display` mirrors `sso.user.display` (human-readable label).
 * - `accessToken` nullable because apple never returns one.
 * - `unionId` for Tencent-ecosystem (qq / wechat / dingtalk) cross-app identity.
 */
export interface SsoOAuth {
  identityId: number
  provider: string
  externalId: string
  name?: string
  accessToken?: string
  refreshToken?: string
  display?: string
  email?: string
  avatar?: string
  scope?: string
  tokenExpiresAt?: Date
  unionId?: string
}

export interface OAuthTokenResponse {
  access_token?: string
  refresh_token?: string
  id_token?: string
  expires_in?: number
  scope?: string
  token_type?: string
  error?: string
  [key: string]: any
}

export interface OAuthUserInfo {
  externalId: string
  name?: string
  display?: string
  email?: string
  avatar?: string
  unionId?: string
  raw?: any
}

export interface OAuthBaseConfig {
  scope?: string
  redirectUrl?: string
}

export const OAuthBaseConfig: z<OAuthBaseConfig> = z.object({
  scope: z.string().description('OAuth scope (空格分隔)。'),
  redirectUrl: z.string().description('回调成功后跳转的目标 URL。默认 server.baseUrl。'),
})

/** Standard config shape for providers using `clientId`/`clientSecret` naming. */
export interface StandardOAuthConfig extends OAuthBaseConfig {
  clientId: string
  clientSecret: string
}

export const StandardOAuthConfig: z<StandardOAuthConfig> = z.intersect([
  z.object({
    clientId: z.string().required().description('OAuth 应用 client_id。'),
    clientSecret: z.string().required().role('secret').description('OAuth 应用 client_secret。'),
  }),
  OAuthBaseConfig,
])

export interface OAuthCallbackParams {
  code: string
  state: string
  /** Anything else the subclass wants to forward (e.g. apple's `id_token` / `user`). */
  extra?: any
}

/**
 * Shared base for OAuth 2 / OIDC providers. Subclasses implement the per-
 * provider bits (URLs, token-exchange shape, userInfo shape); the base
 * handles PKCE/state, the callback route, the shared `sso.oauth` table
 * plumbing, call-into-handleOAuthCallback, and unlink (with optional revoke).
 */
@Inject('server')
@Inject('timer')
export abstract class OAuthBaseProvider<C extends OAuthBaseConfig = OAuthBaseConfig> extends RedirectProvider {
  canBePrimary = true
  canStepUp = false
  jitProvisioning = true
  interactive = true

  protected pkce?: PkceStore
  protected state?: StateStore

  abstract name: string

  protected abstract readonly authorizeUrl: string
  protected abstract readonly tokenUrl: string
  /** Only used by the default `fetchUserInfo`; OIDC subclasses that derive
   *  user info from `id_token` can leave it unset and override `fetchUserInfo`. */
  protected readonly userInfoUrl?: string
  protected abstract readonly scope: string

  /** OAuth client credentials. Getters so qq (`appId`/`appKey`) and wechat
   *  (`appId`/`appSecret`) can remap without needing a constructor. */
  protected get clientId(): string { return (this.config as any).clientId }
  protected get clientSecret(): string { return (this.config as any).clientSecret }

  /** `'S256'` | `'plain'` enables PKCE with that challenge method; `false`
   *  disables PKCE entirely (falls back to the state store). */
  protected readonly pkceMethod: 'S256' | 'plain' | false = 'S256'
  protected readonly callbackMethod: 'GET' | 'POST' = 'GET'
  /** Where the OAuth callback handler redirects the browser after success
   *  (fragment-appended token) or error. Defaults to `ctx.server.baseUrl`;
   *  a getter so `baseUrl` is read lazily (it may only settle once the server
   *  plugin finishes listening). */
  protected get redirectUrl(): string | undefined { return this.config.redirectUrl ?? this.ctx.server.baseUrl }

  constructor(ctx: Context, protected readonly config: C) {
    super(ctx)
  }

  /**
   * Runs in the fiber-active phase, after subclass class-field initializers
   * have taken effect. Registers the PKCE/state store, the `sso.oauth` schema,
   * and the callback route. `ctx.database.extend` is idempotent, so all sibling
   * providers calling it with the same spec is fine.
   */
  * [Service.init]() {
    if (this.pkceMethod) {
      this.pkce = new PkceStore(this.ctx, { challengeMethod: this.pkceMethod })
    } else {
      this.state = new StateStore(this.ctx)
    }

    this.ctx.database.extend('sso.oauth', {
      identityId: 'unsigned(8)',
      provider: 'string(255)',
      externalId: 'string(255)',
      name: 'string(255)',
      accessToken: 'string(255)',
      refreshToken: 'string(255)',
      display: 'string(255)',
      email: 'string(255)',
      avatar: 'text',
      scope: 'string(255)',
      tokenExpiresAt: 'timestamp',
      unionId: 'string(255)',
    }, {
      primary: 'identityId',
      unique: [['provider', 'externalId']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })

    const method = this.callbackMethod === 'POST' ? 'post' : 'get'
    this.ctx.server[method](`/sso/callback/${this.name}`, async (req) => this.handleCallback(req))

    yield this.ctx.sso.register(this)
  }

  /**
   * Optional: override to place extra bits in the state payload (e.g. apple's
   * nonce). Default is just `{ link }` if linking.
   */
  protected derivePayload(link: { userId: number } | undefined): any {
    return link ? { link } : undefined
  }

  /**
   * Default: standard OAuth 2 authorize params. Subclasses can override to
   * rename `client_id` → `app_id` / `appid`, add `nonce` / `response_mode`,
   * or inject provider-specific fragment suffixes.
   */
  protected buildAuthorizeParams(
    redirectUri: string,
    state: string,
    _link: { userId: number } | undefined,
    extras: Record<string, string>,
    _payload?: any,
  ): URLSearchParams {
    return new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      redirect_uri: redirectUri,
      state,
      ...(this.scope ? { scope: this.scope } : {}),
      ...extras,
    })
  }

  /**
   * Default: read `code` and `state` from the URL query. Apple and other
   * form_post providers override to read the request body.
   */
  protected async readCallbackParams(req: Request): Promise<OAuthCallbackParams> {
    const url = new URL(req.url, 'http://localhost')
    return {
      code: url.searchParams.get('code') ?? '',
      state: url.searchParams.get('state') ?? '',
    }
  }

  /**
   * Default: POST `application/x-www-form-urlencoded` to `tokenUrl` with the
   * RFC 6749 authorization_code body. Override for providers with non-standard
   * token endpoints (ES256 JWT secret, Basic auth, query string, two-stage
   * app-token, JSON bodies, etc).
   */
  protected async exchangeToken(
    code: string,
    redirectUri: string,
    entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code,
      redirect_uri: redirectUri,
    })
    if ((entry as PkceEntry).codeVerifier) {
      body.set('code_verifier', (entry as PkceEntry).codeVerifier)
    }
    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body,
    })
    return res.json() as Promise<OAuthTokenResponse>
  }

  /**
   * Default: GET `userInfoUrl` with Bearer auth, then run subclass's
   * `extractUser` on the response. Override for providers that decode
   * id_token (apple), use query-string tokens (weibo), or need two-stage
   * lookups (qq).
   *
   * `statePayload` is the payload originally stashed via `derivePayload`
   * (e.g. apple uses it to validate `nonce` against the id_token).
   */
  protected async fetchUserInfo(
    tokenData: OAuthTokenResponse,
    _callbackExtra?: any,
    _statePayload?: any,
  ): Promise<OAuthUserInfo> {
    if (!this.userInfoUrl) {
      throw new Error(`${this.name}: userInfoUrl not set and fetchUserInfo not overridden`)
    }
    if (!tokenData.access_token) throw ssoError(400, 'NO_ACCESS_TOKEN')
    const res = await fetch(this.userInfoUrl, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    })
    const data = await res.json()
    return { ...this.extractUser(data), raw: data }
  }

  /**
   * Map provider-native userInfo payload to our normalized shape. Ignored if
   * `fetchUserInfo` is overridden end-to-end.
   */
  protected extractUser(_data: any): OAuthUserInfo {
    throw new Error(`${this.name}: extractUser not implemented`)
  }

  /**
   * Optional: revoke the provider-side grant on unlink. If implemented and
   * throws, `unlink` fails with 502 REVOKE_FAILED. Should be idempotent (treat
   * 404 / already-revoked as success).
   */
  protected revokeGrant?(row: SsoOAuth): Promise<void>

  // Shared `sso.oauth` row ops. Private by design — every provider uses
  // the shared table with identical logic. Promote to protected only when
  // a concrete subclass genuinely needs a different table.

  private async resolveRow(externalId: string): Promise<{ identityId: number } | null> {
    const [row] = await this.ctx.database.get('sso.oauth', { provider: this.name, externalId })
    return row ? { identityId: row.identityId } : null
  }

  private async writeRow(
    identityId: number,
    db: Database,
    tokenData: OAuthTokenResponse,
    userInfo: OAuthUserInfo,
  ): Promise<void> {
    await db.create('sso.oauth', {
      identityId,
      provider: this.name,
      externalId: userInfo.externalId,
      name: userInfo.name,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      display: userInfo.display,
      email: userInfo.email,
      avatar: userInfo.avatar,
      scope: this.scope || undefined,
      tokenExpiresAt: tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in * 1000) : undefined,
      unionId: userInfo.unionId,
    })
  }

  private async updateRow(
    identityId: number,
    tokenData: OAuthTokenResponse,
    userInfo: OAuthUserInfo,
  ): Promise<void> {
    const patch: Partial<SsoOAuth> = {}
    if (userInfo.name !== undefined) patch.name = userInfo.name
    if (tokenData.access_token !== undefined) patch.accessToken = tokenData.access_token
    if (tokenData.refresh_token !== undefined) patch.refreshToken = tokenData.refresh_token
    if (userInfo.display !== undefined) patch.display = userInfo.display
    if (userInfo.email !== undefined) patch.email = userInfo.email
    if (userInfo.avatar !== undefined) patch.avatar = userInfo.avatar
    if (userInfo.unionId !== undefined) patch.unionId = userInfo.unionId
    if (this.scope) patch.scope = this.scope
    if (tokenData.expires_in) patch.tokenExpiresAt = new Date(Date.now() + tokenData.expires_in * 1000)
    if (Object.keys(patch).length) {
      await this.ctx.database.set('sso.oauth', { identityId }, patch)
    }
  }

  private async loadRow(identityId: number, db: Database): Promise<SsoOAuth | null> {
    const [row] = await db.get('sso.oauth', { identityId })
    return row ?? null
  }

  private async deleteRow(identityId: number, db: Database): Promise<void> {
    await db.remove('sso.oauth', { identityId })
  }

  // Public entry points (not usually overridden)

  async getAuthUrl(
    redirectUri: string,
    state: string,
    link: { userId: number } | undefined,
    _ctx: Sso.StepContext,
  ): Promise<string> {
    const extras: Record<string, string> = {}
    const payload = this.derivePayload(link)
    if (this.pkce) {
      const issued = this.pkce.register(state, redirectUri, payload)
      extras.code_challenge = issued.codeChallenge
      extras.code_challenge_method = issued.codeChallengeMethod
    } else {
      this.state!.register(state, redirectUri, payload)
    }
    const params = this.buildAuthorizeParams(redirectUri, state, link, extras, payload)
    return `${this.authorizeUrl}?${params}`
  }

  private async handleCallback(req: Request): Promise<Response> {
    const { code, state, extra } = await this.readCallbackParams(req)
    if (!code || !state) {
      return callbackResponse({ error: 'INVALID_REQUEST', status: 400 }, this.redirectUrl)
    }
    const entry = this.pkce ? this.pkce.consume(state) : this.state!.consume(state)
    if (!entry) return callbackResponse({ error: 'INVALID_STATE', status: 400 }, this.redirectUrl)
    const linkUserId = entry.payload?.link?.userId as number | undefined

    try {
      const tokenData = await this.exchangeToken(code, entry.redirectUri, entry)
      if (tokenData.error) {
        return callbackResponse({ error: 'TOKEN_EXCHANGE_FAILED', status: 400 }, this.redirectUrl)
      }

      const userInfo = await this.fetchUserInfo(tokenData, extra, entry.payload)

      const existing = await this.resolveRow(userInfo.externalId)

      return await handleOAuthCallback({
        ctx: this.ctx,
        providerName: this.name,
        jitProvisioning: this.jitProvisioning,
        linkUserId,
        resolveResult: existing,
        // Fall back to the OAuth handle when seeding `sso.user.display` for a
        // new user / fresh link — but keep `userInfo.display` raw for the
        // snapshot in `sso.oauth` so we don't clobber a richer label there.
        display: userInfo.display ?? userInfo.name,
        registerFn: async (identityId, db) => {
          await this.writeRow(identityId, db, tokenData, userInfo)
        },
        // Refresh the existing row only when handleOAuthCallback decides to
        // actually reuse this identity (login or same-user re-link). On
        // ALREADY_LINKED rejection this never runs, so we don't silently
        // touch a stranger's row.
        updateFn: existing
          ? async () => this.updateRow(existing.identityId, tokenData, userInfo)
          : undefined,
        redirectUrl: this.redirectUrl,
      })
    } catch (e) {
      this.ctx.logger.warn(`[sso-${this.name}]`, e)
      if (typeof (e as any)?.status === 'number' && typeof (e as any)?.code === 'string') {
        return callbackResponse({ error: (e as any).code, status: (e as any).status }, this.redirectUrl)
      }
      return callbackResponse({ error: 'OAUTH_CALLBACK_FAILED', status: 500 }, this.redirectUrl)
    }
  }

  async unlink(identityId: number, db: Database = this.ctx.database): Promise<void> {
    if (this.revokeGrant) {
      const row = await this.loadRow(identityId, db)
      if (row) {
        try {
          await this.revokeGrant(row)
        } catch (e) {
          this.ctx.logger.warn(`[sso-${this.name}] revoke failed:`, e)
          throw ssoError(502, 'REVOKE_FAILED')
        }
      }
    }
    await this.deleteRow(identityId, db)
  }
}
