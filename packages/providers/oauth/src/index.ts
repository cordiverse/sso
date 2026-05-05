import { Context, Inject } from 'cordis'
import { RedirectProvider, Sso, ssoError } from '@cordisjs/plugin-sso'
import { callbackResponse, decodeJwtPayload, handleOAuthCallback, PkceStore, StateStore } from '@cordisjs/oauth-utils'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-logger'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-timer'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.oauth': SsoOAuth
  }
}

export interface SsoOAuth {
  identityId: number
  provider: string
  externalId: string
  accessToken: string
  refreshToken?: string
  displayName?: string
  email?: string
  avatar?: string
  scope?: string
  tokenExpiresAt?: Date
}

export interface OAuthPreset {
  name: string
  authorizeUrl: string
  tokenUrl: string
  userInfoUrl: string
  defaultScope: string
  authorizeParams?: Record<string, string>
  tokenParams?: Record<string, string>
  tokenTransport?: 'header' | 'query'
  pkce?: 'S256' | 'plain' | false
  oidc?: boolean
  extractUser(data: any): {
    externalId: string
    displayName?: string
    email?: string
    avatar?: string
  }
  getRelated?(data: any): { provider: string; key: any }[]
  /**
   * Revoke the OAuth grant on the provider side, so the next authorize
   * forces a fresh consent page. Called on unlink. Should be idempotent —
   * treat "grant not found" / 404 as success.
   */
  revoke?(accessToken: string, clientId: string, clientSecret: string): Promise<void>
}

export const github: OAuthPreset = {
  name: 'github',
  authorizeUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userInfoUrl: 'https://api.github.com/user',
  defaultScope: 'read:user user:email',
  extractUser: (data) => ({
    externalId: String(data.id),
    displayName: data.login,
    email: data.email,
    avatar: data.avatar_url,
  }),
  async revoke(accessToken, clientId, clientSecret) {
    const auth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
    const res = await fetch(`https://api.github.com/applications/${clientId}/grant`, {
      method: 'DELETE',
      headers: {
        Authorization: `Basic ${auth}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ access_token: accessToken }),
    })
    if (!res.ok && res.status !== 404) {
      throw new Error(`github revoke failed: HTTP ${res.status}`)
    }
  },
}

export const google: OAuthPreset = {
  name: 'google',
  authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
  defaultScope: 'openid email profile',
  authorizeParams: { access_type: 'offline', prompt: 'consent' },
  tokenParams: { grant_type: 'authorization_code' },
  oidc: true,
  extractUser: (data) => ({
    externalId: data.sub ?? data.id,
    displayName: data.name,
    email: data.email,
    avatar: data.picture,
  }),
}

export const microsoft: OAuthPreset = {
  name: 'microsoft',
  authorizeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
  tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
  defaultScope: 'openid email profile User.Read',
  authorizeParams: { response_mode: 'query' },
  tokenParams: { grant_type: 'authorization_code' },
  oidc: true,
  extractUser: (data) => ({
    externalId: data.sub ?? data.id,
    displayName: data.name ?? data.displayName,
    email: data.email ?? data.mail ?? data.userPrincipalName ?? data.preferred_username,
    avatar: undefined,
  }),
}

export const discord: OAuthPreset = {
  name: 'discord',
  authorizeUrl: 'https://discord.com/oauth2/authorize',
  tokenUrl: 'https://discord.com/api/oauth2/token',
  userInfoUrl: 'https://discord.com/api/users/@me',
  defaultScope: 'identify email',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: data.id,
    displayName: data.global_name ?? data.username,
    email: data.email,
    avatar: data.avatar ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png` : undefined,
  }),
}

export const gitlab: OAuthPreset = {
  name: 'gitlab',
  authorizeUrl: 'https://gitlab.com/oauth/authorize',
  tokenUrl: 'https://gitlab.com/oauth/token',
  userInfoUrl: 'https://gitlab.com/api/v4/user',
  defaultScope: 'read_user',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: String(data.id),
    displayName: data.username,
    email: data.email,
    avatar: data.avatar_url,
  }),
}

export const facebook: OAuthPreset = {
  name: 'facebook',
  authorizeUrl: 'https://www.facebook.com/v21.0/dialog/oauth',
  tokenUrl: 'https://graph.facebook.com/v21.0/oauth/access_token',
  userInfoUrl: 'https://graph.facebook.com/me?fields=id,name,email,picture',
  defaultScope: 'email public_profile',
  extractUser: (data) => ({
    externalId: data.id,
    displayName: data.name,
    email: data.email,
    avatar: data.picture?.data?.url,
  }),
}

export const linkedin: OAuthPreset = {
  name: 'linkedin',
  authorizeUrl: 'https://www.linkedin.com/oauth/v2/authorization',
  tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
  userInfoUrl: 'https://api.linkedin.com/v2/userinfo',
  defaultScope: 'openid email profile',
  tokenParams: { grant_type: 'authorization_code' },
  oidc: true,
  extractUser: (data) => ({
    externalId: data.sub, displayName: data.name, email: data.email, avatar: data.picture,
  }),
}

export const slack: OAuthPreset = {
  name: 'slack',
  authorizeUrl: 'https://slack.com/openid/connect/authorize',
  tokenUrl: 'https://slack.com/api/openid.connect.token',
  userInfoUrl: 'https://slack.com/api/openid.connect.userInfo',
  defaultScope: 'openid email profile',
  oidc: true,
  extractUser: (data) => ({
    externalId: data.sub ?? data['https://slack.com/user_id'],
    displayName: data.name,
    email: data.email,
    avatar: data.picture,
  }),
}

export const gitee: OAuthPreset = {
  name: 'gitee',
  authorizeUrl: 'https://gitee.com/oauth/authorize',
  tokenUrl: 'https://gitee.com/oauth/token',
  userInfoUrl: 'https://gitee.com/api/v5/user',
  defaultScope: 'user_info',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: String(data.id),
    displayName: data.login,
    email: data.email,
    avatar: data.avatar_url,
  }),
}

export const dingtalk: OAuthPreset = {
  name: 'dingtalk',
  authorizeUrl: 'https://login.dingtalk.com/oauth2/auth',
  tokenUrl: 'https://api.dingtalk.com/v1.0/oauth2/userAccessToken',
  userInfoUrl: 'https://api.dingtalk.com/v1.0/contact/users/me',
  defaultScope: 'openid',
  tokenParams: { grantType: 'authorization_code' },
  extractUser: (data) => ({
    externalId: data.openId ?? data.unionId,
    displayName: data.nick,
    email: data.email,
    avatar: data.avatarUrl,
  }),
}

export const weibo: OAuthPreset = {
  name: 'weibo',
  authorizeUrl: 'https://api.weibo.com/oauth2/authorize',
  tokenUrl: 'https://api.weibo.com/oauth2/access_token',
  userInfoUrl: 'https://api.weibo.com/2/users/show.json',
  defaultScope: '',
  tokenTransport: 'query',
  pkce: false,
  extractUser: (data) => ({
    externalId: String(data.id ?? data.uid),
    displayName: data.screen_name ?? data.name,
    email: undefined,
    avatar: data.avatar_large ?? data.profile_image_url,
  }),
}

export const feishu: OAuthPreset = {
  name: 'feishu',
  authorizeUrl: 'https://passport.feishu.cn/suite/passport/oauth/authorize',
  tokenUrl: 'https://open.feishu.cn/open-apis/authen/v1/oidc/access_token',
  userInfoUrl: 'https://open.feishu.cn/open-apis/authen/v1/user_info',
  defaultScope: '',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => {
    const user = data.data ?? data
    return { externalId: user.open_id, displayName: user.name, email: user.email, avatar: user.avatar_url }
  },
  getRelated: (data) => {
    const user = data.data ?? data
    return [{ provider: 'satori', key: { platform: 'lark', pid: user.open_id } }]
  },
}

export function lark(isFeishu = false): OAuthPreset {
  if (isFeishu) return feishu
  const domain = 'https://open.larksuite.com'
  const authDomain = 'https://passport.larksuite.com'
  return {
    name: 'lark',
    authorizeUrl: `${authDomain}/suite/passport/oauth/authorize`,
    tokenUrl: `${domain}/open-apis/authen/v1/oidc/access_token`,
    userInfoUrl: `${domain}/open-apis/authen/v1/user_info`,
    defaultScope: '',
    tokenParams: { grant_type: 'authorization_code' },
    extractUser: (data) => {
      const user = data.data ?? data
      return { externalId: user.open_id, displayName: user.name, email: user.email, avatar: user.avatar_url }
    },
    getRelated: (data) => {
      const user = data.data ?? data
      return [{ provider: 'satori', key: { platform: 'lark', pid: user.open_id } }]
    },
  }
}

export interface Config {
  preset: OAuthPreset | string
  clientId: string
  clientSecret: string
  scope?: string
  name?: string
  authorizeUrl?: string
  tokenUrl?: string
  userInfoUrl?: string
  redirectUrl?: string
}

const builtinPresets: Record<string, OAuthPreset> = {
  github, google, microsoft, discord, gitlab, facebook, linkedin, slack, gitee, dingtalk, weibo, feishu,
}

@Inject('server')
@Inject('timer')
@Inject('logger')
export default class OAuthProvider extends RedirectProvider {
  name: string
  canBePrimary = true
  canStepUp = false
  jitProvisioning = true
  interactive = true

  private preset: OAuthPreset
  private scope: string
  private pkce?: PkceStore
  private state?: StateStore

  constructor(ctx: Context, private config: Config) {
    super(ctx)

    if (typeof config.preset === 'string') {
      if (config.preset === 'lark') {
        this.preset = lark()
      } else if (config.preset === 'none') {
        if (!config.name || !config.authorizeUrl || !config.tokenUrl || !config.userInfoUrl) {
          throw new Error('preset "none" requires name, authorizeUrl, tokenUrl, and userInfoUrl')
        }
        this.preset = {
          name: config.name,
          authorizeUrl: config.authorizeUrl,
          tokenUrl: config.tokenUrl,
          userInfoUrl: config.userInfoUrl,
          defaultScope: config.scope ?? '',
          extractUser: (data) => ({
            externalId: String(data.id ?? data.sub ?? data.user_id),
            displayName: data.name ?? data.login ?? data.username ?? data.display_name,
            email: data.email,
            avatar: data.avatar_url ?? data.avatar ?? data.picture,
          }),
        }
      } else if (builtinPresets[config.preset]) {
        this.preset = builtinPresets[config.preset]
      } else {
        throw new Error(`unknown preset: ${config.preset}`)
      }
    } else {
      this.preset = config.preset
    }

    this.name = this.preset.name
    this.scope = config.scope ?? this.preset.defaultScope

    const pkceMethod = this.preset.pkce ?? 'S256'
    if (pkceMethod !== false) {
      this.pkce = new PkceStore(ctx, { challengeMethod: pkceMethod })
    } else {
      this.state = new StateStore(ctx)
    }

    ctx.database.extend('sso.oauth', {
      identityId: 'unsigned(8)',
      provider: 'string(255)',
      externalId: 'string(255)',
      accessToken: 'string(255)',
      refreshToken: 'string(255)',
      displayName: 'string(255)',
      email: 'string(255)',
      avatar: 'text',
      scope: 'string(255)',
      tokenExpiresAt: 'timestamp',
    }, {
      primary: 'identityId',
      unique: [['provider', 'externalId']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })

    ctx.server.get(`/sso/callback/${this.name}`, async (req) => {
      const url = new URL(req.url, 'http://localhost')
      const code = url.searchParams.get('code')!
      const state = url.searchParams.get('state')!
      const entry = this.pkce ? this.pkce.consume(state) : this.state!.consume(state)
      if (!entry) return callbackResponse({ error: 'INVALID_STATE', status: 400 }, this.config.redirectUrl)
      const linkUserId = entry.payload?.link?.userId as number | undefined

      try {
        const tokenData = await this.exchangeToken(code, entry.redirectUri, (entry as any).codeVerifier) as any
        if (tokenData.error) {
          return callbackResponse({ error: 'TOKEN_EXCHANGE_FAILED', status: 400 }, this.config.redirectUrl)
        }
        const accessToken = tokenData.access_token ?? tokenData.data?.access_token
        if (!accessToken) {
          return callbackResponse({ error: 'NO_ACCESS_TOKEN', status: 400 }, this.config.redirectUrl)
        }
        const userInfoData = this.preset.oidc && tokenData.id_token
          ? decodeJwtPayload(tokenData.id_token)
          : await this.fetchUserInfo(accessToken)
        const userInfo = this.preset.extractUser(userInfoData)

        const [existing] = await this.ctx.database.get('sso.oauth', {
          provider: this.name, externalId: userInfo.externalId,
        })
        let resolveResult: { identityId: number } | null = null
        if (existing) {
          await this.ctx.database.set('sso.oauth', { identityId: existing.identityId }, {
            accessToken,
            refreshToken: tokenData.refresh_token ?? existing.refreshToken,
            displayName: userInfo.displayName,
            email: userInfo.email,
            avatar: userInfo.avatar,
            scope: this.scope,
            tokenExpiresAt: tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in * 1000) : undefined,
          })
          resolveResult = { identityId: existing.identityId }
        }

        return await handleOAuthCallback({
          ctx,
          providerName: this.name,
          jitProvisioning: this.jitProvisioning,
          linkUserId,
          resolveResult,
          display: userInfo.displayName,
          registerFn: async (identityId, db) => {
            await db.create('sso.oauth', {
              identityId,
              provider: this.name,
              externalId: userInfo.externalId,
              accessToken,
              refreshToken: tokenData.refresh_token,
              displayName: userInfo.displayName,
              email: userInfo.email,
              avatar: userInfo.avatar,
              scope: this.scope,
              tokenExpiresAt: tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in * 1000) : undefined,
            })
          },
          redirectUrl: this.config.redirectUrl,
        })
      } catch (e) {
        this.ctx.logger.warn('[sso-oauth]', e)
        return callbackResponse({ error: 'OAUTH_CALLBACK_FAILED', status: 500 }, this.config.redirectUrl)
      }
    })
  }

  private async exchangeToken(code: string, redirectUri: string, codeVerifier?: string): Promise<any> {
    const body: Record<string, string> = {
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
      redirect_uri: redirectUri,
      ...this.preset.tokenParams,
    }
    if (codeVerifier) body.code_verifier = codeVerifier

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }

    if (this.name === 'lark') {
      const appTokenRes = await fetch(this.preset.tokenUrl.replace('/authen/v1/oidc/access_token', '/auth/v3/app_access_token/internal'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_id: this.config.clientId, app_secret: this.config.clientSecret }),
      })
      const appTokenData = await appTokenRes.json() as any
      headers['Authorization'] = `Bearer ${appTokenData.app_access_token}`
      delete body.client_id
      delete body.client_secret
    }

    const res = await fetch(this.preset.tokenUrl, { method: 'POST', headers, body: JSON.stringify(body) })
    return res.json()
  }

  private async fetchUserInfo(accessToken: string): Promise<any> {
    const headers: Record<string, string> = {}
    let url = this.preset.userInfoUrl
    if (this.preset.tokenTransport === 'query') {
      url += `?access_token=${accessToken}`
    } else {
      headers['Authorization'] = `Bearer ${accessToken}`
    }
    const res = await fetch(url, { headers })
    return res.json()
  }

  getAuthUrl(redirectUri: string, state: string, link: { userId: number } | undefined, _ctx: Sso.StepContext) {
    const extras: Record<string, string> = {}
    const payload = link ? { link } : undefined
    if (this.pkce) {
      const issued = this.pkce.register(state, redirectUri, payload)
      extras.code_challenge = issued.codeChallenge
      extras.code_challenge_method = issued.codeChallengeMethod
    } else {
      this.state!.register(state, redirectUri, payload)
    }
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      state,
      ...(this.scope ? { scope: this.scope } : {}),
      ...(this.preset.authorizeParams ?? {}),
      ...extras,
    })
    if (this.name === 'lark') {
      params.delete('client_id')
      params.set('app_id', this.config.clientId)
    }
    return `${this.preset.authorizeUrl}?${params}`
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    if (this.preset.revoke) {
      const [row] = await db.get('sso.oauth', { identityId })
      if (row?.accessToken) {
        try {
          await this.preset.revoke(row.accessToken, this.config.clientId, this.config.clientSecret)
        } catch (e: any) {
          this.ctx.logger.warn('[sso-oauth] revoke failed:', e)
          throw ssoError(502, 'REVOKE_FAILED')
        }
      }
    }
    await db.remove('sso.oauth', { identityId })
  }
}
