import { Context, Inject } from 'cordis'
import { SsoProvider } from '@cordisjs/plugin-sso'
import { callbackResponse, handleOAuthCallback, PkceStore } from '@cordisjs/oauth-utils'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-timer'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.twitter': SsoTwitter
  }
}

export interface SsoTwitter {
  identityId: number
  twitterId: string
  username: string
  accessToken: string
  refreshToken?: string
  displayName?: string
  avatar?: string
  tokenExpiresAt?: Date
}

export interface Config {
  clientId: string
  clientSecret: string
  scope?: string
  redirectUrl?: string
}

@Inject('server')
@Inject('timer')
export default class TwitterProvider extends SsoProvider {
  name = 'twitter'
  type = 'redirect' as const
  interactive = true
  autoRegister = true

  private pkce: PkceStore

  constructor(ctx: Context, private config: Config) {
    super(ctx)

    this.pkce = new PkceStore(ctx)

    ctx.database.extend('sso.twitter', {
      identityId: 'unsigned(8)',
      twitterId: 'string(255)',
      username: 'string(255)',
      accessToken: 'string(255)',
      refreshToken: 'string(255)',
      displayName: 'string(255)',
      avatar: 'text',
      tokenExpiresAt: 'timestamp',
    }, {
      primary: 'identityId',
      unique: [['twitterId']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })

    ctx.server.get('/sso/callback/twitter', async (req) => {
      const url = new URL(req.url, 'http://localhost')
      const code = url.searchParams.get('code')!
      const state = url.searchParams.get('state')!
      const pkce = this.pkce.consume(state)
      if (!pkce) return callbackResponse({ error: 'INVALID_STATE', status: 400 }, this.config.redirectUrl)
      const linkUserId = pkce.payload?.link?.userId as number | undefined

      try {
        const tokenData = await this.exchangeToken(code, pkce.redirectUri, pkce.codeVerifier)
        if (tokenData.error) {
          return callbackResponse({ error: 'TOKEN_EXCHANGE_FAILED', status: 400 }, this.config.redirectUrl)
        }
        const { access_token, refresh_token, expires_in } = tokenData
        const user = await this.fetchUser(access_token)

        const [existing] = await this.ctx.database.get('sso.twitter', { twitterId: user.id })
        let resolveResult: { identityId: number } | null = null
        if (existing) {
          await this.ctx.database.set('sso.twitter', { identityId: existing.identityId }, {
            accessToken: access_token,
            refreshToken: refresh_token,
            username: user.username,
            displayName: user.name,
            avatar: user.profile_image_url,
            tokenExpiresAt: expires_in ? new Date(Date.now() + expires_in * 1000) : undefined,
          })
          resolveResult = { identityId: existing.identityId }
        }

        return await handleOAuthCallback({
          ctx,
          providerName: 'twitter',
          autoRegister: this.autoRegister,
          linkUserId,
          resolveResult,
          registerFn: async (identityId, db) => {
            await db.create('sso.twitter', {
              identityId,
              twitterId: user.id,
              username: user.username,
              accessToken: access_token,
              refreshToken: refresh_token,
              displayName: user.name,
              avatar: user.profile_image_url,
              tokenExpiresAt: expires_in ? new Date(Date.now() + expires_in * 1000) : undefined,
            })
          },
          redirectUrl: this.config.redirectUrl,
        })
      } catch (e) {
        console.warn('[sso-twitter]', e)
        return callbackResponse({ error: 'OAUTH_CALLBACK_FAILED', status: 500 }, this.config.redirectUrl)
      }
    })
  }

  getAuthUrl(redirectUri: string, state: string, link?: { userId: number }) {
    const scope = this.config.scope ?? 'tweet.read users.read offline.access'
    const { codeChallenge, codeChallengeMethod } = this.pkce.register(state, redirectUri, link ? { link } : undefined)
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
    })
    return `https://twitter.com/i/oauth2/authorize?${params}`
  }

  private async exchangeToken(code: string, redirectUri: string, codeVerifier: string) {
    const basicAuth = Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString('base64')
    const res = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': `Basic ${basicAuth}` },
      body: new URLSearchParams({
        code, grant_type: 'authorization_code', redirect_uri: redirectUri, code_verifier: codeVerifier,
      }),
    })
    return res.json() as Promise<any>
  }

  private async fetchUser(accessToken: string) {
    const res = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    return ((await res.json()) as any).data
  }

  async resolve(credentials: any) {
    // Driven entirely by the /sso/callback/twitter handler above; direct
    // POST /sso/sessions/twitter is not a meaningful flow.
    return null
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    await db.remove('sso.twitter', { identityId })
  }
}
