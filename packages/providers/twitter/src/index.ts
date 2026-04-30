import { Context, Inject } from 'cordis'
import { SsoProvider } from '@cordisjs/plugin-sso'
import { callbackResponse, PkceStore } from '@cordisjs/oauth-utils'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    sso_twitter: SsoTwitter
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
  interactive = true
  autoRegister = true

  private pkce: PkceStore

  constructor(ctx: Context, private config: Config) {
    super(ctx)

    this.pkce = new PkceStore(ctx)

    ctx.database.extend('sso_twitter', {
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
      const result = await this.resolve!({ code, state })
      if (result) {
        const identity = await ctx.sso.getIdentity(result.identityId)
        const token = await ctx.sso.createSession(identity!.userId, identity!.id)
        return callbackResponse({ token }, this.config.redirectUrl)
      }
      if (this.autoRegister) {
        const { user, identityId } = await ctx.sso.createUser('twitter')
        await this.register!({ identityId, code, state })
        const token = await ctx.sso.createSession(user.id, identityId)
        return callbackResponse({ token }, this.config.redirectUrl)
      }
      return callbackResponse({ error: 'ACCOUNT_NOT_FOUND', status: 401 }, this.config.redirectUrl)
    })
  }

  getAuthUrl(redirectUri: string, state: string) {
    const scope = this.config.scope ?? 'tweet.read users.read offline.access'
    const { codeChallenge, codeChallengeMethod } = this.pkce.register(state, redirectUri)
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
    const { code, state } = credentials
    if (!code || !state) return null
    const pkce = this.pkce.consume(state)
    if (!pkce) return null

    const tokenData = await this.exchangeToken(code, pkce.redirectUri, pkce.codeVerifier)
    if (tokenData.error) return null
    const { access_token, refresh_token, expires_in } = tokenData
    const user = await this.fetchUser(access_token)

    const [existing] = await this.ctx.database.get('sso_twitter', { twitterId: user.id })
    if (existing) {
      await this.ctx.database.set('sso_twitter', { identityId: existing.identityId }, {
        accessToken: access_token,
        refreshToken: refresh_token,
        username: user.username,
        displayName: user.name,
        avatar: user.profile_image_url,
        tokenExpiresAt: expires_in ? new Date(Date.now() + expires_in * 1000) : undefined,
      })
      return { identityId: existing.identityId }
    }
    return null
  }

  async register(credentials: any) {
    const { identityId, code, state } = credentials
    if (!identityId) throw new Error('identityId required')
    const pkce = this.pkce.consume(state)
    if (!pkce) throw new Error('PKCE challenge expired')

    const tokenData = await this.exchangeToken(code, pkce.redirectUri, pkce.codeVerifier)
    const user = await this.fetchUser(tokenData.access_token)

    await this.ctx.database.create('sso_twitter', {
      identityId,
      twitterId: user.id,
      username: user.username,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      displayName: user.name,
      avatar: user.profile_image_url,
      tokenExpiresAt: tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in * 1000) : undefined,
    })
    return {}
  }
}
