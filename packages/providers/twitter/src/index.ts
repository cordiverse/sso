import { Context } from 'cordis'
import { createHash, randomBytes } from 'node:crypto'
import type {} from 'minato'
import type { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from '@cordisjs/plugin-server'

declare module 'minato' {
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
}

export const name = 'sso-twitter'
export const inject = ['sso', 'server']

interface PKCEChallenge {
  codeVerifier: string
  state: string
  redirectUri: string
  expiresAt: number
}

export function apply(ctx: Context, config: Config) {
  const challenges = new Map<string, PKCEChallenge>()

  ctx.model.extend('sso_twitter', {
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
    foreign: { identityId: ['sso_identity', 'id'] },
  })

  // PKCE: generate code_verifier and code_challenge
  function generatePKCE() {
    const codeVerifier = randomBytes(32).toString('base64url')
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url')
    return { codeVerifier, codeChallenge }
  }

  const provider: SsoProvider = {
    name: 'twitter',
    interactive: true,
    autoRegister: true,

    getAuthUrl(redirectUri: string, state: string) {
      const scope = config.scope ?? 'tweet.read users.read offline.access'
      const { codeVerifier, codeChallenge } = generatePKCE()

      // Store PKCE challenge for later verification
      challenges.set(state, {
        codeVerifier,
        state,
        redirectUri,
        expiresAt: Date.now() + 10 * 60 * 1000, // 10 min
      })
      ctx.setTimeout(() => challenges.delete(state), 10 * 60 * 1000)

      const params = new URLSearchParams({
        response_type: 'code',
        client_id: config.clientId,
        redirect_uri: redirectUri,
        scope,
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      })
      return `https://twitter.com/i/oauth2/authorize?${params}`
    },

    async resolve(credentials: any) {
      const { code, state } = credentials
      if (!code || !state) return null

      const pkce = challenges.get(state)
      if (!pkce) return null
      challenges.delete(state)

      if (Date.now() > pkce.expiresAt) return null

      // Exchange code for token (with PKCE code_verifier)
      const basicAuth = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64')
      const tokenRes = await fetch('https://api.twitter.com/2/oauth2/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${basicAuth}`,
        },
        body: new URLSearchParams({
          code,
          grant_type: 'authorization_code',
          redirect_uri: pkce.redirectUri,
          code_verifier: pkce.codeVerifier,
        }),
      })
      const tokenData = await tokenRes.json() as any
      if (tokenData.error) return null

      const { access_token, refresh_token, expires_in } = tokenData

      // Get user info
      const userRes = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url', {
        headers: { Authorization: `Bearer ${access_token}` },
      })
      const userData = await userRes.json() as any
      const user = userData.data

      const [existing] = await ctx.model.get('sso_twitter', { twitterId: user.id })
      if (existing) {
        await ctx.model.set('sso_twitter', { identityId: existing.identityId }, {
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
    },

    async register(credentials: any) {
      const { identityId, code, state } = credentials
      if (!identityId) throw new Error('identityId required')

      // Re-resolve to get user data (in practice should cache from resolve)
      const pkce = challenges.get(state)
      if (!pkce) throw new Error('PKCE challenge expired')
      challenges.delete(state)

      const basicAuth = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString('base64')
      const tokenRes = await fetch('https://api.twitter.com/2/oauth2/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${basicAuth}`,
        },
        body: new URLSearchParams({
          code,
          grant_type: 'authorization_code',
          redirect_uri: pkce.redirectUri,
          code_verifier: pkce.codeVerifier,
        }),
      })
      const tokenData = await tokenRes.json() as any

      const userRes = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      })
      const userData = await userRes.json() as any
      const user = userData.data

      await ctx.model.create('sso_twitter', {
        identityId,
        twitterId: user.id,
        username: user.username,
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        displayName: user.name,
        avatar: user.profile_image_url,
        tokenExpiresAt: tokenData.expires_in
          ? new Date(Date.now() + tokenData.expires_in * 1000) : undefined,
      })
      return {}
    },
  }

  ctx.server.get('/sso/callback/twitter', async (req) => {
    const url = new URL(req.url, 'http://localhost')
    const code = url.searchParams.get('code')!
    const state = url.searchParams.get('state')!
    const result = await provider.resolve!({ code, state })
    if (result) {
      const identity = await ctx.sso.getIdentity(result.identityId)
      const token = await ctx.sso.createSession(identity!.userId, identity!.id)
      return Response.json({ token })
    }
    if (provider.autoRegister) {
      const { user, identityId } = await ctx.sso.createUser('twitter')
      await provider.register!({ identityId, code, state })
      const token = await ctx.sso.createSession(user.id, identityId)
      return Response.json({ token })
    }
    return Response.json({ error: 'ACCOUNT_NOT_FOUND' }, { status: 401 })
  })

  ctx.sso.register(provider)
}
