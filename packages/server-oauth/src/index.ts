import { Context } from 'cordis'
import { Random } from 'cosmokit'
import { createHash } from 'node:crypto'
import type { SSO } from '@cordisjs/plugin-sso'

declare module 'minato' {
  interface Tables {
    oauth_client: OAuthClient
    oauth_code: OAuthCode
    oauth_token: OAuthToken
  }
}

export interface OAuthClient {
  clientId: string
  clientSecret: string
  name: string
  redirectUris: string     // JSON array
  scopes: string           // space-separated
  createdAt: Date
}

export interface OAuthCode {
  code: string
  clientId: string
  userId: number
  scope: string
  redirectUri: string
  codeChallenge?: string
  codeChallengeMethod?: string
  expiresAt: Date
}

export interface OAuthToken {
  accessToken: string
  refreshToken?: string
  clientId: string
  userId: number
  scope: string
  expiresAt: Date
  createdAt: Date
}

export interface Config {
  /** Access token lifetime in seconds (default: 3600) */
  tokenLifetime?: number
  /** Authorization code lifetime in seconds (default: 600) */
  codeLifetime?: number
  /** Refresh token lifetime in seconds (default: 30 days) */
  refreshTokenLifetime?: number
}

export const name = 'server-oauth'
export const inject = ['sso', 'server', 'minato']

export function apply(ctx: Context, config: Config = {}) {
  const {
    tokenLifetime = 3600,
    codeLifetime = 600,
    refreshTokenLifetime = 30 * 24 * 3600,
  } = config
  const sso: SSO = ctx.sso

  ctx.minato.extend('oauth_client', {
    clientId: 'string(255)',
    clientSecret: 'string(255)',
    name: 'string(255)',
    redirectUris: 'text',
    scopes: 'string(512)',
    createdAt: 'timestamp',
  }, { primary: 'clientId' })

  ctx.minato.extend('oauth_code', {
    code: 'string(255)',
    clientId: 'string(255)',
    userId: 'unsigned(8)',
    scope: 'string(512)',
    redirectUri: 'string(512)',
    codeChallenge: 'string(255)',
    codeChallengeMethod: 'string(10)',
    expiresAt: 'timestamp',
  }, { primary: 'code' })

  ctx.minato.extend('oauth_token', {
    accessToken: 'string(255)',
    refreshToken: 'string(255)',
    clientId: 'string(255)',
    userId: 'unsigned(8)',
    scope: 'string(512)',
    expiresAt: 'timestamp',
    createdAt: 'timestamp',
  }, { primary: 'accessToken' })

  async function validateClient(clientId: string, clientSecret?: string) {
    const [client] = await ctx.minato.get('oauth_client', { clientId })
    if (!client) return null
    if (clientSecret && client.clientSecret !== clientSecret) return null
    return client
  }

  function validateRedirectUri(client: OAuthClient, redirectUri: string): boolean {
    const uris: string[] = JSON.parse(client.redirectUris)
    return uris.includes(redirectUri)
  }

  function verifyPKCE(codeChallenge: string, codeChallengeMethod: string, codeVerifier: string): boolean {
    if (codeChallengeMethod === 'S256') {
      const hash = createHash('sha256').update(codeVerifier).digest('base64url')
      return hash === codeChallenge
    }
    // plain method
    return codeVerifier === codeChallenge
  }

  // GET /oauth/authorize — Authorization endpoint
  // In a real implementation, this would render a consent page.
  // For API use, it accepts the user's session token and issues a code directly.
  ctx.server.get('/oauth/authorize', async (koa) => {
    const {
      response_type, client_id, redirect_uri, scope, state,
      code_challenge, code_challenge_method,
    } = koa.query as Record<string, string>

    if (response_type !== 'code') {
      koa.status = 400
      koa.body = { error: 'unsupported_response_type' }
      return
    }

    const client = await validateClient(client_id)
    if (!client) {
      koa.status = 400
      koa.body = { error: 'invalid_client' }
      return
    }

    if (!validateRedirectUri(client, redirect_uri)) {
      koa.status = 400
      koa.body = { error: 'invalid_redirect_uri' }
      return
    }

    // Authenticate user via SSO session
    const token = koa.headers.authorization?.replace('Bearer ', '')
    const user = token ? await sso.validateSession(token) : null
    if (!user) {
      // Redirect to login (or return 401 for API clients)
      koa.status = 401
      koa.body = { error: 'login_required' }
      return
    }

    // Issue authorization code
    const code = Random.id(32, 36)
    await ctx.minato.create('oauth_code', {
      code,
      clientId: client_id,
      userId: user.id,
      scope: scope ?? '',
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      expiresAt: new Date(Date.now() + codeLifetime * 1000),
    })

    const params = new URLSearchParams({ code })
    if (state) params.set('state', state)
    koa.redirect(`${redirect_uri}?${params}`)
  })

  // POST /oauth/token — Token endpoint
  ctx.server.post('/oauth/token', async (koa) => {
    const body = koa.request.body as Record<string, string>
    const { grant_type } = body

    if (grant_type === 'authorization_code') {
      const { code, client_id, client_secret, redirect_uri, code_verifier } = body

      // Validate client
      const client = await validateClient(client_id, client_secret)
      // Allow public clients (no secret) when using PKCE
      const publicClient = !client_secret ? await validateClient(client_id) : null
      const validClient = client ?? publicClient
      if (!validClient) {
        koa.status = 401
        koa.body = { error: 'invalid_client' }
        return
      }

      // Validate code
      const [authCode] = await ctx.minato.get('oauth_code', { code })
      if (!authCode || authCode.clientId !== client_id) {
        koa.status = 400
        koa.body = { error: 'invalid_grant' }
        return
      }

      // Check expiry
      if (authCode.expiresAt < new Date()) {
        await ctx.minato.remove('oauth_code', { code })
        koa.status = 400
        koa.body = { error: 'invalid_grant', error_description: 'code expired' }
        return
      }

      // Check redirect_uri
      if (authCode.redirectUri !== redirect_uri) {
        koa.status = 400
        koa.body = { error: 'invalid_grant', error_description: 'redirect_uri mismatch' }
        return
      }

      // PKCE verification
      if (authCode.codeChallenge) {
        if (!code_verifier) {
          koa.status = 400
          koa.body = { error: 'invalid_grant', error_description: 'code_verifier required' }
          return
        }
        if (!verifyPKCE(authCode.codeChallenge, authCode.codeChallengeMethod ?? 'plain', code_verifier)) {
          koa.status = 400
          koa.body = { error: 'invalid_grant', error_description: 'PKCE verification failed' }
          return
        }
      }

      // Consume code
      await ctx.minato.remove('oauth_code', { code })

      // Issue tokens
      const accessToken = Random.id(32, 36)
      const refreshToken = Random.id(32, 36)
      const now = new Date()

      await ctx.minato.create('oauth_token', {
        accessToken,
        refreshToken,
        clientId: client_id,
        userId: authCode.userId,
        scope: authCode.scope,
        expiresAt: new Date(now.getTime() + tokenLifetime * 1000),
        createdAt: now,
      })

      koa.body = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: tokenLifetime,
        refresh_token: refreshToken,
        scope: authCode.scope,
      }
    } else if (grant_type === 'refresh_token') {
      const { refresh_token, client_id, client_secret } = body

      const client = await validateClient(client_id, client_secret)
      if (!client) {
        koa.status = 401
        koa.body = { error: 'invalid_client' }
        return
      }

      const [existing] = await ctx.minato.get('oauth_token', { refreshToken: refresh_token })
      if (!existing || existing.clientId !== client_id) {
        koa.status = 400
        koa.body = { error: 'invalid_grant' }
        return
      }

      // Rotate tokens
      await ctx.minato.remove('oauth_token', { accessToken: existing.accessToken })

      const accessToken = Random.id(32, 36)
      const refreshToken = Random.id(32, 36)
      const now = new Date()

      await ctx.minato.create('oauth_token', {
        accessToken,
        refreshToken,
        clientId: client_id,
        userId: existing.userId,
        scope: existing.scope,
        expiresAt: new Date(now.getTime() + tokenLifetime * 1000),
        createdAt: now,
      })

      koa.body = {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: tokenLifetime,
        refresh_token: refreshToken,
        scope: existing.scope,
      }
    } else {
      koa.status = 400
      koa.body = { error: 'unsupported_grant_type' }
    }
  })

  // GET /oauth/userinfo — UserInfo endpoint (OpenID Connect compatible)
  ctx.server.get('/oauth/userinfo', async (koa) => {
    const token = koa.headers.authorization?.replace('Bearer ', '')
    if (!token) {
      koa.status = 401
      koa.body = { error: 'invalid_token' }
      return
    }

    const [oauthToken] = await ctx.minato.get('oauth_token', { accessToken: token })
    if (!oauthToken || oauthToken.expiresAt < new Date()) {
      koa.status = 401
      koa.body = { error: 'invalid_token' }
      return
    }

    const user = await sso.getUser(oauthToken.userId)
    if (!user) {
      koa.status = 401
      koa.body = { error: 'invalid_token' }
      return
    }

    koa.body = {
      sub: String(user.id),
      name: user.name,
      updated_at: user.updatedAt ? Math.floor(user.updatedAt.getTime() / 1000) : undefined,
    }
  })

  // POST /oauth/revoke — Token revocation
  ctx.server.post('/oauth/revoke', async (koa) => {
    const { token: revokeToken } = koa.request.body as Record<string, string>
    if (!revokeToken) {
      koa.status = 400
      koa.body = { error: 'invalid_request' }
      return
    }

    // Try as access token
    const removed = await ctx.minato.remove('oauth_token', { accessToken: revokeToken })
    if (!removed.matched) {
      // Try as refresh token
      await ctx.minato.remove('oauth_token', { refreshToken: revokeToken })
    }

    koa.body = {}
  })
}
