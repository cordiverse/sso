import { Context } from 'cordis'
import type {} from '@cordisjs/plugin-database'
import { createHash, randomUUID } from 'node:crypto'
import type { Sso } from '@cordisjs/plugin-sso'
import type { Request } from '@cordisjs/plugin-server'
import z from 'schemastery'

declare module '@cordisjs/plugin-database' {
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
  redirectUris: string
  scopes: string
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
  tokenLifetime?: number
  codeLifetime?: number
  refreshTokenLifetime?: number
}

export const Config: z<Config> = z.object({
  tokenLifetime: z.natural().default(3600).description('access token 有效期（秒）。'),
  codeLifetime: z.natural().default(600).description('授权码有效期（秒）。'),
  refreshTokenLifetime: z.natural().default(30 * 24 * 3600).description('refresh token 有效期（秒）。'),
})

export const name = 'server-oauth'
export const inject = ['sso', 'server', 'model']

export function apply(ctx: Context, config: Config = {}) {
  const {
    tokenLifetime = 3600,
    codeLifetime = 600,
    // refreshTokenLifetime = 30 * 24 * 3600,
  } = config
  const sso: Sso = ctx.sso

  ctx.database.extend('oauth_client', {
    clientId: 'string(255)',
    clientSecret: 'string(255)',
    name: 'string(255)',
    redirectUris: 'text',
    scopes: 'string(512)',
    createdAt: 'timestamp',
  }, { primary: 'clientId' })

  ctx.database.extend('oauth_code', {
    code: 'string(255)',
    clientId: 'string(255)',
    userId: 'unsigned(8)',
    scope: 'string(512)',
    redirectUri: 'string(512)',
    codeChallenge: 'string(255)',
    codeChallengeMethod: 'string(10)',
    expiresAt: 'timestamp',
  }, { primary: 'code' })

  ctx.database.extend('oauth_token', {
    accessToken: 'string(255)',
    refreshToken: 'string(255)',
    clientId: 'string(255)',
    userId: 'unsigned(8)',
    scope: 'string(512)',
    expiresAt: 'timestamp',
    createdAt: 'timestamp',
  }, { primary: 'accessToken' })

  function getQuery(req: Request): Record<string, string> {
    const url = new URL(req.url, 'http://localhost')
    const query: Record<string, string> = {}
    url.searchParams.forEach((v, k) => { query[k] = v })
    return query
  }

  function getToken(req: Request): string | undefined {
    const header = req.headers.get('authorization')
    if (!header) return
    const [type, token] = header.split(' ')
    if (type.toLowerCase() === 'bearer') return token
  }

  async function validateClient(clientId: string, clientSecret?: string) {
    const [client] = await ctx.database.get('oauth_client', { clientId })
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
    return codeVerifier === codeChallenge
  }

  // GET /oauth/authorize
  ctx.server.get('/oauth/authorize', async (req) => {
    const query = getQuery(req)
    const {
      response_type, client_id, redirect_uri, scope, state,
      code_challenge, code_challenge_method,
    } = query

    if (response_type !== 'code') {
      return Response.json({ error: 'unsupported_response_type' }, { status: 400 })
    }

    const client = await validateClient(client_id)
    if (!client) {
      return Response.json({ error: 'invalid_client' }, { status: 400 })
    }

    if (!validateRedirectUri(client, redirect_uri)) {
      return Response.json({ error: 'invalid_redirect_uri' }, { status: 400 })
    }

    const token = getToken(req)
    const user = token ? await sso.validateSession(token) : null
    if (!user) {
      return Response.json({ error: 'login_required' }, { status: 401 })
    }

    const code = randomUUID()
    await ctx.database.create('oauth_code', {
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
    return Response.redirect(`${redirect_uri}?${params}`)
  })

  // POST /oauth/token
  ctx.server.post('/oauth/token', async (req) => {
    const body = await req.json() as Record<string, string>
    const { grant_type } = body

    if (grant_type === 'authorization_code') {
      const { code, client_id, client_secret, redirect_uri, code_verifier } = body

      const client = await validateClient(client_id, client_secret)
      const publicClient = !client_secret ? await validateClient(client_id) : null
      const validClient = client ?? publicClient
      if (!validClient) {
        return Response.json({ error: 'invalid_client' }, { status: 401 })
      }

      const [authCode] = await ctx.database.get('oauth_code', { code })
      if (!authCode || authCode.clientId !== client_id) {
        return Response.json({ error: 'invalid_grant' }, { status: 400 })
      }

      if (authCode.expiresAt < new Date()) {
        await ctx.database.remove('oauth_code', { code })
        return Response.json({ error: 'invalid_grant', error_description: 'code expired' }, { status: 400 })
      }

      if (authCode.redirectUri !== redirect_uri) {
        return Response.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, { status: 400 })
      }

      if (authCode.codeChallenge) {
        if (!code_verifier) {
          return Response.json({ error: 'invalid_grant', error_description: 'code_verifier required' }, { status: 400 })
        }
        if (!verifyPKCE(authCode.codeChallenge, authCode.codeChallengeMethod ?? 'plain', code_verifier)) {
          return Response.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, { status: 400 })
        }
      }

      await ctx.database.remove('oauth_code', { code })

      const accessToken = randomUUID()
      const refreshToken = randomUUID()
      const now = new Date()

      await ctx.database.create('oauth_token', {
        accessToken,
        refreshToken,
        clientId: client_id,
        userId: authCode.userId,
        scope: authCode.scope,
        expiresAt: new Date(now.getTime() + tokenLifetime * 1000),
        createdAt: now,
      })

      return Response.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: tokenLifetime,
        refresh_token: refreshToken,
        scope: authCode.scope,
      })
    } else if (grant_type === 'refresh_token') {
      const { refresh_token, client_id, client_secret } = body

      const client = await validateClient(client_id, client_secret)
      if (!client) {
        return Response.json({ error: 'invalid_client' }, { status: 401 })
      }

      const [existing] = await ctx.database.get('oauth_token', { refreshToken: refresh_token })
      if (!existing || existing.clientId !== client_id) {
        return Response.json({ error: 'invalid_grant' }, { status: 400 })
      }

      await ctx.database.remove('oauth_token', { accessToken: existing.accessToken })

      const accessToken = randomUUID()
      const refreshToken = randomUUID()
      const now = new Date()

      await ctx.database.create('oauth_token', {
        accessToken,
        refreshToken,
        clientId: client_id,
        userId: existing.userId,
        scope: existing.scope,
        expiresAt: new Date(now.getTime() + tokenLifetime * 1000),
        createdAt: now,
      })

      return Response.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: tokenLifetime,
        refresh_token: refreshToken,
        scope: existing.scope,
      })
    } else {
      return Response.json({ error: 'unsupported_grant_type' }, { status: 400 })
    }
  })

  // GET /oauth/userinfo
  ctx.server.get('/oauth/userinfo', async (req) => {
    const token = getToken(req)
    if (!token) {
      return Response.json({ error: 'invalid_token' }, { status: 401 })
    }

    const [oauthToken] = await ctx.database.get('oauth_token', { accessToken: token })
    if (!oauthToken || oauthToken.expiresAt < new Date()) {
      return Response.json({ error: 'invalid_token' }, { status: 401 })
    }

    const user = await sso.getUser(oauthToken.userId)
    if (!user) {
      return Response.json({ error: 'invalid_token' }, { status: 401 })
    }

    return Response.json({
      sub: String(user.id),
      // OIDC-wise, `name` is meant to be the human-readable full name and
      // `preferred_username` is the short login handle. We map them to our
      // split: sso.user.display → name (fallback to the handle), and
      // sso.user.name → preferred_username.
      name: user.display ?? user.name,
      preferred_username: user.name,
      updated_at: user.updatedAt ? Math.floor(user.updatedAt.getTime() / 1000) : undefined,
    })
  })

  // POST /oauth/revoke
  ctx.server.post('/oauth/revoke', async (req) => {
    const body = await req.json() as Record<string, string>
    const { token: revokeToken } = body
    if (!revokeToken) {
      return Response.json({ error: 'invalid_request' }, { status: 400 })
    }

    const removed = await ctx.database.remove('oauth_token', { accessToken: revokeToken })
    if (!removed.matched) {
      await ctx.database.remove('oauth_token', { refreshToken: revokeToken })
    }

    return Response.json({})
  })
}
