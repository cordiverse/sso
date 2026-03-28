import { Context } from 'cordis'
import { createPrivateKey, createSign } from 'node:crypto'
import type { SsoProvider } from '@cordisjs/plugin-sso'

declare module 'minato' {
  interface Tables {
    sso_apple: SSOApple
  }
}

export interface SSOApple {
  identityId: number
  sub: string // Apple's unique user identifier
  email?: string
  displayName?: string
  refreshToken?: string
}

export interface Config {
  /** Apple Services ID (com.example.app) */
  clientId: string
  /** Apple Team ID (10-char) */
  teamId: string
  /** Key ID for the private key */
  keyId: string
  /** Private key content (PEM) or path */
  privateKey: string
}

export const name = 'sso-apple'
export const inject = ['sso', 'sso.server']

// Apple requires a JWT as client_secret, signed with the developer's private key
function generateClientSecret(config: Config): string {
  const now = Math.floor(Date.now() / 1000)

  const header = {
    alg: 'ES256',
    kid: config.keyId,
  }

  const payload = {
    iss: config.teamId,
    iat: now,
    exp: now + 86400 * 180, // 6 months max
    aud: 'https://appleid.apple.com',
    sub: config.clientId,
  }

  const encodePart = (obj: any) => Buffer.from(JSON.stringify(obj)).toString('base64url')
  const signingInput = `${encodePart(header)}.${encodePart(payload)}`

  const key = createPrivateKey(config.privateKey)
  const signature = createSign('SHA256').update(signingInput).sign(key)

  // ES256 signature is DER-encoded, need to convert to raw r||s for JWT
  const r = signature.subarray(4, 4 + signature[3])
  const s = signature.subarray(6 + signature[3])
  const rawSig = Buffer.concat([
    r.length > 32 ? r.subarray(1) : r,
    s.length > 32 ? s.subarray(1) : s,
  ])

  return `${signingInput}.${rawSig.toString('base64url')}`
}

// Decode JWT without verification (Apple's id_token)
function decodeJWT(token: string): any {
  const [, payload] = token.split('.')
  return JSON.parse(Buffer.from(payload, 'base64url').toString())
}

export function apply(ctx: Context, config: Config) {
  ctx.model.extend('sso_apple', {
    identityId: 'unsigned(8)',
    sub: 'string(255)',
    email: 'string(255)',
    displayName: 'string(255)',
    refreshToken: 'string(255)',
  }, {
    primary: 'identityId',
    unique: [['sub']],
    foreign: { identityId: ['sso_identity', 'id'] },
  })

  const provider: SsoProvider = {
    name: 'apple',
    interactive: true,
    autoRegister: true,

    getAuthUrl(redirectUri: string, state: string) {
      const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: redirectUri,
        response_type: 'code id_token',
        response_mode: 'form_post',
        scope: 'name email',
        state,
      })
      return `https://appleid.apple.com/auth/authorize?${params}`
    },

    async resolve(credentials: any) {
      const { code, id_token, user: userJson } = credentials
      if (!code) return null

      // Exchange code for tokens
      const clientSecret = generateClientSecret(config)
      const tokenRes = await fetch('https://appleid.apple.com/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: config.clientId,
          client_secret: clientSecret,
          code,
          grant_type: 'authorization_code',
        }),
      })
      const tokenData = await tokenRes.json() as any
      if (tokenData.error) return null

      // User info is in the id_token (JWT)
      const idToken = decodeJWT(tokenData.id_token ?? id_token)
      const sub = idToken.sub as string

      // Apple only sends user info (name) on first login via form_post
      let displayName: string | undefined
      if (userJson) {
        try {
          const user = typeof userJson === 'string' ? JSON.parse(userJson) : userJson
          displayName = [user.name?.firstName, user.name?.lastName].filter(Boolean).join(' ')
        } catch {}
      }

      const [existing] = await ctx.model.get('sso_apple', { sub })
      if (existing) {
        // Update refresh token if provided
        if (tokenData.refresh_token) {
          await ctx.model.set('sso_apple', { identityId: existing.identityId }, {
            refreshToken: tokenData.refresh_token,
            ...(displayName ? { displayName } : {}),
          })
        }
        return { identityId: existing.identityId }
      }

      return null
    },

    async register(credentials: any) {
      const { identityId, code, id_token, user: userJson } = credentials
      if (!identityId) throw new Error('identityId required')

      const clientSecret = generateClientSecret(config)
      const tokenRes = await fetch('https://appleid.apple.com/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: config.clientId,
          client_secret: clientSecret,
          code,
          grant_type: 'authorization_code',
        }),
      })
      const tokenData = await tokenRes.json() as any
      const idToken = decodeJWT(tokenData.id_token ?? id_token)

      let displayName: string | undefined
      if (userJson) {
        try {
          const user = typeof userJson === 'string' ? JSON.parse(userJson) : userJson
          displayName = [user.name?.firstName, user.name?.lastName].filter(Boolean).join(' ')
        } catch {}
      }

      await ctx.model.create('sso_apple', {
        identityId,
        sub: idToken.sub,
        email: idToken.email,
        displayName,
        refreshToken: tokenData.refresh_token,
      })
      return {}
    },
  }

  // Apple uses form_post for callback (POST, not GET)
  ctx['sso.server'].route('post', '/callback/apple', async (routeCtx) => {
    const { code, state, id_token, user } = routeCtx.body ?? {}
    const result = await provider.resolve!({ code, state, id_token, user })
    if (result) {
      const identity = await ctx.sso.getIdentity(result.identityId)
      const token = await ctx.sso.createSession(identity!.userId, identity!.id)
      return { token }
    }
    if (provider.autoRegister) {
      const { user: ssoUser, identityId } = await ctx.sso.createUser('apple')
      await provider.register!({ identityId, code, id_token, user })
      const token = await ctx.sso.createSession(ssoUser.id, identityId)
      return { token }
    }
    return { error: 'ACCOUNT_NOT_FOUND' }
  })

  ctx.sso.register(provider)
}
