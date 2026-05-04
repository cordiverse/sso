import { Context, Inject } from 'cordis'
import { createPrivateKey, createSign, randomBytes } from 'node:crypto'
import { SsoProvider } from '@cordisjs/plugin-sso'
import { callbackResponse, decodeJwtPayload, handleOAuthCallback, StateStore } from '@cordisjs/oauth-utils'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.apple': SsoApple
  }
}

export interface SsoApple {
  identityId: number
  sub: string
  email?: string
  displayName?: string
  refreshToken?: string
}

export interface Config {
  clientId: string
  teamId: string
  keyId: string
  privateKey: string
  redirectUrl?: string
}

function generateClientSecret(config: Config): string {
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'ES256', kid: config.keyId }
  const payload = { iss: config.teamId, iat: now, exp: now + 86400 * 180, aud: 'https://appleid.apple.com', sub: config.clientId }
  const encodePart = (obj: any) => Buffer.from(JSON.stringify(obj)).toString('base64url')
  const signingInput = `${encodePart(header)}.${encodePart(payload)}`
  const key = createPrivateKey(config.privateKey)
  const signature = createSign('SHA256').update(signingInput).sign(key)
  const r = signature.subarray(4, 4 + signature[3])
  const s = signature.subarray(6 + signature[3])
  const rawSig = Buffer.concat([r.length > 32 ? r.subarray(1) : r, s.length > 32 ? s.subarray(1) : s])
  return `${signingInput}.${rawSig.toString('base64url')}`
}

function decodeJWT(token: string): any {
  return decodeJwtPayload(token)
}

@Inject('server')
@Inject('timer')
export default class AppleProvider extends SsoProvider {
  name = 'apple'
  type = 'redirect' as const
  interactive = true
  autoRegister = true

  private state: StateStore

  constructor(ctx: Context, private config: Config) {
    super(ctx)

    this.state = new StateStore(ctx)

    ctx.database.extend('sso.apple', {
      identityId: 'unsigned(8)',
      sub: 'string(255)',
      email: 'string(255)',
      displayName: 'string(255)',
      refreshToken: 'string(255)',
    }, {
      primary: 'identityId',
      unique: [['sub']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })

    ctx.server.post('/sso/callback/apple', async (req) => {
      let body: any = {}
      try { body = await req.json() } catch {}
      const { code, state, id_token, user } = body
      const entry = this.state.consume(state)
      if (!entry) return callbackResponse({ error: 'INVALID_STATE', status: 400 }, this.config.redirectUrl)
      const nonce = entry.payload?.nonce
      const linkUserId = entry.payload?.link?.userId as number | undefined

      try {
        const clientSecret = generateClientSecret(this.config)
        const tokenRes = await fetch('https://appleid.apple.com/auth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ client_id: this.config.clientId, client_secret: clientSecret, code, grant_type: 'authorization_code' }),
        })
        const tokenData = await tokenRes.json() as any
        if (tokenData.error) {
          return callbackResponse({ error: 'TOKEN_EXCHANGE_FAILED', status: 400 }, this.config.redirectUrl)
        }
        const idToken = decodeJWT(tokenData.id_token ?? id_token)
        if (nonce && idToken.nonce !== nonce) {
          return callbackResponse({ error: 'NONCE_MISMATCH', status: 400 }, this.config.redirectUrl)
        }
        const displayName = this.parseUserName(user)

        const [existing] = await this.ctx.database.get('sso.apple', { sub: idToken.sub })
        let resolveResult: { identityId: number } | null = null
        if (existing) {
          if (tokenData.refresh_token) {
            await this.ctx.database.set('sso.apple', { identityId: existing.identityId }, {
              refreshToken: tokenData.refresh_token, ...(displayName ? { displayName } : {}),
            })
          }
          resolveResult = { identityId: existing.identityId }
        }

        return await handleOAuthCallback({
          ctx,
          providerName: 'apple',
          autoRegister: this.autoRegister,
          linkUserId,
          resolveResult,
          registerFn: async (identityId, db) => {
            await db.create('sso.apple', {
              identityId,
              sub: idToken.sub,
              email: idToken.email,
              displayName,
              refreshToken: tokenData.refresh_token,
            })
          },
          redirectUrl: this.config.redirectUrl,
        })
      } catch (e) {
        console.warn('[sso-apple]', e)
        return callbackResponse({ error: 'OAUTH_CALLBACK_FAILED', status: 500 }, this.config.redirectUrl)
      }
    })
  }

  private parseUserName(userJson: any): string | undefined {
    try {
      const user = typeof userJson === 'string' ? JSON.parse(userJson) : userJson
      return [user.name?.firstName, user.name?.lastName].filter(Boolean).join(' ') || undefined
    } catch { return undefined }
  }

  getAuthUrl(redirectUri: string, state: string, link?: { userId: number }) {
    const nonce = randomBytes(16).toString('base64url')
    this.state.register(state, redirectUri, { nonce, ...(link ? { link } : {}) })
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      response_type: 'code id_token',
      response_mode: 'form_post',
      scope: 'name email',
      state,
      nonce,
    })
    return `https://appleid.apple.com/auth/authorize?${params}`
  }

  async resolve(credentials: any) {
    // The Apple flow is driven by POST /sso/callback/apple above; direct
    // POST /sso/sessions/apple is not a meaningful path.
    return null
  }
}
