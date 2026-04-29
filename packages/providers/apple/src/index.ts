import { Context, Inject } from 'cordis'
import { createPrivateKey, createSign } from 'node:crypto'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-database'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    sso_apple: SsoApple
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
  const [, payload] = token.split('.')
  return JSON.parse(Buffer.from(payload, 'base64url').toString())
}

@Inject('server')
export default class AppleProvider extends SsoProvider {
  name = 'apple'
  interactive = true
  autoRegister = true

  constructor(ctx: Context, private config: Config) {
    super(ctx)

    ctx.model.extend('sso_apple', {
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
      const result = await this.resolve!({ code, state, id_token, user })
      if (result) {
        const identity = await ctx.sso.getIdentity(result.identityId)
        const token = await ctx.sso.createSession(identity!.userId, identity!.id)
        return Response.json({ token })
      }
      if (this.autoRegister) {
        const { user: ssoUser, identityId } = await ctx.sso.createUser('apple')
        await this.register!({ identityId, code, id_token, user })
        const token = await ctx.sso.createSession(ssoUser.id, identityId)
        return Response.json({ token })
      }
      return Response.json({ error: 'ACCOUNT_NOT_FOUND' }, { status: 401 })
    })
  }

  private parseUserName(userJson: any): string | undefined {
    try {
      const user = typeof userJson === 'string' ? JSON.parse(userJson) : userJson
      return [user.name?.firstName, user.name?.lastName].filter(Boolean).join(' ') || undefined
    } catch { return undefined }
  }

  getAuthUrl(redirectUri: string, state: string) {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: redirectUri,
      response_type: 'code id_token',
      response_mode: 'form_post',
      scope: 'name email',
      state,
    })
    return `https://appleid.apple.com/auth/authorize?${params}`
  }

  async resolve(credentials: any) {
    const { code, id_token, user: userJson } = credentials
    if (!code) return null
    const clientSecret = generateClientSecret(this.config)
    const tokenRes = await fetch('https://appleid.apple.com/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: this.config.clientId, client_secret: clientSecret, code, grant_type: 'authorization_code' }),
    })
    const tokenData = await tokenRes.json() as any
    if (tokenData.error) return null
    const idToken = decodeJWT(tokenData.id_token ?? id_token)
    const displayName = this.parseUserName(userJson)
    const [existing] = await this.ctx.model.get('sso_apple', { sub: idToken.sub })
    if (existing) {
      if (tokenData.refresh_token) {
        await this.ctx.model.set('sso_apple', { identityId: existing.identityId }, {
          refreshToken: tokenData.refresh_token, ...(displayName ? { displayName } : {}),
        })
      }
      return { identityId: existing.identityId }
    }
    return null
  }

  async register(credentials: any) {
    const { identityId, code, id_token, user: userJson } = credentials
    if (!identityId) throw new Error('identityId required')
    const clientSecret = generateClientSecret(this.config)
    const tokenRes = await fetch('https://appleid.apple.com/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: this.config.clientId, client_secret: clientSecret, code, grant_type: 'authorization_code' }),
    })
    const tokenData = await tokenRes.json() as any
    const idToken = decodeJWT(tokenData.id_token ?? id_token)
    await this.ctx.model.create('sso_apple', {
      identityId,
      sub: idToken.sub,
      email: idToken.email,
      displayName: this.parseUserName(userJson),
      refreshToken: tokenData.refresh_token,
    })
    return {}
  }
}
