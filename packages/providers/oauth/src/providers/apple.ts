import { createPrivateKey, createSign, randomBytes } from 'node:crypto'
import type { Request } from '@cordisjs/plugin-server'
import { OAuthBaseConfig, OAuthBaseProvider, OAuthCallbackParams, OAuthTokenResponse, OAuthUserInfo, PkceEntry, StateEntry } from '../base'
import { decodeJwtPayload } from '../utils'
import { ssoError } from '@cordisjs/plugin-sso'

function generateClientSecret(config: AppleProvider.Config): string {
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'ES256', kid: config.keyId }
  const payload = {
    iss: config.teamId,
    iat: now,
    exp: now + 86400 * 180,
    aud: 'https://appleid.apple.com',
    sub: config.clientId,
  }
  const encodePart = (obj: any) => Buffer.from(JSON.stringify(obj)).toString('base64url')
  const signingInput = `${encodePart(header)}.${encodePart(payload)}`
  const key = createPrivateKey(config.privateKey)
  const signature = createSign('SHA256').update(signingInput).sign(key)
  const r = signature.subarray(4, 4 + signature[3])
  const s = signature.subarray(6 + signature[3])
  const rawSig = Buffer.concat([r.length > 32 ? r.subarray(1) : r, s.length > 32 ? s.subarray(1) : s])
  return `${signingInput}.${rawSig.toString('base64url')}`
}

class AppleProvider extends OAuthBaseProvider<AppleProvider.Config> {
  name = 'apple'
  protected readonly authorizeUrl = 'https://appleid.apple.com/auth/authorize'
  protected readonly tokenUrl = 'https://appleid.apple.com/auth/token'
  protected readonly scope = 'name email'
  protected override get usesPkce() { return false }
  protected override get callbackMethod(): 'POST' { return 'POST' }

  protected override get clientId() { return this.config.clientId }
  // Apple uses a dynamically-generated ES256 JWT as the client secret.
  protected override get clientSecret() { return generateClientSecret(this.config) }

  // Apple delivers the callback as form_post. Read JSON body instead of query.
  protected override async readCallbackParams(req: Request): Promise<OAuthCallbackParams> {
    let body: any = {}
    try { body = await req.json() } catch {}
    return {
      code: body.code ?? '',
      state: body.state ?? '',
      extra: { id_token: body.id_token, user: body.user },
    }
  }

  protected override async exchangeToken(
    code: string,
    _redirectUri: string,
    _entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code,
        grant_type: 'authorization_code',
      }),
    })
    return res.json() as Promise<OAuthTokenResponse>
  }

  protected override async fetchUserInfo(
    tokenData: OAuthTokenResponse,
    extra: any,
    statePayload: any,
  ): Promise<OAuthUserInfo> {
    const idToken = decodeJwtPayload(tokenData.id_token ?? extra?.id_token)
    const expectedNonce = statePayload?.nonce
    if (expectedNonce && idToken.nonce !== expectedNonce) {
      throw ssoError(400, 'NONCE_MISMATCH')
    }
    const display = this.parseUserName(extra?.user)
    return {
      externalId: idToken.sub,
      email: idToken.email,
      display,
      raw: { idToken },
    }
  }

  // Apple requires a nonce round-tripped through the state payload.
  protected override derivePayload(link: { userId: number } | undefined) {
    const nonce = randomBytes(16).toString('base64url')
    return { nonce, ...(link ? { link } : {}) }
  }

  protected override buildAuthorizeParams(
    redirectUri: string,
    state: string,
    _link: { userId: number } | undefined,
    _extras: Record<string, string>,
    payload?: any,
  ): URLSearchParams {
    const nonce = payload?.nonce
    return new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: redirectUri,
      response_type: 'code id_token',
      response_mode: 'form_post',
      scope: this.scope,
      state,
      ...(nonce ? { nonce } : {}),
    })
  }

  private parseUserName(userJson: any): string | undefined {
    try {
      const user = typeof userJson === 'string' ? JSON.parse(userJson) : userJson
      return [user?.name?.firstName, user?.name?.lastName].filter(Boolean).join(' ') || undefined
    } catch {
      return undefined
    }
  }
}

namespace AppleProvider {
  export interface Config extends OAuthBaseConfig {
    clientId: string
    teamId: string
    keyId: string
    privateKey: string
  }
}

export default AppleProvider
