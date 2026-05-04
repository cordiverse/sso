import { Context, Inject } from 'cordis'
import { randomBytes } from 'node:crypto'
import {
  AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  WebAuthnCredential,
} from '@simplewebauthn/server'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-timer'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.webauthn': SsoWebAuthn
  }
}

export interface SsoWebAuthn {
  identityId: number
  credentialId: string
  publicKey: string
  signCount: number
  deviceType: string
  backedUp: boolean
  deviceName?: string
  transports?: string
  createdAt: Date
  lastUsedAt?: Date
}

export interface Config {
  // All three default to values derived from ctx.server.baseUrl. Set
  // explicitly only when you need to override — most commonly when the
  // server sits behind a reverse proxy AND ctx.server.config.baseUrl isn't
  // already set, OR when you want rpId to be a parent domain for cross-
  // subdomain passkey sharing.
  rpName?: string  // app name shown in the OS passkey picker; default 'Cordis'
  rpId?: string    // registrable suffix of the server's origin, derived from baseUrl by default
  origin?: string  // full scheme://host[:port] of the server, derived from baseUrl by default
  timeout?: number // challenge TTL in ms; default 60000
}

@Inject('server')
@Inject('timer')
export default class WebAuthnProvider extends SsoProvider {
  name = 'webauthn'
  type = 'webauthn' as const
  interactive = true
  autoRegister = false

  private challenges = new Map<string, PendingChallenge>()
  private rpName: string
  private rpId: string
  private origin: string
  private timeout: number

  constructor(ctx: Context, config: Config = {}) {
    super(ctx)
    // Derive defaults from ctx.server.baseUrl. baseUrl already respects
    // server.config.baseUrl (explicitly configured public URL behind a
    // proxy) and any intercept path prefix, so it's the right source of
    // truth for "what URL will the browser actually use".
    //
    // Quirk: when the server binds to 0.0.0.0 / :: (default), baseUrl
    // resolves to 127.0.0.1:PORT. Browsers in local dev almost always use
    // the 'localhost' alias, and WebAuthn's rpId check is a strict string
    // match against the browser's hostname — so fall back to 'localhost'
    // for loopback addresses. If the user actually accesses via 127.0.0.1
    // (or a LAN IP), they need to set `origin` + `rpId` explicitly.
    const base = new URL(ctx.server.baseUrl)
    let hostname = base.hostname
    if (hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]') {
      hostname = 'localhost'
    }
    const port = base.port ? `:${base.port}` : ''
    this.rpName = config.rpName ?? 'Cordis'
    this.rpId = config.rpId ?? hostname
    this.origin = config.origin ?? `${base.protocol}//${hostname}${port}`
    this.timeout = config.timeout ?? 60000

    ctx.database.extend('sso.webauthn', {
      identityId: 'unsigned(8)',
      credentialId: 'string(512)',
      publicKey: 'text',
      signCount: 'unsigned(8)',
      deviceType: 'string(32)',
      backedUp: { type: 'boolean', initial: false },
      deviceName: 'string(255)',
      transports: 'string(255)',
      createdAt: 'timestamp',
      lastUsedAt: 'timestamp',
    }, {
      primary: 'identityId',
      unique: [['credentialId']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  private async getCredentialsForUser(userId: number): Promise<WebAuthnCredential[]> {
    const identities = await this.ctx.sso.getIdentities(userId)
    const ids = identities.filter(i => i.provider === 'webauthn').map(i => i.id)
    if (!ids.length) return []
    const records = await this.ctx.database.get('sso.webauthn', { identityId: { $in: ids } })
    return records.map(r => ({
      id: r.credentialId,
      publicKey: Buffer.from(r.publicKey, 'base64'),
      counter: r.signCount,
      transports: r.transports ? JSON.parse(r.transports) : undefined,
    }))
  }

  async challenge(target: any) {
    const { userId, type = 'authenticate', userName, userDisplayName } = target
    const challengeId = randomBytes(16).toString('hex')

    if (type === 'register') {
      // userName is what the user would type at a login prompt (username /
      // email); userDisplayName is the human-readable label shown in the OS
      // passkey manager. Callers that know better should pass both; we fall
      // back to a placeholder so the credential is still distinguishable.
      const name = userName ?? `user-${userId}`
      // Tell the browser which authenticators the user has already bound, so
      // the OS rejects / warns on duplicate registration from the same
      // device. Without this, repeated clicks silently produce new identity
      // rows for the same physical passkey.
      const existing = userId ? await this.getCredentialsForUser(userId) : []
      const options = await generateRegistrationOptions({
        rpName: this.rpName,
        rpID: this.rpId,
        userID: Buffer.from(String(userId)),
        userName: name,
        userDisplayName: userDisplayName ?? name,
        timeout: this.timeout,
        attestationType: 'none',
        authenticatorSelection: { userVerification: 'preferred' },
        excludeCredentials: existing.map(c => ({ id: c.id, transports: c.transports })),
      })
      this.challenges.set(challengeId, {
        challenge: options.challenge,
        userId,
        type: 'register',
        expiresAt: Date.now() + this.timeout,
      })
      this.ctx.timeout(() => this.challenges.delete(challengeId), this.timeout)
      return { challengeId, data: options }
    }

    const credentials = userId ? await this.getCredentialsForUser(userId) : []
    const options = await generateAuthenticationOptions({
      rpID: this.rpId,
      timeout: this.timeout,
      allowCredentials: credentials.map(c => ({ id: c.id, transports: c.transports })),
      userVerification: 'preferred',
    })
    this.challenges.set(challengeId, {
      challenge: options.challenge,
      userId,
      type: 'authenticate',
      expiresAt: Date.now() + this.timeout,
    })
    this.ctx.timeout(() => this.challenges.delete(challengeId), this.timeout)
    return { challengeId, data: options }
  }

  async verify(challengeId: string, response: string) {
    const pending = this.challenges.get(challengeId)
    if (!pending || Date.now() > pending.expiresAt) {
      this.challenges.delete(challengeId)
      return false
    }

    if (pending.type === 'register') {
      this.challenges.delete(challengeId)
      const body = JSON.parse(response)
      try {
        const verification = await verifyRegistrationResponse({
          response: body as RegistrationResponseJSON,
          expectedChallenge: pending.challenge,
          expectedOrigin: this.origin,
          expectedRPID: this.rpId,
        })
        if (!verification.verified || !verification.registrationInfo) return false
        const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo
        const { deviceName } = body
        // Tie the new credential to the user whose id was captured in the
        // pending challenge. link() + create run in the same transaction so a
        // post-attestation DB failure cannot leave an orphan sso.identity.
        // SECURITY CAVEAT: the challenge endpoint doesn't authenticate, so a
        // caller can challenge for any userId. Until /sso/challenge/webauthn
        // is wrapped with a session check, treat webauthn binding as trusting
        // the caller to be the session holder of `pending.userId`.
        if (!pending.userId) return false
        await this.ctx.database.transact(async (db) => {
          const { identityId } = await this.ctx.sso.link(pending.userId!, 'webauthn', db)
          await db.create('sso.webauthn', {
            identityId,
            credentialId: credential.id,
            publicKey: Buffer.from(credential.publicKey).toString('base64'),
            signCount: credential.counter,
            deviceType: credentialDeviceType,
            backedUp: credentialBackedUp,
            deviceName,
            transports: body.response?.transports ? JSON.stringify(body.response.transports) : undefined,
            createdAt: new Date(),
          })
        })
        return true
      } catch { return false }
    }

    // authenticate branch delegates to the shared implementation below.
    return !!(await this.authenticate(challengeId, response))
  }

  // Public method used by POST /sso/sessions/:provider/finish for passwordless
  // login. Returns identityId on success so the session endpoint can mint a
  // token; returns null for every failure mode (unknown challenge, wrong type,
  // signature mismatch, unknown credential). Shares the challenge store with
  // verify(): the first of {verify, authenticate} wins; subsequent calls see
  // the challenge already deleted.
  async authenticate(challengeId: string, response: string): Promise<{ identityId: number } | null> {
    const pending = this.challenges.get(challengeId)
    if (!pending || Date.now() > pending.expiresAt) {
      this.challenges.delete(challengeId)
      return null
    }
    if (pending.type !== 'authenticate') return null
    this.challenges.delete(challengeId)

    try {
      const body = JSON.parse(response)
      const credentialId = body.id
      const [record] = await this.ctx.database.get('sso.webauthn', { credentialId })
      if (!record) return null
      const credential: WebAuthnCredential = {
        id: record.credentialId,
        publicKey: Buffer.from(record.publicKey, 'base64'),
        counter: record.signCount,
        transports: record.transports ? JSON.parse(record.transports) : undefined,
      }
      const verification = await verifyAuthenticationResponse({
        response: body as AuthenticationResponseJSON,
        expectedChallenge: pending.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        credential,
      })
      if (!verification.verified) return null
      await this.ctx.database.set('sso.webauthn', { credentialId }, {
        signCount: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date(),
      })
      return { identityId: record.identityId }
    } catch { return null }
  }

  // resolve is intentionally not implemented. The old version looked up
  // sso.webauthn by credentialId alone without verifying the signed challenge,
  // which would have let anyone who knows a credential id get a session for
  // its owner. Passwordless login MUST go through a challenge → verify pair
  // (the authenticate branch of verify() below does proper signature checks)
  // — see the TODO section in the sso CLAUDE.md.

  async register(credentials: any, db: Database = this.ctx.database) {
    const { identityId, credentialId, publicKey, signCount, deviceType, backedUp, transports, deviceName } = credentials
    if (!identityId || !credentialId || !publicKey) {
      throw new Error('identityId, credentialId, and publicKey required')
    }
    await db.create('sso.webauthn', {
      identityId,
      credentialId,
      publicKey: typeof publicKey === 'string' ? publicKey : Buffer.from(publicKey).toString('base64'),
      signCount: signCount ?? 0,
      deviceType: deviceType ?? 'singleDevice',
      backedUp: backedUp ?? false,
      deviceName,
      transports: transports ? JSON.stringify(transports) : undefined,
      createdAt: new Date(),
    })
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    await db.remove('sso.webauthn', { identityId })
  }
}

interface PendingChallenge {
  challenge: string
  userId?: number
  type: 'register' | 'authenticate'
  expiresAt: number
}
