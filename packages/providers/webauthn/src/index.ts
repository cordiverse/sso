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
  rpName: string
  rpId: string
  origin: string
  timeout?: number
}

@Inject('timer')
export default class WebAuthnProvider extends SsoProvider {
  name = 'webauthn'
  interactive = false
  autoRegister = false

  private challenges = new Map<string, PendingChallenge>()
  private rpName: string
  private rpId: string
  private origin: string
  private timeout: number

  constructor(ctx: Context, config: Config) {
    super(ctx)
    this.rpName = config.rpName
    this.rpId = config.rpId
    this.origin = config.origin
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
    const { userId, type = 'authenticate' } = target
    const challengeId = randomBytes(16).toString('hex')

    if (type === 'register') {
      const options = await generateRegistrationOptions({
        rpName: this.rpName,
        rpID: this.rpId,
        userID: Buffer.from(String(userId)),
        userName: `user-${userId}`,
        timeout: this.timeout,
        attestationType: 'none',
        authenticatorSelection: { userVerification: 'preferred' },
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
    this.challenges.delete(challengeId)
    const body = JSON.parse(response)

    if (pending.type === 'register') {
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

    try {
      const credentialId = body.id
      const [record] = await this.ctx.database.get('sso.webauthn', { credentialId })
      if (!record) return false
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
      if (!verification.verified) return false
      await this.ctx.database.set('sso.webauthn', { credentialId }, {
        signCount: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date(),
      })
      return true
    } catch { return false }
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
}

interface PendingChallenge {
  challenge: string
  userId?: number
  type: 'register' | 'authenticate'
  expiresAt: number
}
