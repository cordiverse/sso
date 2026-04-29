import { Context } from 'cordis'
import { randomBytes } from 'node:crypto'
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type WebAuthnCredential,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
} from '@simplewebauthn/server'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from '@cordisjs/plugin-database'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    sso_webauthn: SsoWebAuthn
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

    ctx.model.extend('sso_webauthn', {
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
      foreign: { identityId: ['sso_identity', 'id'] },
    })
  }

  private async getCredentialsForUser(userId: number): Promise<WebAuthnCredential[]> {
    const identities = await this.ctx.sso.getIdentities(userId)
    const ids = identities.filter(i => i.provider === 'webauthn').map(i => i.id)
    if (!ids.length) return []
    const records = await this.ctx.model.get('sso_webauthn', { identityId: { $in: ids } })
    return records.map(r => ({
      id: r.credentialId,
      publicKey: Buffer.from(r.publicKey, 'base64'),
      counter: r.signCount,
      deviceType: r.deviceType as 'singleDevice' | 'multiDevice',
      backedUp: r.backedUp,
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
      this.ctx.setTimeout(() => this.challenges.delete(challengeId), this.timeout)
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
      challenge: options.challenge, userId, type: 'authenticate',
      expiresAt: Date.now() + this.timeout,
    })
    this.ctx.setTimeout(() => this.challenges.delete(challengeId), this.timeout)
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
        const { identityId, deviceName } = body
        if (identityId) {
          await this.ctx.model.create('sso_webauthn', {
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
        }
        return true
      } catch { return false }
    }

    try {
      const credentialId = body.id
      const [record] = await this.ctx.model.get('sso_webauthn', { credentialId })
      if (!record) return false
      const credential: WebAuthnCredential = {
        id: record.credentialId,
        publicKey: Buffer.from(record.publicKey, 'base64'),
        counter: record.signCount,
        deviceType: record.deviceType as 'singleDevice' | 'multiDevice',
        backedUp: record.backedUp,
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
      await this.ctx.model.set('sso_webauthn', { credentialId }, {
        signCount: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date(),
      })
      return true
    } catch { return false }
  }

  async resolve(credentials: any) {
    const { credentialId } = credentials
    if (!credentialId) return null
    const [record] = await this.ctx.model.get('sso_webauthn', { credentialId })
    if (!record) return null
    return { identityId: record.identityId }
  }

  async register(credentials: any) {
    const { identityId, credentialId, publicKey, signCount, deviceType, backedUp, transports, deviceName } = credentials
    if (!identityId || !credentialId || !publicKey) {
      throw new Error('identityId, credentialId, and publicKey required')
    }
    await this.ctx.model.create('sso_webauthn', {
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
    return {}
  }
}

interface PendingChallenge {
  challenge: string
  userId?: number
  type: 'register' | 'authenticate'
  expiresAt: number
}
