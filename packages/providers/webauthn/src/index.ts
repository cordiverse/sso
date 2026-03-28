import { Context } from 'cordis'
import { randomBytes } from 'node:crypto'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type WebAuthnCredential,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
} from '@simplewebauthn/server'
import type { SSO, SSOProvider } from '@cordisjs/plugin-sso'

declare module 'minato' {
  interface Tables {
    sso_webauthn: SSOWebAuthn
  }
}

export interface SSOWebAuthn {
  identityId: number
  credentialId: string
  publicKey: string        // base64-encoded
  signCount: number
  deviceType: string       // 'singleDevice' | 'multiDevice'
  backedUp: boolean
  deviceName?: string
  transports?: string      // JSON array
  createdAt: Date
  lastUsedAt?: Date
}

export interface Config {
  rpName: string
  rpId: string
  origin: string
  timeout?: number
}

export const name = 'sso-webauthn'
export const inject = ['sso', 'sso.server']

interface PendingChallenge {
  challenge: string
  userId?: number
  type: 'register' | 'authenticate'
  expiresAt: number
}

export function apply(ctx: Context, config: Config) {
  const { timeout = 60000 } = config
  const challenges = new Map<string, PendingChallenge>()

  ctx.minato.extend('sso_webauthn', {
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

  async function getCredentialsForUser(userId: number): Promise<WebAuthnCredential[]> {
    const identities = await ctx.sso.getIdentities(userId)
    const ids = identities.filter(i => i.provider === 'webauthn').map(i => i.id)
    if (!ids.length) return []
    const records = await ctx.minato.get('sso_webauthn', { identityId: { $in: ids } })
    return records.map(r => ({
      id: r.credentialId,
      publicKey: Buffer.from(r.publicKey, 'base64'),
      counter: r.signCount,
      deviceType: r.deviceType as 'singleDevice' | 'multiDevice',
      backedUp: r.backedUp,
      transports: r.transports ? JSON.parse(r.transports) : undefined,
    }))
  }

  const provider: SSOProvider = {
    name: 'webauthn',
    interactive: false,
    autoRegister: false,

    async challenge(target: any) {
      const { userId, type = 'authenticate' } = target
      const challengeId = randomBytes(16).toString('hex')

      if (type === 'register') {
        const options = await generateRegistrationOptions({
          rpName: config.rpName,
          rpID: config.rpId,
          userID: Buffer.from(String(userId)),
          userName: `user-${userId}`,
          timeout,
          attestationType: 'none',
          authenticatorSelection: {
            userVerification: 'preferred',
          },
        })

        challenges.set(challengeId, {
          challenge: options.challenge,
          userId,
          type: 'register',
          expiresAt: Date.now() + timeout,
        })
        ctx.setTimeout(() => challenges.delete(challengeId), timeout)

        return { challengeId, data: options }
      }

      // Authentication
      const credentials = userId ? await getCredentialsForUser(userId) : []
      const options = await generateAuthenticationOptions({
        rpID: config.rpId,
        timeout,
        allowCredentials: credentials.map(c => ({
          id: c.id,
          transports: c.transports,
        })),
        userVerification: 'preferred',
      })

      challenges.set(challengeId, {
        challenge: options.challenge,
        userId,
        type: 'authenticate',
        expiresAt: Date.now() + timeout,
      })
      ctx.setTimeout(() => challenges.delete(challengeId), timeout)

      return { challengeId, data: options }
    },

    async verify(challengeId: string, response: string) {
      const pending = challenges.get(challengeId)
      if (!pending || Date.now() > pending.expiresAt) {
        challenges.delete(challengeId)
        return false
      }
      challenges.delete(challengeId)

      const body = JSON.parse(response)

      if (pending.type === 'register') {
        try {
          const verification = await verifyRegistrationResponse({
            response: body as RegistrationResponseJSON,
            expectedChallenge: pending.challenge,
            expectedOrigin: config.origin,
            expectedRPID: config.rpId,
          })

          if (!verification.verified || !verification.registrationInfo) return false

          const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo

          // Store credential — caller must provide identityId via the body
          const { identityId, deviceName } = body
          if (identityId) {
            await ctx.minato.create('sso_webauthn', {
              identityId,
              credentialId: credential.id,
              publicKey: Buffer.from(credential.publicKey).toString('base64'),
              signCount: credential.counter,
              deviceType: credentialDeviceType,
              backedUp: credentialBackedUp,
              deviceName,
              transports: body.response?.transports
                ? JSON.stringify(body.response.transports) : undefined,
              createdAt: new Date(),
            })
          }

          return true
        } catch {
          return false
        }
      }

      // Authentication
      try {
        const credentialId = body.id
        const [record] = await ctx.minato.get('sso_webauthn', { credentialId })
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
          expectedOrigin: config.origin,
          expectedRPID: config.rpId,
          credential,
        })

        if (!verification.verified) return false

        // Update sign count
        await ctx.minato.set('sso_webauthn', { credentialId }, {
          signCount: verification.authenticationInfo.newCounter,
          lastUsedAt: new Date(),
        })

        return true
      } catch {
        return false
      }
    },

    async resolve(credentials: any) {
      const { credentialId } = credentials
      if (!credentialId) return null
      const [record] = await ctx.minato.get('sso_webauthn', { credentialId })
      if (!record) return null
      return { identityId: record.identityId }
    },

    async register(credentials: any) {
      const { identityId, credentialId, publicKey, signCount, deviceType, backedUp, transports, deviceName } = credentials
      if (!identityId || !credentialId || !publicKey) {
        throw new Error('identityId, credentialId, and publicKey required')
      }
      await ctx.minato.create('sso_webauthn', {
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
    },
  }

  ctx.sso.register(provider)
}
