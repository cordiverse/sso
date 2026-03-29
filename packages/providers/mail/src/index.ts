import { Context } from 'cordis'
import { randomBytes, randomUUID } from 'node:crypto'
import type { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from 'minato'

function randomDigits(length: number): string {
  return Array.from(randomBytes(length), b => (b % 10).toString()).join('')
}

declare module 'minato' {
  interface Tables {
    sso_mail: SsoMail
  }
}

export interface SsoMail {
  identityId: number
  email: string
  verified: boolean
}

export interface Config {
  /** Function to send the verification code email */
  send: (email: string, code: string) => Promise<void>
  /** Code expiry in milliseconds (default: 5 min) */
  codeExpiry?: number
  /** Code length (default: 6) */
  codeLength?: number
  /** Auto-register when email not found */
  autoRegister?: boolean
}

export const name = 'sso-mail'
export const inject = ['sso']

interface PendingChallenge {
  email: string
  code: string
  expiresAt: number
}

export function apply(ctx: Context, config: Config) {
  const {
    codeExpiry = 5 * 60 * 1000,
    codeLength = 6,
    autoRegister = true,
  } = config

  const challenges = new Map<string, PendingChallenge>()

  ctx.model.extend('sso_mail', {
    identityId: 'unsigned(8)',
    email: 'string(255)',
    verified: { type: 'boolean', initial: false },
  }, {
    primary: 'identityId',
    unique: [['email']],
    foreign: { identityId: ['sso_identity', 'id'] },
  })

  const provider: SsoProvider = {
    name: 'mail',
    interactive: true,
    autoRegister,

    async challenge(target: any) {
      const { email } = target
      if (!email) throw new Error('email required')

      const code = randomDigits(codeLength)
      const challengeId = randomUUID()

      challenges.set(challengeId, {
        email,
        code,
        expiresAt: Date.now() + codeExpiry,
      })

      // Auto-cleanup
      ctx.setTimeout(() => challenges.delete(challengeId), codeExpiry)

      await config.send(email, code)

      return { challengeId }
    },

    async verify(challengeId: string, response: string) {
      const challenge = challenges.get(challengeId)
      if (!challenge) return false
      if (Date.now() > challenge.expiresAt) {
        challenges.delete(challengeId)
        return false
      }
      if (challenge.code !== response) return false

      challenges.delete(challengeId)
      return true
    },

    async resolve(credentials: any) {
      const { email } = credentials
      if (!email) return null

      const [record] = await ctx.model.get('sso_mail', { email })
      if (!record) return null

      return { identityId: record.identityId }
    },

    async register(credentials: any) {
      const { identityId, email } = credentials
      if (!identityId) throw new Error('identityId required')
      if (!email) throw new Error('email required')

      const [existing] = await ctx.model.get('sso_mail', { email })
      if (existing) throw new Error('email already registered')

      await ctx.model.create('sso_mail', {
        identityId,
        email,
        verified: true,
      })
      return {}
    },
  }

  ctx.sso.register(provider)
}
