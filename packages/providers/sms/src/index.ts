import { Context } from 'cordis'
import { Random } from 'cosmokit'
import type {} from 'minato'
import type { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from '@cordisjs/sms'

declare module 'minato' {
  interface Tables {
    sso_sms: SsoSms
  }
}

export interface SsoSms {
  identityId: number
  phone: string
  verified: boolean
}

export interface Config {
  /** Code expiry in milliseconds (default: 5 min) */
  codeExpiry?: number
  /** Code length (default: 6) */
  codeLength?: number
  /** Auto-register when phone not found */
  autoRegister?: boolean
  /** Message template. Use {code} as placeholder (default: "Your verification code is {code}") */
  template?: string
}

export const name = 'sso-sms'
export const inject = ['sso', 'sms']

interface PendingChallenge {
  phone: string
  code: string
  expiresAt: number
}

export function apply(ctx: Context, config: Config = {}) {
  const {
    codeExpiry = 5 * 60 * 1000,
    codeLength = 6,
    autoRegister = true,
    template = 'Your verification code is {code}',
  } = config

  const challenges = new Map<string, PendingChallenge>()

  ctx.model.extend('sso_sms', {
    identityId: 'unsigned(8)',
    phone: 'string(255)',
    verified: { type: 'boolean', initial: false },
  }, {
    primary: 'identityId',
    unique: [['phone']],
    foreign: { identityId: ['sso_identity', 'id'] },
  })

  const provider: SsoProvider = {
    name: 'sms',
    interactive: true,
    autoRegister,

    async challenge(target: any) {
      const { phone } = target
      if (!phone) throw new Error('phone required')

      const code = Random.id(codeLength, 10)
      const challengeId = Random.id(32, 36)

      challenges.set(challengeId, {
        phone,
        code,
        expiresAt: Date.now() + codeExpiry,
      })

      ctx.setTimeout(() => challenges.delete(challengeId), codeExpiry)

      // Use the sms service to send
      const message = template.replace('{code}', code)
      await ctx.sms.send(phone, message)

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
      const { phone } = credentials
      if (!phone) return null
      const [record] = await ctx.model.get('sso_sms', { phone })
      if (!record) return null
      return { identityId: record.identityId }
    },

    async register(credentials: any) {
      const { identityId, phone } = credentials
      if (!identityId) throw new Error('identityId required')
      if (!phone) throw new Error('phone required')

      const [existing] = await ctx.model.get('sso_sms', { phone })
      if (existing) throw new Error('phone already registered')

      await ctx.model.create('sso_sms', {
        identityId,
        phone,
        verified: true,
      })
      return {}
    },
  }

  ctx.sso.register(provider)
}
