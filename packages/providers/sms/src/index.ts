import { Context, Inject } from 'cordis'
import { randomBytes, randomUUID } from 'node:crypto'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'
import type {} from '@cordisjs/sms'

function randomDigits(length: number): string {
  return Array.from(randomBytes(length), b => (b % 10).toString()).join('')
}

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.sms': SsoSms
  }
}

export interface SsoSms {
  identityId: number
  phone: string
  verified: boolean
}

export interface Config {
  codeExpiry?: number
  codeLength?: number
  autoRegister?: boolean
  template?: string
}

interface PendingChallenge {
  phone: string
  code: string
  expiresAt: number
}

@Inject('sms')
@Inject('timer')
export default class SmsProvider extends SsoProvider {
  name = 'sms'
  type = 'challenge' as const
  interactive = true
  autoRegister: boolean

  private challenges = new Map<string, PendingChallenge>()
  private codeExpiry: number
  private codeLength: number
  private template: string

  constructor(ctx: Context, config: Config = {}) {
    super(ctx)
    this.codeExpiry = config.codeExpiry ?? 5 * 60 * 1000
    this.codeLength = config.codeLength ?? 6
    this.autoRegister = config.autoRegister ?? true
    this.template = config.template ?? 'Your verification code is {code}'

    ctx.database.extend('sso.sms', {
      identityId: 'unsigned(8)',
      phone: 'string(255)',
      verified: { type: 'boolean', initial: false },
    }, {
      primary: 'identityId',
      unique: [['phone']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  async challenge(target: any) {
    const { phone } = target
    if (!phone) throw new Error('phone required')

    const code = randomDigits(this.codeLength)
    const challengeId = randomUUID()

    this.challenges.set(challengeId, {
      phone,
      code,
      expiresAt: Date.now() + this.codeExpiry,
    })

    this.ctx.timeout(() => this.challenges.delete(challengeId), this.codeExpiry)
    const message = this.template.replace('{code}', code)
    await this.ctx.sms.send(phone, message)

    return { challengeId }
  }

  // Peek/consume split — same rationale as the mail provider. resolve peeks so
  // the same challenge survives for an autoRegister fallback.
  private peekChallenge(phone: string, challengeId: string, code: string): boolean {
    const challenge = this.challenges.get(challengeId)
    if (!challenge) return false
    if (Date.now() > challenge.expiresAt) return false
    if (challenge.phone !== phone) return false
    if (challenge.code !== code) return false
    return true
  }

  private consumeChallenge(phone: string, challengeId: string, code: string): boolean {
    if (!this.peekChallenge(phone, challengeId, code)) {
      this.challenges.delete(challengeId)
      return false
    }
    this.challenges.delete(challengeId)
    return true
  }

  async verify(challengeId: string, response: string) {
    // Kept for the generic /sso/verify/sms endpoint. Validates code only —
    // callers that already know the phone should prefer the resolve/register
    // flow which cross-checks phone ↔ challenge and is atomic with identity
    // writes.
    const challenge = this.challenges.get(challengeId)
    if (!challenge) return false
    if (Date.now() > challenge.expiresAt) {
      this.challenges.delete(challengeId)
      return false
    }
    if (challenge.code !== response) return false
    this.challenges.delete(challengeId)
    return true
  }

  async resolve(credentials: any) {
    const { phone, challengeId, code } = credentials
    if (!phone || !challengeId || !code) return null
    if (!this.peekChallenge(phone, challengeId, code)) return null
    const [record] = await this.ctx.database.get('sso.sms', { phone })
    if (!record) return null
    this.consumeChallenge(phone, challengeId, code)
    return { identityId: record.identityId }
  }

  async register(credentials: any, db: Database = this.ctx.database) {
    const { identityId, phone, challengeId, code } = credentials
    if (!identityId) throw new Error('identityId required')
    if (!phone) throw new Error('phone required')
    if (!challengeId || !code) throw new Error('challengeId and code required')
    if (!this.consumeChallenge(phone, challengeId, code)) {
      throw new Error('verification failed')
    }
    const [existing] = await db.get('sso.sms', { phone })
    if (existing) throw new Error('phone already registered')
    await db.create('sso.sms', { identityId, phone, verified: true })
  }
}
