import { Context, Inject } from 'cordis'
import { randomBytes, randomUUID } from 'node:crypto'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'
import type {} from '@cordisjs/sms'

function randomDigits(length: number): string {
  return Array.from(randomBytes(length), b => (b % 10).toString()).join('')
}

declare module '@cordisjs/plugin-database' {
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
export default class SmsProvider extends SsoProvider {
  name = 'sms'
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

    ctx.model.extend('sso_sms', {
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

  async verify(challengeId: string, response: string) {
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
    const { phone } = credentials
    if (!phone) return null
    const [record] = await this.ctx.model.get('sso_sms', { phone })
    if (!record) return null
    return { identityId: record.identityId }
  }

  async register(credentials: any) {
    const { identityId, phone } = credentials
    if (!identityId) throw new Error('identityId required')
    if (!phone) throw new Error('phone required')
    const [existing] = await this.ctx.model.get('sso_sms', { phone })
    if (existing) throw new Error('phone already registered')
    await this.ctx.model.create('sso_sms', { identityId, phone, verified: true })
    return {}
  }
}
