import { Context } from 'cordis'
import { randomBytes, randomUUID } from 'node:crypto'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'

function randomDigits(length: number): string {
  return Array.from(randomBytes(length), b => (b % 10).toString()).join('')
}

declare module '@cordisjs/plugin-database' {
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
  send: (email: string, code: string) => Promise<void>
  codeExpiry?: number
  codeLength?: number
  autoRegister?: boolean
}

interface PendingChallenge {
  email: string
  code: string
  expiresAt: number
}

export default class MailProvider extends SsoProvider {
  name = 'mail'
  interactive = true
  autoRegister: boolean

  private challenges = new Map<string, PendingChallenge>()
  private codeExpiry: number
  private codeLength: number
  private send: (email: string, code: string) => Promise<void>

  constructor(ctx: Context, config: Config) {
    super(ctx)
    this.codeExpiry = config.codeExpiry ?? 5 * 60 * 1000
    this.codeLength = config.codeLength ?? 6
    this.autoRegister = config.autoRegister ?? true
    this.send = config.send

    ctx.database.extend('sso_mail', {
      identityId: 'unsigned(8)',
      email: 'string(255)',
      verified: { type: 'boolean', initial: false },
    }, {
      primary: 'identityId',
      unique: [['email']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  async challenge(target: any) {
    const { email } = target
    if (!email) throw new Error('email required')

    const code = randomDigits(this.codeLength)
    const challengeId = randomUUID()

    this.challenges.set(challengeId, {
      email,
      code,
      expiresAt: Date.now() + this.codeExpiry,
    })

    this.ctx.timeout(() => this.challenges.delete(challengeId), this.codeExpiry)
    await this.send(email, code)

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
    const { email } = credentials
    if (!email) return null
    const [record] = await this.ctx.database.get('sso_mail', { email })
    if (!record) return null
    return { identityId: record.identityId }
  }

  async register(credentials: any) {
    const { identityId, email } = credentials
    if (!identityId) throw new Error('identityId required')
    if (!email) throw new Error('email required')
    const [existing] = await this.ctx.database.get('sso_mail', { email })
    if (existing) throw new Error('email already registered')
    await this.ctx.database.create('sso_mail', { identityId, email, verified: true })
    return {}
  }
}
