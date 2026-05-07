import { Context, Inject } from 'cordis'
import { randomBytes, randomUUID } from 'node:crypto'
import { ChallengeProvider, Sso, ssoError } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'
import type {} from '@cordisjs/sms'
import z from 'schemastery'

function randomDigits(length: number): string {
  return Array.from(randomBytes(length), (b) => (b % 10).toString()).join('')
}

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.sms': SsoSms
  }
}

export interface SsoSms {
  identityId: number
  phone: string
}

export interface Config {
  /** Logical template name registered on the configured `ctx.sms` driver. The provider passes `{ code }` as the template variables. */
  templateId: string
  codeExpiry?: number
  codeLength?: number
  jitProvisioning?: boolean
}

interface SmsInit {
  phone: string
}

interface SmsComplete {
  code: string
}

interface SmsExtra {
  phone: string
  code: string
}

@Inject('sms')
export default class SmsProvider extends ChallengeProvider<SmsInit, SmsComplete, SmsExtra> {
  static Config: z<Config> = z.object({
    templateId: z.string().default('sso.otp').description('ctx.sms 上注册的模板名，占位符可用 `{ code }`。'),
    codeExpiry: z.natural().default(5 * 60 * 1000).description('验证码有效期（毫秒）。'),
    codeLength: z.natural().default(6).description('验证码位数。'),
    jitProvisioning: z.boolean().default(true).description('登录未命中时自动注册。'),
  })

  name = 'sms'
  canBePrimary = true
  canStepUp = true
  jitProvisioning: boolean
  interactive = true

  private codeLength: number
  private templateId: string

  constructor(ctx: Context, config: Config) {
    super(ctx)
    this.challengeTtl = config.codeExpiry ?? 5 * 60 * 1000
    this.codeLength = config.codeLength ?? 6
    this.jitProvisioning = config.jitProvisioning ?? true
    this.templateId = config.templateId

    ctx.database.extend('sso.sms', {
      identityId: 'unsigned(8)',
      phone: 'string(255)',
    }, {
      primary: 'identityId',
      unique: [['phone']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  async issue(input: SmsInit) {
    const phone = input?.phone
    if (!phone) throw ssoError(400, 'INVALID_REQUEST')
    const code = randomDigits(this.codeLength)
    const challengeId = randomUUID()
    await this.ctx.sms.sendTemplate(phone, this.templateId, { code })
    return {
      challengeId,
      response: { shape: 'code' as const, length: this.codeLength, digits: true },
      extra: { phone, code },
    }
  }

  async verify(pending: Sso.Pending<SmsExtra>, input: SmsComplete) {
    return input?.code === pending.extra.code
  }

  async resolve(pending: Sso.Pending<SmsExtra>) {
    const [record] = await this.ctx.database.get('sso.sms', { phone: pending.extra.phone })
    if (!record) return null
    return { identityId: record.identityId }
  }

  async writeIdentity(userId: number, identityId: number, pending: Sso.Pending<SmsExtra>, db: Database) {
    const phone = pending.extra.phone
    const [existing] = await db.get('sso.sms', { phone })
    if (existing) throw ssoError(409, 'PHONE_TAKEN')
    await db.create('sso.sms', { identityId, phone })
    const [owner] = await db.get('sso.user', { id: userId })
    if (owner && !owner.display) {
      await db.set('sso.user', { id: userId }, { display: String(phone) })
    }
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    await db.remove('sso.sms', { identityId })
  }

  async resolveUser(identifier: string): Promise<number | null> {
    if (!/^\+?[\d\s\-()]{6,}$/.test(identifier)) return null
    const [row] = await this.ctx.database.get('sso.sms', { phone: identifier })
    if (!row) return null
    const identity = await this.ctx.sso.getIdentity(row.identityId)
    return identity?.userId ?? null
  }
}
