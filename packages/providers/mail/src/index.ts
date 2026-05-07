import { Context, Inject } from 'cordis'
import { randomBytes, randomUUID } from 'node:crypto'
import { ChallengeProvider, Sso, ssoError } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'
import type {} from '@cordisjs/mail'
import z from 'schemastery'

function randomDigits(length: number): string {
  return Array.from(randomBytes(length), (b) => (b % 10).toString()).join('')
}

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.mail': SsoMail
  }
}

export interface SsoMail {
  identityId: number
  email: string
}

export interface Config {
  /** Logical template name registered on the configured `ctx.mail` driver. The provider passes `{ code, email }` as the template variables. */
  templateId: string
  codeExpiry?: number
  codeLength?: number
  jitProvisioning?: boolean
}

interface MailInit {
  email: string
}

interface MailComplete {
  code: string
}

interface MailExtra {
  email: string
  code: string
}

@Inject('mail')
export default class MailProvider extends ChallengeProvider<MailInit, MailComplete, MailExtra> {
  static Config: z<Config> = z.object({
    templateId: z.string().default('sso.otp').description('ctx.mail 上注册的模板名，占位符可用 `{ code, email }`。'),
    codeExpiry: z.natural().default(5 * 60 * 1000).description('验证码有效期（毫秒）。'),
    codeLength: z.natural().default(6).description('验证码位数。'),
    jitProvisioning: z.boolean().default(true).description('登录未命中时自动注册。'),
  })

  name = 'mail'
  canBePrimary = true
  canStepUp = true
  jitProvisioning: boolean
  interactive = true
  multipleIdentities = true

  private codeLength: number
  private templateId: string

  constructor(ctx: Context, config: Config) {
    super(ctx)
    this.challengeTtl = config.codeExpiry ?? 5 * 60 * 1000
    this.codeLength = config.codeLength ?? 6
    this.jitProvisioning = config.jitProvisioning ?? true
    this.templateId = config.templateId

    ctx.database.extend('sso.mail', {
      identityId: 'unsigned(8)',
      email: 'string(255)',
    }, {
      primary: 'identityId',
      unique: [['email']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  async issue(input: MailInit) {
    const email = input?.email
    if (!email) throw ssoError(400, 'INVALID_REQUEST')
    const code = randomDigits(this.codeLength)
    const challengeId = randomUUID()
    await this.ctx.mail.sendTemplate(email, this.templateId, { code, email })
    return {
      challengeId,
      response: { shape: 'code' as const, length: this.codeLength, digits: true },
      extra: { email, code },
    }
  }

  async verify(pending: Sso.Pending<MailExtra>, input: MailComplete) {
    return input?.code === pending.extra.code
  }

  async resolve(pending: Sso.Pending<MailExtra>) {
    const [record] = await this.ctx.database.get('sso.mail', { email: pending.extra.email })
    if (!record) return null
    return { identityId: record.identityId }
  }

  async writeIdentity(userId: number, identityId: number, pending: Sso.Pending<MailExtra>, db: Database) {
    const email = pending.extra.email
    const [existing] = await db.get('sso.mail', { email })
    if (existing) throw ssoError(409, 'EMAIL_TAKEN')
    await db.create('sso.mail', { identityId, email })
    const [owner] = await db.get('sso.user', { id: userId })
    if (owner && !owner.display) {
      const localPart = String(email).split('@')[0]
      if (localPart) await db.set('sso.user', { id: userId }, { display: localPart })
    }
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    await db.remove('sso.mail', { identityId })
  }

  async resolveUser(identifier: string): Promise<number | null> {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(identifier)) return null
    const [row] = await this.ctx.database.get('sso.mail', { email: identifier })
    if (!row) return null
    const identity = await this.ctx.sso.getIdentity(row.identityId)
    return identity?.userId ?? null
  }
}
