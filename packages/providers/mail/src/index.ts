import { Context, Inject } from 'cordis'
import { randomBytes, randomUUID } from 'node:crypto'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'

function randomDigits(length: number): string {
  return Array.from(randomBytes(length), b => (b % 10).toString()).join('')
}

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.mail': SsoMail
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

@Inject('timer')
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

    ctx.database.extend('sso.mail', {
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

  // Split verification from consumption so login (resolve) and register can
  // share one challenge: resolve peeks, and only whichever of
  // { resolve-hit, register } actually succeeds consumes. This keeps the
  // autoRegister fallback path working — previously resolve consumed the
  // challenge, then register's second consume failed and the whole session
  // request threw 500.
  private peekChallenge(email: string, challengeId: string, code: string): boolean {
    const challenge = this.challenges.get(challengeId)
    if (!challenge) return false
    if (Date.now() > challenge.expiresAt) return false
    if (challenge.email !== email) return false
    if (challenge.code !== code) return false
    return true
  }

  private consumeChallenge(email: string, challengeId: string, code: string): boolean {
    if (!this.peekChallenge(email, challengeId, code)) {
      // Still delete on pure-mismatch hits so an expired/mismatched challenge
      // doesn't linger past its usefulness.
      this.challenges.delete(challengeId)
      return false
    }
    this.challenges.delete(challengeId)
    return true
  }

  async resolve(credentials: any) {
    const { email, challengeId, code } = credentials
    if (!email || !challengeId || !code) return null
    if (!this.peekChallenge(email, challengeId, code)) return null
    const [record] = await this.ctx.database.get('sso.mail', { email })
    if (!record) return null
    // Match found — consume the challenge on our way out. If no match, the
    // server will fall through to autoRegister (if enabled); register will
    // consume then.
    this.consumeChallenge(email, challengeId, code)
    return { identityId: record.identityId }
  }

  async register(credentials: any, db: Database = this.ctx.database) {
    const { identityId, email, challengeId, code } = credentials
    if (!identityId) throw new Error('identityId required')
    if (!email) throw new Error('email required')
    if (!challengeId || !code) throw new Error('challengeId and code required')
    if (!this.consumeChallenge(email, challengeId, code)) {
      throw new Error('verification failed')
    }
    const [existing] = await db.get('sso.mail', { email })
    if (existing) throw new Error('email already registered')
    await db.create('sso.mail', { identityId, email, verified: true })
  }
}
