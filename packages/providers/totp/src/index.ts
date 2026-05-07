import { Context } from 'cordis'
import { createHmac, randomBytes, randomUUID } from 'node:crypto'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'
import { ChallengeProvider, Sso, ssoError } from '@cordisjs/plugin-sso'
import z from 'schemastery'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.totp': SsoTotp
  }
}

export interface SsoTotp {
  identityId: number
  secret: string
  label?: string
}

export interface Config {
  issuer?: string
  period?: number
  digits?: number
  algorithm?: 'sha1' | 'sha256' | 'sha512'
  window?: number
  challengeTtl?: number
}

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Encode(buffer: Buffer): string {
  let result = ''
  let bits = 0
  let value = 0
  for (const byte of buffer) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      result += BASE32_CHARS[(value >>> (bits - 5)) & 0x1f]
      bits -= 5
    }
  }
  if (bits > 0) {
    result += BASE32_CHARS[(value << (5 - bits)) & 0x1f]
  }
  return result
}

function base32Decode(encoded: string): Buffer {
  const bytes: number[] = []
  let bits = 0
  let value = 0
  for (const char of encoded.toUpperCase()) {
    const idx = BASE32_CHARS.indexOf(char)
    if (idx === -1) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Buffer.from(bytes)
}

function generateTOTP(secret: Buffer, time: number, period: number, digits: number, algorithm: string): string {
  const counter = Math.floor(time / period)
  const counterBuffer = Buffer.alloc(8)
  counterBuffer.writeBigUInt64BE(BigInt(counter))
  const hmac = createHmac(algorithm, secret).update(counterBuffer).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % (10 ** digits)
  return String(code).padStart(digits, '0')
}

interface TotpInit {
  label?: string
}

interface TotpComplete {
  code: string
}

interface TotpExtra {
  secret: string | null
  label?: string
}

export default class TotpProvider extends ChallengeProvider<TotpInit, TotpComplete, TotpExtra> {
  static Config: z<Config> = z.object({
    issuer: z.string().default('Cordis').description('otpauth URL 中的 issuer 字段。'),
    period: z.natural().default(30).description('时间步长（秒）。'),
    digits: z.natural().default(6).description('验证码位数。'),
    algorithm: z.union([
      z.const('sha1').required(),
      z.const('sha256').required(),
      z.const('sha512').required(),
    ] as const).default('sha1').description('HMAC 算法。'),
    window: z.natural().default(1).description('允许的时间步长偏移数，用于对抗时钟漂移。'),
    challengeTtl: z.natural().description('绑定流程中秘钥挑战的存活时间（毫秒）。'),
  })

  name = 'totp'
  canBePrimary = false
  canStepUp = true
  jitProvisioning = false
  interactive = false

  private issuer: string
  private period: number
  private digits: number
  private algorithm: string
  private window: number

  constructor(ctx: Context, config: Config = {}) {
    super(ctx)
    this.issuer = config.issuer ?? 'Cordis'
    this.period = config.period ?? 30
    this.digits = config.digits ?? 6
    this.algorithm = config.algorithm ?? 'sha1'
    this.window = config.window ?? 1
    if (config.challengeTtl) this.challengeTtl = config.challengeTtl

    ctx.database.extend('sso.totp', {
      identityId: 'unsigned(8)',
      secret: 'string(255)',
      label: 'string(255)',
    }, {
      primary: 'identityId',
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  async issue(input: TotpInit, ctx: Sso.StepContext) {
    const challengeId = randomUUID()
    if (ctx.kind === 'bind') {
      const secretBytes = randomBytes(20)
      const secret = base32Encode(secretBytes)
      let accountName: string | undefined = input?.label
      if (!accountName && ctx.userId) {
        const [owner] = await this.ctx.database.get('sso.user', { id: ctx.userId })
        accountName = owner?.name ?? owner?.display
      }
      accountName = accountName ?? 'User'
      const otpauthUrl =
        `otpauth://totp/${encodeURIComponent(this.issuer)}:${encodeURIComponent(accountName)}`
        + `?secret=${secret}&issuer=${encodeURIComponent(this.issuer)}`
        + `&algorithm=${this.algorithm.toUpperCase()}&digits=${this.digits}&period=${this.period}`
      return {
        challengeId,
        response: { shape: 'code' as const, length: this.digits, digits: true },
        extra: { secret, label: input?.label },
        data: { otpauthUrl, secret },
      }
    }
    return {
      challengeId,
      response: { shape: 'code' as const, length: this.digits, digits: true },
      extra: { secret: null },
    }
  }

  async verify(pending: Sso.Pending<TotpExtra>, input: TotpComplete) {
    const code = input?.code
    if (!code) return false
    let secretStr: string | null = pending.extra.secret
    if (!secretStr) {
      if (!pending.userId) return false
      const identities = await this.ctx.sso.getIdentities(pending.userId)
      const mine = identities.find((i) => i.provider === this.name)
      if (!mine) return false
      const [row] = await this.ctx.database.get('sso.totp', { identityId: mine.id })
      if (!row) return false
      secretStr = row.secret
    }
    const secret = base32Decode(secretStr)
    const now = Math.floor(Date.now() / 1000)
    for (let i = -this.window; i <= this.window; i++) {
      const expected = generateTOTP(secret, now + i * this.period, this.period, this.digits, this.algorithm)
      if (expected === code) return true
    }
    return false
  }

  async resolve() {
    return null
  }

  async writeIdentity(userId: number, identityId: number, pending: Sso.Pending<TotpExtra>, db: Database) {
    if (!pending.extra.secret) throw ssoError(400, 'INVALID_REQUEST')
    await db.create('sso.totp', {
      identityId,
      secret: pending.extra.secret,
      label: pending.extra.label,
    })
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    await db.remove('sso.totp', { identityId })
  }
}
