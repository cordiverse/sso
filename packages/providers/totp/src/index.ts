import { Context } from 'cordis'
import { createHmac, randomBytes } from 'node:crypto'
import type {} from '@cordisjs/plugin-database'
import { SsoProvider } from '@cordisjs/plugin-sso'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    sso_totp: SsoTotp
  }
}

export interface SsoTotp {
  identityId: number
  secret: string
  label?: string
  verified: boolean
}

export interface Config {
  issuer?: string
  period?: number
  digits?: number
  algorithm?: 'sha1' | 'sha256' | 'sha512'
  window?: number
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

export default class TotpProvider extends SsoProvider {
  name = 'totp'
  interactive = false
  autoRegister = false

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

    ctx.model.extend('sso_totp', {
      identityId: 'unsigned(8)',
      secret: 'string(255)',
      label: 'string(255)',
      verified: { type: 'boolean', initial: false },
    }, {
      primary: 'identityId',
      foreign: { identityId: ['sso_identity', 'id'] },
    })
  }

  async resolve(credentials: any) {
    const { identityId, code } = credentials
    if (!identityId || !code) return null
    const [record] = await this.ctx.model.get('sso_totp', { identityId })
    if (!record || !record.verified) return null
    const secret = base32Decode(record.secret)
    const now = Math.floor(Date.now() / 1000)
    for (let i = -this.window; i <= this.window; i++) {
      const expected = generateTOTP(secret, now + i * this.period, this.period, this.digits, this.algorithm)
      if (expected === code) return { identityId }
    }
    return null
  }

  async register(credentials: any) {
    const { identityId, label } = credentials
    if (!identityId) throw new Error('identityId required')
    const secretBytes = randomBytes(20)
    const secret = base32Encode(secretBytes)
    await this.ctx.model.create('sso_totp', { identityId, secret, label, verified: false })
    const accountName = label || 'user'
    const otpauthUrl = `otpauth://totp/${encodeURIComponent(this.issuer)}:${encodeURIComponent(accountName)}`
      + `?secret=${secret}&issuer=${encodeURIComponent(this.issuer)}&algorithm=${this.algorithm.toUpperCase()}`
      + `&digits=${this.digits}&period=${this.period}`
    return { data: { secret, otpauthUrl } }
  }

  async verify(challengeId: string, response: string) {
    const identityId = parseInt(challengeId)
    const [record] = await this.ctx.model.get('sso_totp', { identityId })
    if (!record) return false
    const secret = base32Decode(record.secret)
    const now = Math.floor(Date.now() / 1000)
    for (let i = -this.window; i <= this.window; i++) {
      const expected = generateTOTP(secret, now + i * this.period, this.period, this.digits, this.algorithm)
      if (expected === response) {
        await this.ctx.model.set('sso_totp', { identityId }, { verified: true })
        return true
      }
    }
    return false
  }
}
