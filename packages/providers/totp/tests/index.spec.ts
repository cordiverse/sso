import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import Timer from '@cordisjs/plugin-timer'
import Sso from '@cordisjs/plugin-sso'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createHmac } from 'node:crypto'
import Totp, { Config as TotpConfig } from '../src'

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Decode(encoded: string): Buffer {
  const bytes: number[] = []
  let bits = 0
  let value = 0
  for (const ch of encoded.toUpperCase()) {
    const idx = BASE32_CHARS.indexOf(ch)
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

function totp(secret: Buffer, time: number, period: number, digits: number, algorithm: string): string {
  const counter = Math.floor(time / period)
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))
  const hmac = createHmac(algorithm, secret).update(buf).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % (10 ** digits)
  return String(code).padStart(digits, '0')
}

async function setup(config: TotpConfig = {}) {
  const ctx = new Context()
  await ctx.plugin(Database)
  await ctx.plugin(MemoryDriver)
  await ctx.plugin(Timer)
  await ctx.plugin(Sso)
  await ctx.plugin(Totp, config)
  return ctx
}

describe('@cordisjs/plugin-sso-totp', () => {
  describe('bind (step 1 issue)', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('returns a challenge with otpauthUrl + secret', async () => {
      const { user } = await ctx.sso.createUser('x')
      const provider = ctx.sso.getProvider('totp')!
      const result = await provider.step({ label: 'alice@example.com' }, { kind: 'bind', userId: user.id })
      expect(result.phase).to.equal('challenge')
      const data = (result as any).data
      expect(data.secret).to.be.a('string').and.match(/^[A-Z2-7]+$/)
      expect(data.otpauthUrl).to.match(/^otpauth:\/\/totp\//)
      expect(data.otpauthUrl).to.include(`secret=${data.secret}`)
    })

    it('leaves NO sso.totp rows before verification', async () => {
      const { user } = await ctx.sso.createUser('x')
      const provider = ctx.sso.getProvider('totp')!
      await provider.step({ label: 'l1' }, { kind: 'bind', userId: user.id })
      expect(await ctx.database.get('sso.totp' as any, {})).to.have.length(0)
    })
  })

  describe('bind (step 2 verify)', () => {
    let ctx: Context
    const T0 = 1700000000000

    beforeEach(async () => {
      vi.useFakeTimers({ now: T0 })
      ctx = await setup()
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    it('valid code → atomic link + sso.totp row', async () => {
      const { user } = await ctx.sso.createUser('x')
      const provider = ctx.sso.getProvider('totp')!
      const startResult = await provider.step({ label: 'alice' }, { kind: 'bind', userId: user.id })
      const { challengeId } = startResult as any
      const secret = (startResult as any).data.secret
      const code = totp(base32Decode(secret), Math.floor(T0 / 1000), 30, 6, 'sha1')
      const finishResult = await provider.step({ challengeId, code }, { kind: 'bind', userId: user.id })
      expect(finishResult.phase).to.equal('finish')
      const identities = await ctx.sso.getIdentities(user.id)
      expect(identities.map(i => i.provider)).to.include('totp')
      const rows = await ctx.database.get('sso.totp' as any, {})
      expect(rows).to.have.length(1)
      expect(rows[0].secret).to.equal(secret)
    })

    it('wrong code → VERIFICATION_FAILED, pending persists by default', async () => {
      const { user } = await ctx.sso.createUser('x')
      const provider = ctx.sso.getProvider('totp')!
      const start = await provider.step({}, { kind: 'bind', userId: user.id })
      const { challengeId } = start as any
      let err: any
      try {
        await provider.step({ challengeId, code: '000000' }, { kind: 'bind', userId: user.id })
      } catch (e) { err = e }
      expect(err?.code).to.equal('VERIFICATION_FAILED')
      expect(await ctx.database.get('sso.totp' as any, {})).to.have.length(0)
    })
  })

  describe('custom config', () => {
    const T0 = 1700000000000

    beforeEach(() => {
      vi.useFakeTimers({ now: T0 })
    })

    afterEach(() => {
      vi.useRealTimers()
    })

    it('honors digits / period / algorithm', async () => {
      const ctx = await setup({ digits: 8, period: 60, algorithm: 'sha256', issuer: 'TestCo' })
      const { user } = await ctx.sso.createUser('x')
      const provider = ctx.sso.getProvider('totp')!
      const start = await provider.step({ label: 'bob' }, { kind: 'bind', userId: user.id })
      const data = (start as any).data
      expect(data.otpauthUrl).to.include('digits=8')
      expect(data.otpauthUrl).to.include('period=60')
      expect(data.otpauthUrl).to.include('algorithm=SHA256')
      expect(data.otpauthUrl).to.include('issuer=TestCo')
      const code = totp(base32Decode(data.secret), Math.floor(T0 / 1000), 60, 8, 'sha256')
      expect(code).to.have.length(8)
      const finish = await provider.step({ challengeId: (start as any).challengeId, code }, { kind: 'bind', userId: user.id })
      expect(finish.phase).to.equal('finish')
    })
  })
})
