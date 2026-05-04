import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import Sso from '@cordisjs/plugin-sso'
import { expect } from 'chai'
import { install, InstalledClock } from '@sinonjs/fake-timers'
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
  await ctx.plugin(Sso)
  await ctx.plugin(Totp, config)
  return ctx
}

describe('@cordisjs/plugin-sso-totp', () => {
  describe('register', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('creates an unverified record with a base32 secret + otpauth url', async () => {
      const { identityId } = await ctx.sso.createUser('totp')
      const provider = ctx.sso.getProvider('totp')!
      const result = await provider.register!({ identityId, label: 'alice@example.com' })
      const data = result.data!
      expect(data.secret).to.be.a('string').and.match(/^[A-Z2-7]+$/)
      expect(data.otpauthUrl).to.match(/^otpauth:\/\/totp\//)
      expect(data.otpauthUrl).to.include(`secret=${data.secret}`)
      expect(data.otpauthUrl).to.include('issuer=Cordis')
      expect(data.otpauthUrl).to.include('algorithm=SHA1')
      expect(data.otpauthUrl).to.include('digits=6')
      expect(data.otpauthUrl).to.include('period=30')

      const [row] = await ctx.database.get('sso.totp' as any, { identityId })
      expect(row.verified).to.equal(false)
      expect(row.label).to.equal('alice@example.com')
    })

    it('rejects missing identityId', async () => {
      const provider = ctx.sso.getProvider('totp')!
      let err: Error | undefined
      try { await provider.register!({}) } catch (e) { err = e as Error }
      expect(err).to.exist
      expect(err!.message).to.match(/identityId required/)
    })
  })

  describe('verify + resolve', () => {
    let ctx: Context
    let clock: InstalledClock
    const T0 = 1700000000000 // some fixed instant

    beforeEach(async () => {
      clock = install({ now: T0 })
      ctx = await setup()
    })

    afterEach(() => {
      clock.uninstall()
    })

    async function registerFor(identityId: number) {
      const provider = ctx.sso.getProvider('totp')!
      const { data } = await provider.register!({ identityId })
      return data!.secret as string
    }

    it('verify accepts a correct code and flips verified=true', async () => {
      const { identityId } = await ctx.sso.createUser('totp')
      const secret = await registerFor(identityId)
      const code = totp(base32Decode(secret), Math.floor(T0 / 1000), 30, 6, 'sha1')
      const provider = ctx.sso.getProvider('totp')!

      // TOTP does not expose resolve — it is not a primary login factor. The
      // only way to prove the code is provider.verify(), which doubles as
      // the activation step for register and as the future 2FA step-up path.
      expect(provider.resolve).to.equal(undefined)

      const ok = await provider.verify!(String(identityId), code)
      expect(ok).to.equal(true)

      const [row] = await ctx.database.get('sso.totp' as any, { identityId })
      expect(row.verified).to.equal(true)
    })

    it('verify rejects an incorrect code', async () => {
      const { identityId } = await ctx.sso.createUser('totp')
      await registerFor(identityId)
      const provider = ctx.sso.getProvider('totp')!
      expect(await provider.verify!(String(identityId), '000000')).to.equal(false)
    })

    it('verify accepts codes within ±window periods', async () => {
      const { identityId } = await ctx.sso.createUser('totp')
      const secret = await registerFor(identityId)
      const provider = ctx.sso.getProvider('totp')!
      const t = Math.floor(T0 / 1000)
      const sec = base32Decode(secret)

      // default window = 1 → previous and next 30s slots both accepted
      const codePast = totp(sec, t - 30, 30, 6, 'sha1')
      const codeFuture = totp(sec, t + 30, 30, 6, 'sha1')
      expect(await provider.verify!(String(identityId), codePast)).to.equal(true)
      expect(await provider.verify!(String(identityId), codeFuture)).to.equal(true)
    })

    it('rejects a code outside the window', async () => {
      const { identityId } = await ctx.sso.createUser('totp')
      const secret = await registerFor(identityId)
      const provider = ctx.sso.getProvider('totp')!
      const t = Math.floor(T0 / 1000)
      const codeFar = totp(base32Decode(secret), t + 90, 30, 6, 'sha1')
      expect(await provider.verify!(String(identityId), codeFar)).to.equal(false)
    })
  })

  describe('custom config', () => {
    let clock: InstalledClock
    const T0 = 1700000000000

    beforeEach(() => {
      clock = install({ now: T0 })
    })

    afterEach(() => {
      clock.uninstall()
    })

    it('honors digits / period / algorithm', async () => {
      const ctx = await setup({ digits: 8, period: 60, algorithm: 'sha256', issuer: 'TestCo' })
      const { identityId } = await ctx.sso.createUser('totp')
      const provider = ctx.sso.getProvider('totp')!
      const { data } = await provider.register!({ identityId, label: 'bob' })
      expect(data!.otpauthUrl).to.include('digits=8')
      expect(data!.otpauthUrl).to.include('period=60')
      expect(data!.otpauthUrl).to.include('algorithm=SHA256')
      expect(data!.otpauthUrl).to.include('issuer=TestCo')

      const code = totp(base32Decode(data!.secret), Math.floor(T0 / 1000), 60, 8, 'sha256')
      expect(code).to.have.length(8)
      expect(await provider.verify!(String(identityId), code)).to.equal(true)
    })
  })
})
