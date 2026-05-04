import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import Timer from '@cordisjs/plugin-timer'
import Sso from '@cordisjs/plugin-sso'
import { expect } from 'chai'
import { install, InstalledClock } from '@sinonjs/fake-timers'
import { WebAuthnEmulator } from 'nid-webauthn-emulator'
import WebAuthnProvider, { Config } from '../src'

const ORIGIN = 'https://example.com'
const RP_ID = 'example.com'

async function setup(extra: Partial<Config> = {}) {
  const ctx = new Context()
  await ctx.plugin(Database)
  await ctx.plugin(MemoryDriver)
  await ctx.plugin(Timer)
  await ctx.plugin(Sso)
  await ctx.plugin(WebAuthnProvider, {
    rpName: 'TestRP',
    rpId: RP_ID,
    origin: ORIGIN,
    timeout: 60_000,
    ...extra,
  })
  return ctx
}

describe('@cordisjs/plugin-sso-webauthn', () => {
  describe('register round-trip', () => {
    let ctx: Context
    let emulator: WebAuthnEmulator

    beforeEach(async () => {
      ctx = await setup()
      emulator = new WebAuthnEmulator()
    })

    it('completes a registration with a virtual authenticator', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      const { user } = await ctx.sso.createUser('webauthn')

      const { challengeId, data: options } = await provider.challenge!({
        type: 'register',
        userId: user.id,
      }) as any

      const attestation = emulator.createJSON(ORIGIN, options)
      const ok = await provider.verify!(challengeId, JSON.stringify(attestation))
      expect(ok).to.equal(true)

      const rows = await ctx.database.get('sso.webauthn' as any, {})
      expect(rows).to.have.length(1)
      const [row] = rows
      expect(row.credentialId).to.equal(attestation.id)
      expect(row.signCount).to.be.a('number')
      expect(row.publicKey).to.be.a('string').and.match(/^[A-Za-z0-9+/=]+$/)
      // verify() linked a fresh identity owned by the challenge's userId.
      const identity = await ctx.sso.getIdentity(row.identityId)
      expect(identity?.userId).to.equal(user.id)
      expect(identity?.provider).to.equal('webauthn')
    })

    it('rejects a register verify when the challenge lacked userId', async () => {
      const provider = ctx.sso.getProvider('webauthn')!

      const { challengeId, data: options } = await provider.challenge!({
        type: 'register',
      }) as any

      const attestation = emulator.createJSON(ORIGIN, options)
      const ok = await provider.verify!(challengeId, JSON.stringify(attestation))
      expect(ok).to.equal(false)
      expect(await ctx.database.get('sso.webauthn' as any, {})).to.have.length(0)
    })
  })

  describe('authentication round-trip', () => {
    let ctx: Context
    let emulator: WebAuthnEmulator
    let userId: number
    let identityId: number
    let credentialId: string

    beforeEach(async () => {
      ctx = await setup()
      emulator = new WebAuthnEmulator()

      const provider = ctx.sso.getProvider('webauthn')!
      const created = await ctx.sso.createUser('webauthn')
      userId = created.user.id

      const { challengeId, data: options } = await provider.challenge!({
        type: 'register',
        userId,
      }) as any
      const attestation = emulator.createJSON(ORIGIN, options)
      await provider.verify!(challengeId, JSON.stringify(attestation))
      credentialId = attestation.id
      // verify() linked a new identity — capture its id for later assertions.
      const [row] = await ctx.database.get('sso.webauthn' as any, { credentialId })
      identityId = row.identityId
    })

    it('verifies a real assertion and bumps signCount + lastUsedAt', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      const [before] = await ctx.database.get('sso.webauthn' as any, { credentialId })

      const { challengeId, data: options } = await provider.challenge!({ userId }) as any
      const assertion = emulator.getJSON(ORIGIN, options)
      const ok = await provider.verify!(challengeId, JSON.stringify(assertion))
      expect(ok).to.equal(true)

      const [after] = await ctx.database.get('sso.webauthn' as any, { credentialId })
      expect(after.signCount).to.be.greaterThan(before.signCount)
      expect(after.lastUsedAt).to.be.instanceOf(Date)
    })

    it('does not expose resolve (passwordless login must go through challenge+verify)', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      expect(provider.resolve).to.equal(undefined)
    })
  })

  describe('verify early-exit branches', () => {
    let ctx: Context
    let emulator: WebAuthnEmulator

    beforeEach(async () => {
      ctx = await setup()
      emulator = new WebAuthnEmulator()
    })

    it('returns false for an unknown challengeId', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      const result = await provider.verify!('not-a-real-challenge', JSON.stringify({}))
      expect(result).to.equal(false)
    })

    it('returns false for an expired challenge', async () => {
      const clock = install({ now: Date.now() })
      try {
        const ctx2 = await setup({ timeout: 1000 })
        const emu2 = new WebAuthnEmulator()
        const provider = ctx2.sso.getProvider('webauthn')!
        const { user } = await ctx2.sso.createUser('webauthn')

        const { challengeId, data: options } = await provider.challenge!({
          type: 'register',
          userId: user.id,
        }) as any

        clock.tick(2000)
        const attestation = emu2.createJSON(ORIGIN, options)
        const ok = await provider.verify!(challengeId, JSON.stringify(attestation))
        expect(ok).to.equal(false)
      } finally {
        clock.uninstall()
      }
    })
  })

  describe('register (admin direct path)', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('inserts a row with required fields', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      const { identityId } = await ctx.sso.createUser('webauthn')
      await provider.register!({
        identityId,
        credentialId: 'cred-xyz',
        publicKey: 'pk-base64',
        signCount: 0,
        deviceType: 'singleDevice',
        backedUp: false,
      })
      const [row] = await ctx.database.get('sso.webauthn' as any, { credentialId: 'cred-xyz' })
      expect(row).to.exist
      expect(row.identityId).to.equal(identityId)
    })

    it('rejects missing required fields', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      let err: Error | undefined
      try { await provider.register!({ credentialId: 'a', publicKey: 'b' }) } catch (e) { err = e as Error }
      expect(err).to.exist
      expect(err!.message).to.match(/identityId/)
    })
  })
})
