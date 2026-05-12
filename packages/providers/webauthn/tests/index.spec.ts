import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import Server from '@cordisjs/plugin-server'
import LoggerConsole from '@cordisjs/plugin-logger-console'
import Timer from '@cordisjs/plugin-timer'
import Sso from '@cordisjs/plugin-sso'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { WebAuthnEmulator } from 'nid-webauthn-emulator'
import WebAuthnProvider, { Config } from '../src'

const ORIGIN = 'https://example.com'
const RP_ID = 'example.com'

async function setup(extra: Partial<Config> = {}) {
  const ctx = new Context()
  await ctx.plugin(Database)
  await ctx.plugin(MemoryDriver)
  await ctx.plugin(LoggerConsole)
  await ctx.plugin(Timer)
  await ctx.plugin(Server, { host: '127.0.0.1', port: 0 })
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
  describe('bind (register ceremony) via step', () => {
    let ctx: Context
    let emulator: WebAuthnEmulator

    beforeEach(async () => {
      ctx = await setup()
      emulator = new WebAuthnEmulator()
    })

    it('step1 issues webauthn-create options, step2 verifies + writes credential', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      const { user } = await ctx.sso.createUser('x')

      const start = await provider.step({}, { kind: 'bind', userId: user.id })
      expect(start.phase).to.equal('challenge')
      expect((start as any).response.shape).to.equal('webauthn-create')
      const options = (start as any).response.options
      const attestation = emulator.createJSON(ORIGIN, options)

      const finish = await provider.step(
        { challengeId: (start as any).challengeId, response: attestation },
        { kind: 'bind', userId: user.id },
      )
      expect(finish.phase).to.equal('finish')

      const rows = await ctx.database.get('sso.webauthn' as any, {})
      expect(rows).to.have.length(1)
      expect(rows[0].credentialId).to.equal(attestation.id)
      const identities = await ctx.sso.getIdentities(user.id)
      expect(identities.map(i => i.provider)).to.include('webauthn')
    })
  })

  describe('login via step (authenticate ceremony)', () => {
    let ctx: Context
    let emulator: WebAuthnEmulator
    let userId: number
    let credentialId: string

    beforeEach(async () => {
      ctx = await setup()
      emulator = new WebAuthnEmulator()
      const provider = ctx.sso.getProvider('webauthn')!
      const { user } = await ctx.sso.createUser('x')
      userId = user.id
      const start = await provider.step({}, { kind: 'bind', userId })
      const options = (start as any).response.options
      const attestation = emulator.createJSON(ORIGIN, options)
      credentialId = attestation.id
      await provider.step(
        { challengeId: (start as any).challengeId, response: attestation },
        { kind: 'bind', userId },
      )
    })

    it('login step1 issues webauthn-get options, step2 mints a session', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      const start = await provider.step({}, { kind: 'login' })
      expect(start.phase).to.equal('challenge')
      expect((start as any).response.shape).to.equal('webauthn-get')
      const options = (start as any).response.options

      const assertion = emulator.getJSON(ORIGIN, options)
      const finish = await provider.step(
        { challengeId: (start as any).challengeId, response: assertion },
        { kind: 'login' },
      )
      expect(finish.phase).to.equal('finish')
      expect((finish as any).token).to.be.a('string')
      expect((finish as any).userId).to.equal(userId)
      const [row] = await ctx.database.get('sso.webauthn' as any, { credentialId })
      expect(row.signCount).to.be.at.least(0)
      expect(row.lastUsedAt).to.be.instanceOf(Date)
    })

    it('wrong credentialId (unknown) → VERIFICATION_FAILED + pending consumed', async () => {
      const provider = ctx.sso.getProvider('webauthn')!
      const start = await provider.step({}, { kind: 'login' })
      const fakeAssertion = { id: 'no-such-credential' }
      let err: any
      try {
        await provider.step(
          { challengeId: (start as any).challengeId, response: fakeAssertion },
          { kind: 'login' },
        )
      } catch (e) { err = e }
      expect(err?.code).to.equal('VERIFICATION_FAILED')
      // consumeOnFailure=true → replaying with the same challengeId gives CHALLENGE_EXPIRED
      let err2: any
      try {
        await provider.step(
          { challengeId: (start as any).challengeId, response: fakeAssertion },
          { kind: 'login' },
        )
      } catch (e) { err2 = e }
      expect(err2?.code).to.equal('CHALLENGE_EXPIRED')
    })
  })

  describe('expiry', () => {
    it('returns CHALLENGE_EXPIRED after timeout', async () => {
      vi.useFakeTimers({ now: Date.now() })
      try {
        const ctx = await setup({ timeout: 1000 })
        const emu = new WebAuthnEmulator()
        const provider = ctx.sso.getProvider('webauthn')!
        const { user } = await ctx.sso.createUser('x')
        const start = await provider.step({}, { kind: 'bind', userId: user.id })
        vi.advanceTimersByTime(2000)
        const options = (start as any).response.options
        const attestation = emu.createJSON(ORIGIN, options)
        let err: any
        try {
          await provider.step(
            { challengeId: (start as any).challengeId, response: attestation },
            { kind: 'bind', userId: user.id },
          )
        } catch (e) { err = e }
        expect(err?.code).to.equal('CHALLENGE_EXPIRED')
      } finally {
        vi.useRealTimers()
      }
    })
  })
})
