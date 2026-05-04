import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import Sso from '@cordisjs/plugin-sso'
import { expect } from 'chai'
import Password from '../src'

async function setup(config: Password.Config = {}) {
  const ctx = new Context()
  await ctx.plugin(Database)
  await ctx.plugin(MemoryDriver)
  await ctx.plugin(Sso)
  await ctx.plugin(Password, config)
  return ctx
}

namespace Password {
  export type Config = ConstructorParameters<typeof Password>[1]
}

describe('@cordisjs/plugin-sso-password', () => {
  describe('register via step', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('step(register) hashes the password, stores a salt, seeds sso.user.name + display', async () => {
      const provider = ctx.sso.getProvider('password')!
      const result = await provider.step({ username: 'alice', password: 'longenough' }, { kind: 'register' })
      expect(result.phase).to.equal('finish')
      const identityId = (result as any).identityId
      const [row] = await ctx.database.get('sso.password' as any, { identityId })
      expect(row).to.exist
      expect(row.hash).not.to.equal('longenough')
      expect(row.hash).to.match(/^[0-9a-f]+$/)
      expect(row.salt).to.have.length(32)
      expect(row.identityId).to.equal(identityId)
      const [updated] = await ctx.database.get('sso.user', { id: (result as any).userId })
      expect(updated.name).to.equal('alice')
      expect(updated.display).to.equal('alice')
    })

    it('does not overwrite an existing sso.user.display when binding', async () => {
      const { user, identityId } = await ctx.sso.createUser('password', undefined, { display: 'Pre-Set' })
      const provider = ctx.sso.getProvider('password')!
      await provider.step({ username: 'alice', password: 'longenough' }, { kind: 'bind', userId: user.id })
      // The initial identity created by createUser is NOT the password-bound one — we just
      // care that display survives binding.
      const [updated] = await ctx.database.get('sso.user', { id: user.id })
      expect(updated.display).to.equal('Pre-Set')
      // name is set by writeIdentity on bind
      expect(updated.name).to.equal('alice')
    })

    it('rejects passwords shorter than minLength', async () => {
      const provider = ctx.sso.getProvider('password')!
      let err: any
      try {
        await provider.step({ username: 'alice', password: 'short' }, { kind: 'register' })
      } catch (e) { err = e }
      expect(err).to.exist
      expect(err.code).to.equal('PASSWORD_TOO_SHORT')
    })

    it('rejects missing fields on register', async () => {
      const provider = ctx.sso.getProvider('password')!
      let e1: any, e2: any
      try { await provider.step({ password: 'longenough' }, { kind: 'register' }) } catch (e) { e1 = e }
      try { await provider.step({ username: 'a' }, { kind: 'register' }) } catch (e) { e2 = e }
      expect(e1?.code).to.equal('INVALID_REQUEST')
      expect(e2?.code).to.equal('INVALID_REQUEST')
    })

    it('rejects duplicate usernames on register', async () => {
      const provider = ctx.sso.getProvider('password')!
      await provider.step({ username: 'alice', password: 'longenough' }, { kind: 'register' })
      let err: any
      try {
        await provider.step({ username: 'alice', password: 'longenough' }, { kind: 'register' })
      } catch (e) { err = e }
      expect(err).to.exist
      expect(err.code).to.equal('USERNAME_TAKEN')
    })
  })

  describe('login via step', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
      const provider = ctx.sso.getProvider('password')!
      await provider.step({ username: 'alice', password: 'longenough' }, { kind: 'register' })
    })

    it('accepts the correct password and mints a session', async () => {
      const provider = ctx.sso.getProvider('password')!
      const result = await provider.step({ username: 'alice', password: 'longenough' }, { kind: 'login' })
      expect(result.phase).to.equal('finish')
      expect((result as any).token).to.be.a('string')
    })

    it('jitProvisioning=false → ACCOUNT_NOT_FOUND on unknown username', async () => {
      const provider = ctx.sso.getProvider('password')!
      let err: any
      try {
        await provider.step({ username: 'nobody', password: 'longenough' }, { kind: 'login' })
      } catch (e) { err = e }
      expect(err?.code).to.equal('ACCOUNT_NOT_FOUND')
    })

    it('wrong password → ACCOUNT_NOT_FOUND (no user enumeration)', async () => {
      const provider = ctx.sso.getProvider('password')!
      let err: any
      try {
        await provider.step({ username: 'alice', password: 'wrong-password' }, { kind: 'login' })
      } catch (e) { err = e }
      expect(err?.code).to.equal('ACCOUNT_NOT_FOUND')
    })
  })

  describe('algorithm config', () => {
    it('produces sha512-length hashes when configured', async () => {
      const ctx = await setup({ algorithm: 'sha512' })
      const provider = ctx.sso.getProvider('password')!
      const result = await provider.step({ username: 'alice', password: 'longenough' }, { kind: 'register' })
      const [row] = await ctx.database.get('sso.password' as any, { identityId: (result as any).identityId })
      expect(row.hash).to.have.length(128)
    })
  })
})
