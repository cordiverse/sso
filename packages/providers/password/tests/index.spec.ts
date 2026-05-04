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
  describe('register', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('hashes the password, stores a salt, and sets sso.user.name + display', async () => {
      const { user, identityId } = await ctx.sso.createUser('password')
      const provider = ctx.sso.getProvider('password')!
      await provider.register!({ identityId, username: 'alice', password: 'longenough' })
      const [row] = await ctx.database.get('sso.password' as any, { identityId })
      expect(row).to.exist
      expect(row.hash).not.to.equal('longenough')
      expect(row.hash).to.match(/^[0-9a-f]+$/)
      expect(row.salt).to.have.length(32)
      expect(row.identityId).to.equal(identityId)
      // The username lives on sso.user now, not in the password row.
      const [updated] = await ctx.database.get('sso.user', { id: user.id })
      expect(updated.name).to.equal('alice')
      // display seeded from username on first-time register.
      expect(updated.display).to.equal('alice')
    })

    it('does not overwrite an existing sso.user.display', async () => {
      const { user, identityId } = await ctx.sso.createUser('password', undefined, { display: 'Pre-Set' })
      const provider = ctx.sso.getProvider('password')!
      await provider.register!({ identityId, username: 'alice', password: 'longenough' })
      const [updated] = await ctx.database.get('sso.user', { id: user.id })
      expect(updated.display).to.equal('Pre-Set')
      expect(updated.name).to.equal('alice')
    })

    it('rejects passwords shorter than minLength', async () => {
      const { identityId } = await ctx.sso.createUser('password')
      const provider = ctx.sso.getProvider('password')!
      let err: Error | undefined
      try {
        await provider.register!({ identityId, username: 'alice', password: 'short' })
      } catch (e) { err = e as Error }
      expect(err).to.exist
      expect(err!.message).to.match(/at least 8 characters/)
    })

    it('rejects missing username or password', async () => {
      const { identityId } = await ctx.sso.createUser('password')
      const provider = ctx.sso.getProvider('password')!
      let e1: Error | undefined, e2: Error | undefined
      try { await provider.register!({ identityId, password: 'longenough' }) } catch (e) { e1 = e as Error }
      try { await provider.register!({ identityId, username: 'a' }) } catch (e) { e2 = e as Error }
      expect(e1).to.exist
      expect(e2).to.exist
    })

    it('rejects missing identityId', async () => {
      const provider = ctx.sso.getProvider('password')!
      let err: Error | undefined
      try {
        await provider.register!({ username: 'alice', password: 'longenough' })
      } catch (e) { err = e as Error }
      expect(err).to.exist
      expect(err!.message).to.match(/identityId required/)
    })

    it('rejects duplicate usernames', async () => {
      const { identityId: id1 } = await ctx.sso.createUser('password')
      const { identityId: id2 } = await ctx.sso.createUser('password')
      const provider = ctx.sso.getProvider('password')!
      await provider.register!({ identityId: id1, username: 'alice', password: 'longenough' })
      let err: Error | undefined
      try {
        await provider.register!({ identityId: id2, username: 'alice', password: 'longenough' })
      } catch (e) { err = e as Error }
      expect(err).to.exist
      expect(err!.message).to.match(/already taken/)
    })
  })

  describe('resolve', () => {
    let ctx: Context
    let identityId: number

    beforeEach(async () => {
      ctx = await setup()
      const created = await ctx.sso.createUser('password')
      identityId = created.identityId
      const provider = ctx.sso.getProvider('password')!
      await provider.register!({ identityId, username: 'alice', password: 'longenough' })
    })

    it('accepts the correct password', async () => {
      const provider = ctx.sso.getProvider('password')!
      const result = await provider.resolve!({ username: 'alice', password: 'longenough' })
      expect(result).to.deep.equal({ identityId })
    })

    it('rejects the wrong password', async () => {
      const provider = ctx.sso.getProvider('password')!
      expect(await provider.resolve!({ username: 'alice', password: 'wrong-password' })).to.be.null
    })

    it('rejects an unknown username', async () => {
      const provider = ctx.sso.getProvider('password')!
      expect(await provider.resolve!({ username: 'nobody', password: 'longenough' })).to.be.null
    })

    it('rejects missing fields', async () => {
      const provider = ctx.sso.getProvider('password')!
      expect(await provider.resolve!({ username: 'alice' })).to.be.null
      expect(await provider.resolve!({ password: 'longenough' })).to.be.null
    })

    it('throws on ambiguous identifier (invariant violation)', async () => {
      // Arrange a collision: another user's resolveUser also claims "alice".
      const { user: other } = await ctx.sso.createUser('x')
      class Collider extends (await import('@cordisjs/plugin-sso')).SsoProvider {
        name = 'collider'
        type = 'credentials' as const
        interactive = false
        autoRegister = false
        async resolveUser(identifier: string) {
          return identifier === 'alice' ? other.id : null
        }
      }
      await ctx.plugin(Collider as any)
      // Give the plugin a tick to register.
      await new Promise(r => setTimeout(r, 0))
      const provider = ctx.sso.getProvider('password')!
      let err: Error | undefined
      try {
        await provider.resolve!({ username: 'alice', password: 'longenough' })
      } catch (e) { err = e as Error }
      expect(err).to.exist
      expect(err!.message).to.match(/ambiguous/i)
    })
  })

  describe('algorithm config', () => {
    it('produces sha512-length hashes when configured', async () => {
      const ctx = await setup({ algorithm: 'sha512' })
      const { identityId } = await ctx.sso.createUser('password')
      const provider = ctx.sso.getProvider('password')!
      await provider.register!({ identityId, username: 'alice', password: 'longenough' })
      const [row] = await ctx.database.get('sso.password' as any, { identityId })
      expect(row.hash).to.have.length(128) // 512 bits = 64 bytes = 128 hex
    })
  })
})
