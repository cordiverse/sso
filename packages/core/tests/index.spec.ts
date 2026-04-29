import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import { expect } from 'chai'
import { install, InstalledClock } from '@sinonjs/fake-timers'
import Sso, { SsoProvider } from '../src'

function sleep(ms = 0) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms))
}

async function setup(config: Sso.Config = {}) {
  const ctx = new Context()
  await ctx.plugin(Database)
  await ctx.plugin(MemoryDriver)
  await ctx.plugin(Sso, config)
  return ctx
}

class FakeProvider extends SsoProvider {
  name: string
  interactive: boolean
  autoRegister: boolean
  constructor(ctx: Context, config: { name: string; interactive?: boolean; autoRegister?: boolean }) {
    super(ctx)
    this.name = config.name
    this.interactive = config.interactive ?? false
    this.autoRegister = config.autoRegister ?? false
  }
}

describe('@cordisjs/plugin-sso', () => {
  describe('provider registration', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('registers a provider via Service.init', async () => {
      await ctx.plugin(FakeProvider, { name: 'p1' })
      expect(ctx.sso.getProvider('p1')).to.exist
      expect(ctx.sso.getProviders().map(p => p.name)).to.include('p1')
    })

    it('removes a provider when its plugin disposes', async () => {
      await ctx.plugin(FakeProvider, { name: 'p1' })
      expect(ctx.sso.getProvider('p1')).to.exist
      ctx.registry.delete(FakeProvider)
      await sleep()
      expect(ctx.sso.getProvider('p1')).to.be.undefined
    })

    it('throws on duplicate name', async () => {
      await ctx.plugin(FakeProvider, { name: 'p1' })
      const dup = Object.create(SsoProvider.prototype) as SsoProvider
      ;(dup as any).name = 'p1'
      expect(() => ctx.sso.register(dup)).to.throw('already registered')
    })
  })

  describe('user / identity CRUD', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('createUser creates one user + one identity', async () => {
      const { user, identityId } = await ctx.sso.createUser('password')
      expect(user.id).to.be.a('number')
      expect(user.createdAt).to.be.instanceOf(Date)
      const identity = await ctx.sso.getIdentity(identityId)
      expect(identity).to.exist
      expect(identity!.userId).to.equal(user.id)
      expect(identity!.provider).to.equal('password')
      const users = await ctx.database.get('sso.user', {})
      const identities = await ctx.database.get('sso.identity', {})
      expect(users).to.have.length(1)
      expect(identities).to.have.length(1)
    })

    it('link adds a second identity and bumps updatedAt', async () => {
      const { user } = await ctx.sso.createUser('password')
      const original = user.updatedAt.getTime()
      await sleep(10)
      const { identityId: id2 } = await ctx.sso.link(user.id, 'totp')
      const identities = await ctx.sso.getIdentities(user.id)
      expect(identities).to.have.length(2)
      expect(identities.map(i => i.provider).sort()).to.deep.equal(['password', 'totp'])
      const reloaded = await ctx.sso.getUser(user.id)
      expect(reloaded!.updatedAt.getTime()).to.be.greaterThan(original)
      expect(id2).to.be.a('number')
    })

    it('unlink removes a non-last identity', async () => {
      const { user } = await ctx.sso.createUser('password')
      const { identityId: id2 } = await ctx.sso.link(user.id, 'totp')
      await ctx.sso.unlink(id2)
      const identities = await ctx.sso.getIdentities(user.id)
      expect(identities).to.have.length(1)
      expect(identities[0].provider).to.equal('password')
    })

    it('unlink refuses to remove the last identity', async () => {
      const { user, identityId } = await ctx.sso.createUser('password')
      let err: Error | undefined
      try { await ctx.sso.unlink(identityId) } catch (e) { err = e as Error }
      expect(err).to.exist
      expect(err!.message).to.match(/last identity/)
      // identity still there
      const identities = await ctx.sso.getIdentities(user.id)
      expect(identities).to.have.length(1)
    })

    it('getUser / getIdentity return null for unknown ids', async () => {
      expect(await ctx.sso.getUser(999)).to.be.null
      expect(await ctx.sso.getIdentity(999)).to.be.null
    })
  })

  describe('session lifecycle', () => {
    let ctx: Context
    let clock: InstalledClock

    beforeEach(async () => {
      clock = install({ now: 1700000000000 })
      ctx = await setup({ sessionMaxAge: 60_000 })
    })

    afterEach(() => {
      clock.uninstall()
    })

    it('createSession + validateSession round-trips', async () => {
      const { user, identityId } = await ctx.sso.createUser('password')
      const token = await ctx.sso.createSession(user.id, identityId)
      expect(token).to.be.a('string').with.length.greaterThan(0)
      const validated = await ctx.sso.validateSession(token)
      expect(validated).to.exist
      expect(validated!.id).to.equal(user.id)
    })

    it('validateSession returns null after expiry and self-deletes', async () => {
      const { user, identityId } = await ctx.sso.createUser('password')
      const token = await ctx.sso.createSession(user.id, identityId)
      clock.tick(60_001)
      expect(await ctx.sso.validateSession(token)).to.be.null
      const remaining = await ctx.database.get('sso.session', { token })
      expect(remaining).to.have.length(0)
    })

    it('destroySession invalidates a token', async () => {
      const { user, identityId } = await ctx.sso.createUser('password')
      const token = await ctx.sso.createSession(user.id, identityId)
      await ctx.sso.destroySession(token)
      expect(await ctx.sso.validateSession(token)).to.be.null
    })

    it('destroyUserSessions clears all but except', async () => {
      const { user, identityId } = await ctx.sso.createUser('password')
      const t1 = await ctx.sso.createSession(user.id, identityId)
      const t2 = await ctx.sso.createSession(user.id, identityId)
      const t3 = await ctx.sso.createSession(user.id, identityId)
      await ctx.sso.destroyUserSessions(user.id, t2)
      expect(await ctx.sso.validateSession(t1)).to.be.null
      expect(await ctx.sso.validateSession(t2)).to.exist
      expect(await ctx.sso.validateSession(t3)).to.be.null
    })

    it('destroyUserSessions without except clears everything', async () => {
      const { user, identityId } = await ctx.sso.createUser('password')
      const t1 = await ctx.sso.createSession(user.id, identityId)
      const t2 = await ctx.sso.createSession(user.id, identityId)
      await ctx.sso.destroyUserSessions(user.id)
      expect(await ctx.sso.validateSession(t1)).to.be.null
      expect(await ctx.sso.validateSession(t2)).to.be.null
    })

    it('honors custom sessionMaxAge', async () => {
      clock.uninstall()
      clock = install({ now: 1700000000000 })
      const ctx2 = new Context()
      await ctx2.plugin(Database)
      await ctx2.plugin(MemoryDriver)
      await ctx2.plugin(Sso, { sessionMaxAge: 1000 })
      const { user, identityId } = await ctx2.sso.createUser('password')
      const token = await ctx2.sso.createSession(user.id, identityId)
      clock.tick(500)
      expect(await ctx2.sso.validateSession(token)).to.exist
      clock.tick(600)
      expect(await ctx2.sso.validateSession(token)).to.be.null
    })
  })

  describe('getProviderMetas (waterfall)', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('returns base projection when no listener is attached', async () => {
      await ctx.plugin(FakeProvider, { name: 'a', interactive: true, autoRegister: false })
      await ctx.plugin(FakeProvider, { name: 'b', interactive: false, autoRegister: true })
      const metas = await ctx.sso.getProviderMetas()
      expect(metas).to.have.length(2)
      const byName = Object.fromEntries(metas.map(m => [m.name, m]))
      expect(byName.a).to.deep.equal({ name: 'a', interactive: true, autoRegister: false })
      expect(byName.b).to.deep.equal({ name: 'b', interactive: false, autoRegister: true })
    })

    it('listeners can augment via next()', async () => {
      await ctx.plugin(FakeProvider, { name: 'a' })
      function listener(c: Context) {
        c.on('sso/provider-meta', async (_metas, next) => {
          const list = await next()
          return list.map(m => ({ ...m, extra: m.name } as any))
        })
      }
      await ctx.plugin(listener)
      const metas = await ctx.sso.getProviderMetas()
      expect((metas[0] as any).extra).to.equal('a')
    })

    it('augmentation goes away when the listener plugin disposes', async () => {
      await ctx.plugin(FakeProvider, { name: 'a' })
      function listener(c: Context) {
        c.on('sso/provider-meta', async (_metas, next) => {
          const list = await next()
          return list.map(m => ({ ...m, extra: 'tagged' } as any))
        })
      }
      await ctx.plugin(listener)
      expect((await ctx.sso.getProviderMetas())[0]).to.have.property('extra')
      ctx.registry.delete(listener)
      await sleep()
      expect((await ctx.sso.getProviderMetas())[0]).not.to.have.property('extra')
    })
  })
})
