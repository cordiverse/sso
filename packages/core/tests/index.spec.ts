import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import { expect } from 'chai'
import { install, InstalledClock } from '@sinonjs/fake-timers'
import Sso, { CredentialsProvider, SsoProvider } from '../src'

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
  category = 'credentials' as const

  constructor(ctx: Context, config: { name: string; interactive?: boolean; autoRegister?: boolean; canBePrimary?: boolean; canStepUp?: boolean }) {
    super(ctx)
    this.name = config.name
    this.interactive = config.interactive ?? false
    this.autoRegister = config.autoRegister ?? false
    this.canBePrimary = config.canBePrimary ?? true
    this.canStepUp = config.canStepUp ?? false
  }

  async step() {
    return { phase: 'finish' as const }
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
      expect(await ctx.database.get('sso.user', {})).to.have.length(1)
      expect(await ctx.database.get('sso.identity', {})).to.have.length(1)
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
      expect(await ctx.database.get('sso.session', { token })).to.have.length(0)
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
  })

  describe('getProviderMetas (waterfall)', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    it('returns category + capability flags in the base projection', async () => {
      await ctx.plugin(FakeProvider, { name: 'a', interactive: true, autoRegister: false })
      await ctx.plugin(FakeProvider, { name: 'b', interactive: false, autoRegister: true, canBePrimary: false, canStepUp: true })
      const metas = await ctx.sso.getProviderMetas()
      expect(metas).to.have.length(2)
      const byName = Object.fromEntries(metas.map(m => [m.name, m]))
      expect(byName.a).to.deep.equal({ name: 'a', category: 'credentials', canBePrimary: true, canStepUp: false, autoRegister: false, interactive: true })
      expect(byName.b).to.deep.equal({ name: 'b', category: 'credentials', canBePrimary: false, canStepUp: true, autoRegister: true, interactive: false })
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
  })

  describe('findUserByIdentifier', () => {
    let ctx: Context

    beforeEach(async () => {
      ctx = await setup()
    })

    class Hooked extends SsoProvider {
      name: string
      category = 'credentials' as const
      constructor(ctx: Context, config: { name: string; userId: number; matches: string }) {
        super(ctx)
        this.name = config.name
        this._userId = config.userId
        this._matches = config.matches
      }
      _userId: number
      _matches: string
      async step() { return { phase: 'finish' as const } }
      async resolveUser(identifier: string) {
        return identifier === this._matches ? this._userId : null
      }
    }

    it('hits sso.user.name first, bypassing providers entirely', async () => {
      const { user } = await ctx.sso.createUser('x')
      await ctx.database.set('sso.user', { id: user.id }, { name: 'alice' })
      expect(await ctx.sso.findUserByIdentifier('alice')).to.deep.equal([user.id])
    })

    it('falls through to provider.resolveUser when no sso.user matches', async () => {
      const { user } = await ctx.sso.createUser('x')
      await ctx.plugin(Hooked, { name: 'hooked', userId: user.id, matches: 'by-provider' })
      await sleep()
      expect(await ctx.sso.findUserByIdentifier('by-provider')).to.deep.equal([user.id])
      expect(await ctx.sso.findUserByIdentifier('no-such-thing')).to.deep.equal([])
    })

    it('returns every distinct match when an identifier hits multiple layers', async () => {
      const { user: a } = await ctx.sso.createUser('x')
      const { user: b } = await ctx.sso.createUser('x')
      await ctx.database.set('sso.user', { id: a.id }, { name: 'alice@foo.com' })
      await ctx.plugin(Hooked, { name: 'mail-like', userId: b.id, matches: 'alice@foo.com' })
      await sleep()
      const hits = await ctx.sso.findUserByIdentifier('alice@foo.com')
      expect(hits).to.include.members([a.id, b.id])
      expect(hits).to.have.length(2)
    })

    it('deduplicates when sso.user.name and a provider both point at the same user', async () => {
      const { user } = await ctx.sso.createUser('x')
      await ctx.database.set('sso.user', { id: user.id }, { name: 'alice' })
      await ctx.plugin(Hooked, { name: 'echo', userId: user.id, matches: 'alice' })
      await sleep()
      expect(await ctx.sso.findUserByIdentifier('alice')).to.deep.equal([user.id])
    })
  })

  describe('CredentialsProvider template method', () => {
    class TestCreds extends CredentialsProvider<{ id: string }> {
      name = 'tc'
      autoRegister = true
      store = new Map<string, number>()
      async resolve(creds: { id: string }) {
        const id = this.store.get(creds.id)
        return id ? { identityId: id } : null
      }
      async writeIdentity(userId: number, identityId: number, creds: { id: string }) {
        this.store.set(creds.id, identityId)
      }
    }

    let ctx: Context
    beforeEach(async () => {
      ctx = await setup()
      await ctx.plugin(TestCreds)
      await sleep()
    })

    it('login → register fallback when autoRegister', async () => {
      const provider = ctx.sso.getProvider('tc')!
      const result = await provider.step({ id: 'u1' }, { kind: 'login' })
      expect(result.phase).to.equal('finish')
      expect((result as any).created).to.equal(true)
      expect((result as any).token).to.be.a('string')
    })

    it('login hit returns an existing session', async () => {
      const provider = ctx.sso.getProvider('tc')!
      await provider.step({ id: 'u2' }, { kind: 'register' })
      const result = await provider.step({ id: 'u2' }, { kind: 'login' })
      expect(result.phase).to.equal('finish')
      expect((result as any).created).to.equal(false)
    })

    it('bind links to ctx.userId', async () => {
      const { user } = await ctx.sso.createUser('x')
      const provider = ctx.sso.getProvider('tc')!
      const result = await provider.step({ id: 'bound' }, { kind: 'bind', userId: user.id })
      expect(result.phase).to.equal('finish')
      expect((result as any).userId).to.equal(user.id)
      const identities = await ctx.sso.getIdentities(user.id)
      expect(identities.map(i => i.provider)).to.include('tc')
    })
  })
})
