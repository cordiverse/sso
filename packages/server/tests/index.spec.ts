import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import Server from '@cordisjs/plugin-server'
import Timer from '@cordisjs/plugin-timer'
import Sso, { SsoProvider } from '@cordisjs/plugin-sso'
import Password from '@cordisjs/plugin-sso-password'
import Totp from '@cordisjs/plugin-sso-totp'
import { expect } from 'chai'
import { name, inject, apply } from '../src'
const SsoServer = { name, inject, apply }

function sleep(ms = 0) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms))
}

class NoResolveProvider extends SsoProvider {
  name = 'no-resolve'
  interactive = true
  autoRegister = false
}

class AutoRegProvider extends SsoProvider {
  name = 'auto-reg'
  interactive = true
  autoRegister = true
  async resolve() { return null }
  async register() { return {} }
}

class OAuthFakeProvider extends SsoProvider {
  name = 'oauth-fake'
  interactive = true
  autoRegister = true
  getAuthUrl(redirectUri: string, state: string) {
    return `https://example.com/auth?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`
  }
  async resolve() { return null }
  async register() { return {} }
}

let portCursor = 31000

async function setup() {
  const ctx = new Context()
  await ctx.plugin(Database)
  await ctx.plugin(MemoryDriver)
  await ctx.plugin(Timer)
  await ctx.plugin(Server, { host: '127.0.0.1', port: portCursor++, maxPort: 39999 })
  await ctx.plugin(Sso)
  await ctx.plugin(Password)
  await ctx.plugin(Totp)
  await ctx.plugin(SsoServer)
  await sleep()
  return { ctx, baseUrl: ctx.server.baseUrl }
}

async function teardown(ctx: Context) {
  ctx.registry.delete(Server)
  await sleep()
}

async function registerPasswordUser(ctx: Context, username: string, password: string) {
  const { user, identityId } = await ctx.sso.createUser('password')
  await ctx.sso.getProvider('password')!.register!({ identityId, username, password })
  return { user, identityId }
}

async function loginAndGetToken(baseUrl: string, username: string, password: string) {
  const res = await fetch(`${baseUrl}/sso/auth/password`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  expect(res.status).to.equal(200)
  const body = await res.json() as any
  return body.token as string
}

describe('@cordisjs/plugin-sso-server', () => {
  let ctx: Context
  let baseUrl: string

  afterEach(async () => {
    if (ctx) await teardown(ctx)
  })

  describe('GET /sso/providers', () => {
    it('returns the provider meta list', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/providers`)
      expect(res.status).to.equal(200)
      const body = await res.json() as any[]
      const names = body.map(p => p.name).sort()
      expect(names).to.deep.equal(['password', 'totp'])
      expect(body.find(p => p.name === 'password')).to.include({
        interactive: true, autoRegister: false,
      })
    })

    it('reflects waterfall augmentation from listeners', async () => {
      ({ ctx, baseUrl } = await setup())
      function tagger(c: Context) {
        c.on('sso/provider-meta', async (_, next) => {
          const list = await next()
          return list.map(m => ({ ...m, tag: 'X' } as any))
        })
      }
      await ctx.plugin(tagger)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/providers`)
      const body = await res.json() as any[]
      expect(body.every(m => m.tag === 'X')).to.equal(true)
    })
  })

  describe('POST /sso/auth/:provider', () => {
    it('returns 404 for unknown provider', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/auth/nope`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(404)
      expect(await res.json()).to.deep.equal({ error: 'PROVIDER_NOT_FOUND' })
    })

    it('returns 400 RESOLVE_NOT_SUPPORTED when provider has no resolve', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(NoResolveProvider)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/auth/no-resolve`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(400)
      expect(await res.json()).to.deep.equal({ error: 'RESOLVE_NOT_SUPPORTED' })
    })

    it('returns a session token on successful credentials', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/auth/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'longenough' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.token).to.be.a('string')
      const validated = await ctx.sso.validateSession(body.token)
      expect(validated).to.exist
    })

    it('returns 401 ACCOUNT_NOT_FOUND on bad credentials (no autoRegister)', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/auth/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'wrong-password' }),
      })
      expect(res.status).to.equal(401)
      expect(await res.json()).to.deep.equal({ error: 'ACCOUNT_NOT_FOUND' })
    })

    it('falls through to register + token when provider.autoRegister is true', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(AutoRegProvider)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/auth/auto-reg`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.token).to.be.a('string')
      expect(body.userId).to.be.a('number')
    })
  })

  describe('POST /sso/register/:provider', () => {
    it('creates a user and returns a token', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/register/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'bob', password: 'longenough' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.token).to.be.a('string')
      expect(body.userId).to.be.a('number')
      const [row] = await ctx.database.get('sso_password' as any, { username: 'bob' })
      expect(row).to.exist
    })

    it('returns 404 for unknown provider', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/register/nope`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(404)
    })
  })

  describe('GET /sso/auth/:provider (auth url)', () => {
    it('returns 400 OAUTH_NOT_SUPPORTED for providers without getAuthUrl', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/auth/password?redirect_uri=cb&state=s`)
      expect(res.status).to.equal(400)
      expect(await res.json()).to.deep.equal({ error: 'OAUTH_NOT_SUPPORTED' })
    })

    it('returns the URL produced by getAuthUrl', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(OAuthFakeProvider)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/auth/oauth-fake?redirect_uri=https%3A%2F%2Fapp%2Fcb&state=xyz`)
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.url).to.include('https://example.com/auth')
      expect(body.url).to.include('state=xyz')
    })
  })

  describe('challenge / verify', () => {
    it('challenge → verify (totp) end to end', async () => {
      ({ ctx, baseUrl } = await setup())
      const { identityId } = await ctx.sso.createUser('totp')
      const provider = ctx.sso.getProvider('totp')!
      // pre-register so we have a secret in the table
      const { data } = await provider.register!({ identityId })
      const secret: string = data!.secret
      // compute current code via the same TOTP algorithm
      const code = await currentTotpCode(secret)

      const verifyRes = await fetch(`${baseUrl}/sso/verify/totp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: String(identityId), response: code }),
      })
      expect(verifyRes.status).to.equal(200)
      expect(await verifyRes.json()).to.deep.equal({ ok: true })
    })

    it('verify with a wrong code returns 401 VERIFICATION_FAILED', async () => {
      ({ ctx, baseUrl } = await setup())
      const { identityId } = await ctx.sso.createUser('totp')
      await ctx.sso.getProvider('totp')!.register!({ identityId })
      const res = await fetch(`${baseUrl}/sso/verify/totp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: String(identityId), response: '000000' }),
      })
      expect(res.status).to.equal(401)
      expect(await res.json()).to.deep.equal({ error: 'VERIFICATION_FAILED' })
    })

    it('returns 400 CHALLENGE_NOT_SUPPORTED when provider has no challenge', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/challenge/password`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(400)
      expect(await res.json()).to.deep.equal({ error: 'CHALLENGE_NOT_SUPPORTED' })
    })
  })

  describe('session-protected routes', () => {
    it('GET /sso/identities returns 401 without a token', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/identities`)
      expect(res.status).to.equal(401)
      expect(await res.json()).to.deep.equal({ error: 'SESSION_REQUIRED' })
    })

    it('GET /sso/identities returns the user\'s identities with a bearer', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/identities`, {
        headers: { authorization: `Bearer ${token}` },
      })
      expect(res.status).to.equal(200)
      const list = await res.json() as any[]
      expect(list).to.have.length(1)
      expect(list[0].provider).to.equal('password')
    })

    it('POST /sso/link/:provider links a new identity', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/link/totp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.identityId).to.be.a('number')
    })

    it('POST /sso/unlink/:id refuses to remove someone else\'s identity', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const { identityId: bobsId } = await registerPasswordUser(ctx, 'bob', 'longenough')
      const aliceToken = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/unlink/${bobsId}`, {
        method: 'POST',
        headers: { authorization: `Bearer ${aliceToken}` },
      })
      expect(res.status).to.equal(404)
      expect(await res.json()).to.deep.equal({ error: 'IDENTITY_NOT_FOUND' })
    })

    it('POST /sso/unlink/:id removes one of the caller\'s identities', async () => {
      ({ ctx, baseUrl } = await setup())
      const { user } = await registerPasswordUser(ctx, 'alice', 'longenough')
      const { identityId: totpId } = await ctx.sso.link(user.id, 'totp')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/unlink/${totpId}`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
      })
      expect(res.status).to.equal(200)
      const remaining = await ctx.sso.getIdentities(user.id)
      expect(remaining).to.have.length(1)
      expect(remaining[0].provider).to.equal('password')
    })

    it('POST /sso/logout invalidates the token', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const logout = await fetch(`${baseUrl}/sso/logout`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
      })
      expect(logout.status).to.equal(200)
      expect(await ctx.sso.validateSession(token)).to.be.null
    })

    it('POST /sso/logout is a no-op without a token', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/logout`, { method: 'POST' })
      expect(res.status).to.equal(200)
      expect(await res.json()).to.deep.equal({ ok: true })
    })
  })
})

// ---- TOTP code helper (mirrors algorithm in @cordisjs/plugin-sso-totp) ----
import { createHmac } from 'node:crypto'

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Decode(encoded: string): Buffer {
  const bytes: number[] = []
  let bits = 0, value = 0
  for (const ch of encoded.toUpperCase()) {
    const idx = BASE32_CHARS.indexOf(ch)
    if (idx === -1) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8 }
  }
  return Buffer.from(bytes)
}

async function currentTotpCode(secret: string, period = 30, digits = 6, algorithm = 'sha1'): Promise<string> {
  const sec = base32Decode(secret)
  const counter = Math.floor(Math.floor(Date.now() / 1000) / period)
  const buf = Buffer.alloc(8)
  buf.writeBigUInt64BE(BigInt(counter))
  const hmac = createHmac(algorithm, sec).update(buf).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % (10 ** digits)
  return String(code).padStart(digits, '0')
}
