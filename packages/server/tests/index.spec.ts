import { createHmac } from 'node:crypto'
import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import Server from '@cordisjs/plugin-server'
import Timer from '@cordisjs/plugin-timer'
import Sso, { SsoProvider } from '@cordisjs/plugin-sso'
import Password from '@cordisjs/plugin-sso-password'
import Mail from '@cordisjs/plugin-sso-mail'
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
  lastLinkUserId: number | undefined
  getAuthUrl(redirectUri: string, state: string, link?: { userId: number }) {
    this.lastLinkUserId = link?.userId
    return `https://example.com/auth?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`
  }
  async resolve() { return null }
  async register() { return {} }
}

let portCursor = 31000

const mailbox: { email: string; code: string }[] = []

async function setup() {
  const ctx = new Context()
  await ctx.plugin(Database)
  await ctx.plugin(MemoryDriver)
  await ctx.plugin(Timer)
  await ctx.plugin(Server, { host: '127.0.0.1', port: portCursor++, maxPort: 39999 })
  await ctx.plugin(Sso)
  await ctx.plugin(Password)
  await ctx.plugin(Totp)
  await ctx.plugin(Mail, { send: async (email, code) => { mailbox.push({ email, code }) } })
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
  const res = await fetch(`${baseUrl}/sso/sessions/password`, {
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
      expect(names).to.deep.equal(['mail', 'password', 'totp'])
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

  describe('POST /sso/sessions/:provider', () => {
    it('returns 404 for unknown provider', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/sessions/nope`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(404)
      expect(await res.json()).to.deep.equal({ error: 'PROVIDER_NOT_FOUND' })
    })

    it('returns 400 RESOLVE_NOT_SUPPORTED when provider has no resolve', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(NoResolveProvider)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/sessions/no-resolve`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(400)
      expect(await res.json()).to.deep.equal({ error: 'RESOLVE_NOT_SUPPORTED' })
    })

    it('returns a session token on successful credentials', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/sessions/password`, {
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

    it('returns 401 INVALID_CREDENTIALS on bad credentials (no autoRegister)', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/sessions/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'wrong-password' }),
      })
      expect(res.status).to.equal(401)
      expect(await res.json()).to.deep.equal({ error: 'INVALID_CREDENTIALS' })
    })

    it('falls through to register + token when provider.autoRegister is true', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(AutoRegProvider)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/sessions/auto-reg`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.token).to.be.a('string')
      expect(body.userId).to.be.a('number')
    })
  })

  describe('POST /sso/users/:provider', () => {
    it('creates a user and returns a token', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/users/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'bob', password: 'longenough' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.token).to.be.a('string')
      expect(body.userId).to.be.a('number')
      const [row] = await ctx.database.get('sso.password' as any, { username: 'bob' })
      expect(row).to.exist
    })

    it('returns 404 for unknown provider', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/users/nope`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(404)
    })

    it('rolls back user + identity when provider.register throws', async () => {
      ({ ctx, baseUrl } = await setup())
      // password < minLength (8) makes the password provider throw from register.
      // Before the transaction fix this left orphan rows in sso.user + sso.identity.
      const res = await fetch(`${baseUrl}/sso/users/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'carol', password: 'short' }),
      })
      expect(res.status).to.equal(500)
      expect(await ctx.database.get('sso.user', {})).to.have.length(0)
      expect(await ctx.database.get('sso.identity', {})).to.have.length(0)
      expect(await ctx.database.get('sso.password' as any, {})).to.have.length(0)
    })

    it('rolls back when username is already taken', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const usersBefore = await ctx.database.get('sso.user', {})
      const identitiesBefore = await ctx.database.get('sso.identity', {})
      const passwordsBefore = await ctx.database.get('sso.password' as any, {})

      const res = await fetch(`${baseUrl}/sso/users/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'anotherlongone' }),
      })
      expect(res.status).to.equal(500)
      expect(await ctx.database.get('sso.user', {})).to.have.length(usersBefore.length)
      expect(await ctx.database.get('sso.identity', {})).to.have.length(identitiesBefore.length)
      expect(await ctx.database.get('sso.password' as any, {})).to.have.length(passwordsBefore.length)
    })

    it('register → GET /sso/me with the returned token works', async () => {
      ({ ctx, baseUrl } = await setup())
      const regRes = await fetch(`${baseUrl}/sso/users/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'dave', password: 'longenough' }),
      })
      expect(regRes.status).to.equal(200)
      const { token } = await regRes.json() as any
      expect(token).to.be.a('string')
      const meRes = await fetch(`${baseUrl}/sso/me`, {
        headers: { authorization: `Bearer ${token}` },
      })
      expect(meRes.status).to.equal(200)
      const me = await meRes.json() as any
      expect(me.id).to.be.a('number')
    })
  })

  describe('GET /sso/oauth-url/:provider', () => {
    it('returns 400 OAUTH_NOT_SUPPORTED for providers without getAuthUrl', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/oauth-url/password?redirect_uri=cb&state=s`)
      expect(res.status).to.equal(400)
      expect(await res.json()).to.deep.equal({ error: 'OAUTH_NOT_SUPPORTED' })
    })

    it('returns the URL produced by getAuthUrl', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(OAuthFakeProvider)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/oauth-url/oauth-fake?redirect_uri=https%3A%2F%2Fapp%2Fcb&state=xyz`)
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.url).to.include('https://example.com/auth')
      expect(body.url).to.include('state=xyz')
    })

    it('intent=link requires a session and forwards userId to getAuthUrl', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(OAuthFakeProvider)
      await sleep()

      // Without session -> 401
      const unauth = await fetch(`${baseUrl}/sso/oauth-url/oauth-fake?redirect_uri=cb&state=s&intent=link`)
      expect(unauth.status).to.equal(401)
      expect(await unauth.json()).to.deep.equal({ error: 'SESSION_REQUIRED' })

      // With session -> 200; provider sees the caller's userId
      const { user } = await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const instance = ctx.sso.getProvider('oauth-fake') as any as OAuthFakeProvider
      instance.lastLinkUserId = undefined
      const auth = await fetch(`${baseUrl}/sso/oauth-url/oauth-fake?redirect_uri=cb&state=s&intent=link`, {
        headers: { authorization: `Bearer ${token}` },
      })
      expect(auth.status).to.equal(200)
      expect(instance.lastLinkUserId).to.equal(user.id)
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

    it('POST /sso/identities/:provider links a new identity', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/identities/totp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}` },
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.identityId).to.be.a('number')
    })

    it('POST /sso/identities/:provider with credentials writes the provider row', async () => {
      ({ ctx, baseUrl } = await setup())
      const { user } = await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/identities/totp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'alice@laptop' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.identityId).to.be.a('number')
      expect(body.data?.otpauthUrl).to.include('otpauth://totp/')
      const [row] = await ctx.database.get('sso.totp' as any, { identityId: body.identityId })
      expect(row).to.exist
      expect(row.label).to.equal('alice@laptop')
      expect(await ctx.sso.getIdentities(user.id)).to.have.length(2)
    })

    it('POST /sso/identities/:provider rolls back when provider.register throws', async () => {
      ({ ctx, baseUrl } = await setup())
      const { user } = await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      // password register throws when password is too short; the newly-linked
      // identity row must not survive.
      const identitiesBefore = await ctx.sso.getIdentities(user.id)
      const res = await fetch(`${baseUrl}/sso/identities/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice2', password: 'short' }),
      })
      expect(res.status).to.equal(500)
      expect(await ctx.sso.getIdentities(user.id)).to.have.length(identitiesBefore.length)
    })

    it('POST /sso/identities/mail refuses without a verified challenge', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      // Attempting to bind a mail identity without challenge+code must fail;
      // otherwise anyone could register arbitrary emails.
      const res = await fetch(`${baseUrl}/sso/identities/mail`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'alice@example.com' }),
      })
      expect(res.status).to.equal(500)
      expect(await ctx.database.get('sso.mail' as any, {})).to.have.length(0)
    })

    it('POST /sso/identities/mail succeeds with a valid challenge+code', async () => {
      ({ ctx, baseUrl } = await setup())
      const { user } = await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      mailbox.length = 0
      const chRes = await fetch(`${baseUrl}/sso/challenge/mail`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'alice@example.com' }),
      })
      expect(chRes.status).to.equal(200)
      const { challengeId } = await chRes.json() as any
      const sent = mailbox.find(m => m.email === 'alice@example.com')!
      const res = await fetch(`${baseUrl}/sso/identities/mail`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'alice@example.com', challengeId, code: sent.code }),
      })
      expect(res.status).to.equal(200)
      expect(await ctx.sso.getIdentities(user.id)).to.have.length(2)
      const [row] = await ctx.database.get('sso.mail' as any, { email: 'alice@example.com' })
      expect(row).to.exist
    })

    it('DELETE /sso/identities/:id refuses to remove someone else\'s identity', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const { identityId: bobsId } = await registerPasswordUser(ctx, 'bob', 'longenough')
      const aliceToken = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/identities/${bobsId}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${aliceToken}` },
      })
      expect(res.status).to.equal(404)
      expect(await res.json()).to.deep.equal({ error: 'IDENTITY_NOT_FOUND' })
    })

    it('DELETE /sso/identities/:id removes one of the caller\'s identities', async () => {
      ({ ctx, baseUrl } = await setup())
      const { user } = await registerPasswordUser(ctx, 'alice', 'longenough')
      const { identityId: totpId } = await ctx.sso.link(user.id, 'totp')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/identities/${totpId}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      })
      expect(res.status).to.equal(200)
      const remaining = await ctx.sso.getIdentities(user.id)
      expect(remaining).to.have.length(1)
      expect(remaining[0].provider).to.equal('password')
    })

    it('DELETE /sso/sessions invalidates the token', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(ctx, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const logout = await fetch(`${baseUrl}/sso/sessions`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      })
      expect(logout.status).to.equal(200)
      expect(await ctx.sso.validateSession(token)).to.be.null
    })

    it('DELETE /sso/sessions is a no-op without a token', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/sessions`, { method: 'DELETE' })
      expect(res.status).to.equal(200)
      expect(await res.json()).to.deep.equal({ ok: true })
    })
  })
})

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
