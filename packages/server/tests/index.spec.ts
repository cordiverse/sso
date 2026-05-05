import { Context } from 'cordis'
import Database from '@cordisjs/plugin-database'
import MemoryDriver from '@cordisjs/plugin-database-memory'
import Server from '@cordisjs/plugin-server'
import Timer from '@cordisjs/plugin-timer'
import Sso, { CredentialsProvider, RedirectProvider, SsoProvider } from '@cordisjs/plugin-sso'
import Password from '@cordisjs/plugin-sso-password'
import Mail from '@cordisjs/plugin-sso-mail'
import Totp from '@cordisjs/plugin-sso-totp'
import { afterEach, describe, expect, it } from 'vitest'
import { name, inject, apply } from '../src'
const SsoServer = { name, inject, apply }

function sleep(ms = 0) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms))
}

class AutoRegProvider extends CredentialsProvider<any> {
  name = 'auto-reg'
  jitProvisioning = true
  async resolve() { return null }
  async writeIdentity() { /* no-op — base class still links/creates user */ }
}

class OAuthFakeProvider extends RedirectProvider {
  name = 'oauth-fake'
  jitProvisioning = true
  lastLinkUserId: number | undefined
  getAuthUrl(redirectUri: string, state: string, link?: { userId: number }) {
    this.lastLinkUserId = link?.userId
    return `https://example.com/auth?redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`
  }
}

const mailbox: { email: string; code: string }[] = []

async function setup() {
  const ctx = new Context()
  await ctx.plugin(Database)
  await ctx.plugin(MemoryDriver)
  await ctx.plugin(Timer)
  await ctx.plugin(Server, { host: '127.0.0.1', port: 0 })
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

async function registerPasswordUser(baseUrl: string, username: string, password: string) {
  const res = await fetch(`${baseUrl}/sso/sessions/password`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ intent: 'register', username, password }),
  })
  expect(res.status).to.equal(200)
  const body = await res.json() as any
  expect(body.phase).to.equal('finish')
  return { token: body.token as string, userId: body.userId as number }
}

async function loginAndGetToken(baseUrl: string, username: string, password: string) {
  const res = await fetch(`${baseUrl}/sso/sessions/password`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  expect(res.status).to.equal(200)
  const body = await res.json() as any
  expect(body.phase).to.equal('finish')
  return body.token as string
}

describe('@cordisjs/plugin-sso-server', () => {
  let ctx: Context
  let baseUrl: string

  afterEach(async () => {
    if (ctx) await teardown(ctx)
  })

  describe('GET /sso/providers', () => {
    it('returns the provider meta list with category + capability flags', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/providers`)
      expect(res.status).to.equal(200)
      const body = await res.json() as any[]
      const names = body.map(p => p.name).sort()
      expect(names).to.deep.equal(['mail', 'password', 'totp'])
      const password = body.find(p => p.name === 'password')
      expect(password).to.include({ category: 'credentials', canBePrimary: true, canStepUp: false, jitProvisioning: false })
      const mail = body.find(p => p.name === 'mail')
      expect(mail).to.include({ category: 'challenge', canStepUp: true })
      const totp = body.find(p => p.name === 'totp')
      expect(totp).to.include({ category: 'challenge', canBePrimary: false, canStepUp: true })
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

  describe('POST /sso/sessions/:provider (login/register)', () => {
    it('returns 404 for unknown provider', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/sessions/nope`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(404)
      expect(await res.json()).to.deep.equal({ error: 'PROVIDER_NOT_FOUND' })
    })

    it('intent=register creates a user atomically and returns phase:finish', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/sessions/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ intent: 'register', username: 'bob', password: 'longenough' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.phase).to.equal('finish')
      expect(body.token).to.be.a('string')
      expect(body.userId).to.be.a('number')
      expect(body.created).to.equal(true)
      const [user] = await ctx.database.get('sso.user', { name: 'bob' })
      expect(user).to.exist
      const [identity] = await ctx.database.get('sso.identity', { userId: user!.id, provider: 'password' })
      expect(identity).to.exist
      const [row] = await ctx.database.get('sso.password' as any, { identityId: identity!.id })
      expect(row).to.exist
    })

    it('intent=register rolls back when writeIdentity throws (password too short)', async () => {
      ({ ctx, baseUrl } = await setup())
      const res = await fetch(`${baseUrl}/sso/sessions/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ intent: 'register', username: 'carol', password: 'short' }),
      })
      expect(res.status).to.equal(400)
      expect(await ctx.database.get('sso.user', {})).to.have.length(0)
      expect(await ctx.database.get('sso.identity', {})).to.have.length(0)
      expect(await ctx.database.get('sso.password' as any, {})).to.have.length(0)
    })

    it('intent=register rolls back when username already taken', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const usersBefore = (await ctx.database.get('sso.user', {})).length
      const res = await fetch(`${baseUrl}/sso/sessions/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ intent: 'register', username: 'alice', password: 'anotherlongone' }),
      })
      expect(res.status).to.equal(409)
      expect(await ctx.database.get('sso.user', {})).to.have.length(usersBefore)
    })

    it('login with correct credentials returns a token', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/sessions/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'longenough' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.phase).to.equal('finish')
      expect(body.token).to.be.a('string')
      const validated = await ctx.sso.validateSession(body.token)
      expect(validated).to.exist
    })

    it('login wrong password → ACCOUNT_NOT_FOUND (jitProvisioning=false)', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/sessions/password`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'wrong-password' }),
      })
      expect(res.status).to.equal(401)
      expect(await res.json()).to.deep.equal({ error: 'ACCOUNT_NOT_FOUND' })
    })

    it('jitProvisioning=true provider falls through to register on login miss', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(AutoRegProvider)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/sessions/auto-reg`, { method: 'POST', body: '{}' })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.phase).to.equal('finish')
      expect(body.token).to.be.a('string')
      expect(body.created).to.equal(true)
    })
  })

  describe('POST /sso/sessions/mail (challenge → finish)', () => {
    it('unknown email jitProvisionings in one flow', async () => {
      ({ ctx, baseUrl } = await setup())
      mailbox.length = 0
      const step1 = await fetch(`${baseUrl}/sso/sessions/mail`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'fresh@example.com' }),
      })
      expect(step1.status).to.equal(200)
      const body1 = await step1.json() as any
      expect(body1.phase).to.equal('challenge')
      expect(body1.challengeId).to.be.a('string')
      expect(body1.response.shape).to.equal('code')
      const sent = mailbox[0]
      const step2 = await fetch(`${baseUrl}/sso/sessions/mail`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: body1.challengeId, code: sent.code }),
      })
      expect(step2.status).to.equal(200)
      const body2 = await step2.json() as any
      expect(body2.phase).to.equal('finish')
      expect(body2.token).to.be.a('string')
      expect(await ctx.database.get('sso.mail' as any, { email: 'fresh@example.com' })).to.have.length(1)
    })

    it('wrong code → VERIFICATION_FAILED (pending not consumed)', async () => {
      ({ ctx, baseUrl } = await setup())
      mailbox.length = 0
      const step1 = await fetch(`${baseUrl}/sso/sessions/mail`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'retry@example.com' }),
      })
      const body1 = await step1.json() as any
      const bad = await fetch(`${baseUrl}/sso/sessions/mail`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: body1.challengeId, code: 'wrong!' }),
      })
      expect(bad.status).to.equal(401)
      expect(await bad.json()).to.deep.equal({ error: 'VERIFICATION_FAILED' })
      // challenge still valid (not consumeOnFailure) — correct code still works
      const good = await fetch(`${baseUrl}/sso/sessions/mail`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: body1.challengeId, code: mailbox[0].code }),
      })
      expect(good.status).to.equal(200)
    })

    it('replayed challengeId → CHALLENGE_EXPIRED', async () => {
      ({ ctx, baseUrl } = await setup())
      mailbox.length = 0
      const step1 = await fetch(`${baseUrl}/sso/sessions/mail`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'once@example.com' }),
      })
      const body1 = await step1.json() as any
      const body = JSON.stringify({ challengeId: body1.challengeId, code: mailbox[0].code })
      const first = await fetch(`${baseUrl}/sso/sessions/mail`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body,
      })
      expect(first.status).to.equal(200)
      const second = await fetch(`${baseUrl}/sso/sessions/mail`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body,
      })
      expect(second.status).to.equal(401)
      expect(await second.json()).to.deep.equal({ error: 'CHALLENGE_EXPIRED' })
    })
  })

  describe('POST /sso/sessions/:provider for redirect providers', () => {
    it('returns phase:redirect with a URL', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(OAuthFakeProvider)
      await sleep()
      const res = await fetch(`${baseUrl}/sso/sessions/oauth-fake`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uri: 'https://app/cb', state: 'xyz' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.phase).to.equal('redirect')
      expect(body.url).to.include('https://example.com/auth')
      expect(body.url).to.include('state=xyz')
    })

    it('bind kind threads userId through getAuthUrl', async () => {
      ({ ctx, baseUrl } = await setup())
      await ctx.plugin(OAuthFakeProvider)
      await sleep()
      await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const instance = ctx.sso.getProvider('oauth-fake') as OAuthFakeProvider
      instance.lastLinkUserId = undefined
      const res = await fetch(`${baseUrl}/sso/identities/oauth-fake`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uri: 'cb', state: 's' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.phase).to.equal('redirect')
      expect(instance.lastLinkUserId).to.be.a('number')
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
      await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/identities`, {
        headers: { authorization: `Bearer ${token}` },
      })
      expect(res.status).to.equal(200)
      const list = await res.json() as any[]
      expect(list).to.have.length(1)
      expect(list[0].provider).to.equal('password')
    })

    it('POST /sso/identities/totp returns phase:challenge (no sso.totp row yet)', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const res = await fetch(`${baseUrl}/sso/identities/totp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'alice@laptop' }),
      })
      expect(res.status).to.equal(200)
      const body = await res.json() as any
      expect(body.phase).to.equal('challenge')
      expect(body.data?.otpauthUrl).to.include('otpauth://totp/')
      expect(await ctx.database.get('sso.totp' as any, {})).to.have.length(0)
    })

    it('POST /sso/identities/totp full bind creates identity + sso.totp atomically', async () => {
      ({ ctx, baseUrl } = await setup())
      const { userId } = await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const start = await fetch(`${baseUrl}/sso/identities/totp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ label: 'alice@laptop' }),
      })
      const startBody = await start.json() as any
      // compute TOTP code from secret for current time
      const { createHmac } = await import('node:crypto')
      const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
      function decode(s: string): Buffer {
        const bytes: number[] = []
        let bits = 0, value = 0
        for (const ch of s.toUpperCase()) {
          const idx = BASE32.indexOf(ch)
          if (idx === -1) continue
          value = (value << 5) | idx; bits += 5
          if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8 }
        }
        return Buffer.from(bytes)
      }
      const sec = decode(startBody.data.secret)
      const counter = Math.floor(Math.floor(Date.now() / 1000) / 30)
      const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter))
      const hmac = createHmac('sha1', sec).update(buf).digest()
      const off = hmac[hmac.length - 1] & 0x0f
      const codeNum = (
        ((hmac[off] & 0x7f) << 24) | ((hmac[off + 1] & 0xff) << 16)
        | ((hmac[off + 2] & 0xff) << 8) | (hmac[off + 3] & 0xff)
      ) % 1000000
      const code = String(codeNum).padStart(6, '0')

      const finish = await fetch(`${baseUrl}/sso/identities/totp`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: startBody.challengeId, code }),
      })
      expect(finish.status).to.equal(200)
      const finishBody = await finish.json() as any
      expect(finishBody.phase).to.equal('finish')
      expect(await ctx.sso.getIdentities(userId)).to.have.length(2)
      expect(await ctx.database.get('sso.totp' as any, {})).to.have.length(1)
    })

    it('POST /sso/identities/:provider rolls back when writeIdentity throws', async () => {
      ({ ctx, baseUrl } = await setup())
      const { userId } = await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const identitiesBefore = await ctx.sso.getIdentities(userId)
      const res = await fetch(`${baseUrl}/sso/identities/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'alice2', password: 'short' }),
      })
      expect(res.status).to.equal(400)
      expect(await ctx.sso.getIdentities(userId)).to.have.length(identitiesBefore.length)
    })

    it('POST /sso/identities/mail requires a valid challenge', async () => {
      ({ ctx, baseUrl } = await setup())
      const { userId } = await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      mailbox.length = 0
      const step1 = await fetch(`${baseUrl}/sso/identities/mail`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'alice@example.com' }),
      })
      expect(step1.status).to.equal(200)
      const body1 = await step1.json() as any
      expect(body1.phase).to.equal('challenge')
      const step2 = await fetch(`${baseUrl}/sso/identities/mail`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ challengeId: body1.challengeId, code: mailbox[0].code }),
      })
      expect(step2.status).to.equal(200)
      const body2 = await step2.json() as any
      expect(body2.phase).to.equal('finish')
      expect(await ctx.sso.getIdentities(userId)).to.have.length(2)
    })

    it('DELETE /sso/identities/:id refuses someone else\'s identity', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const { userId: bobId } = await registerPasswordUser(baseUrl, 'bob', 'longenough')
      const aliceToken = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const [bobIdentity] = await ctx.database.get('sso.identity', { userId: bobId })
      const res = await fetch(`${baseUrl}/sso/identities/${bobIdentity!.id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${aliceToken}` },
      })
      expect(res.status).to.equal(404)
      expect(await res.json()).to.deep.equal({ error: 'IDENTITY_NOT_FOUND' })
    })

    it('DELETE /sso/identities/:id cascades provider rows + sessions', async () => {
      ({ ctx, baseUrl } = await setup())
      const { userId } = await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const [pwdIdentity] = await ctx.database.get('sso.identity', { userId })
      await ctx.sso.link(userId, 'mail')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      expect(await ctx.database.get('sso.password' as any, { identityId: pwdIdentity!.id })).to.have.length(1)
      expect((await ctx.database.get('sso.session' as any, { identityId: pwdIdentity!.id })).length).to.be.greaterThan(0)
      const res = await fetch(`${baseUrl}/sso/identities/${pwdIdentity!.id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      })
      expect(res.status).to.equal(200)
      expect(await ctx.database.get('sso.identity', { id: pwdIdentity!.id })).to.have.length(0)
      expect(await ctx.database.get('sso.password' as any, { identityId: pwdIdentity!.id })).to.have.length(0)
      expect(await ctx.database.get('sso.session' as any, { identityId: pwdIdentity!.id })).to.have.length(0)
      expect(await ctx.sso.validateSession(token)).to.be.null
    })

    it('DELETE /sso/sessions invalidates the token', async () => {
      ({ ctx, baseUrl } = await setup())
      await registerPasswordUser(baseUrl, 'alice', 'longenough')
      const token = await loginAndGetToken(baseUrl, 'alice', 'longenough')
      const logout = await fetch(`${baseUrl}/sso/sessions`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${token}` },
      })
      expect(logout.status).to.equal(200)
      expect(await ctx.sso.validateSession(token)).to.be.null
    })
  })
})
