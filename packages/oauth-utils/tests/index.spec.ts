import { Context } from 'cordis'
import Timer from '@cordisjs/plugin-timer'
import { expect } from 'chai'
import { install, InstalledClock } from '@sinonjs/fake-timers'
import { createHash } from 'node:crypto'
import { callbackResponse, PkceStore } from '../src'

function sleep(ms = 0) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms))
}

describe('@cordisjs/oauth-utils', () => {
  describe('callbackResponse', () => {
    it('without redirectUrl: success → JSON {token}', async () => {
      const res = callbackResponse({ token: 'abc' })
      expect(res.status).to.equal(200)
      expect(await res.json()).to.deep.equal({ token: 'abc' })
    })

    it('without redirectUrl: error → JSON {error} with status', async () => {
      const res = callbackResponse({ error: 'NOPE', status: 401 })
      expect(res.status).to.equal(401)
      expect(await res.json()).to.deep.equal({ error: 'NOPE' })
    })

    it('without redirectUrl: defaults missing error to UNKNOWN / 401', async () => {
      const res = callbackResponse({})
      expect(res.status).to.equal(401)
      expect(await res.json()).to.deep.equal({ error: 'UNKNOWN' })
    })

    it('with redirectUrl: success → 302 with token in fragment', async () => {
      const res = callbackResponse({ token: 'abc' }, 'https://app.example.com/welcome')
      expect(res.status).to.equal(302)
      expect(res.headers.get('location')).to.equal('https://app.example.com/welcome#token=abc')
    })

    it('with redirectUrl: error → 302 with error query param', async () => {
      const res = callbackResponse({ error: 'ACCOUNT_NOT_FOUND' }, 'https://app.example.com/welcome')
      expect(res.status).to.equal(302)
      const location = res.headers.get('location')!
      expect(location).to.include('https://app.example.com/welcome?')
      expect(location).to.include('error=ACCOUNT_NOT_FOUND')
    })

    it('with redirectUrl preserving existing query params', async () => {
      const res = callbackResponse({ token: 't' }, 'https://app.example.com/cb?return=/home')
      const location = res.headers.get('location')!
      expect(location).to.include('return=/home')
      expect(location).to.include('#token=t')
    })

    it('url-encodes special chars in token fragment', async () => {
      const res = callbackResponse({ token: 'a/b+c=' }, 'https://app.example.com')
      expect(res.headers.get('location')).to.match(/#token=a%2Fb%2Bc%3D$/)
    })
  })

  describe('PkceStore', () => {
    let ctx: Context
    let clock: InstalledClock

    beforeEach(async () => {
      clock = install({ now: 1700000000000 })
      ctx = new Context()
      await ctx.plugin(Timer)
    })

    afterEach(() => {
      clock.uninstall()
    })

    it('issue produces a state, code_verifier, and matching S256 challenge', async () => {
      const store = new PkceStore(ctx)
      const issued = store.issue('https://app/callback')
      expect(issued.state).to.be.a('string').with.length.greaterThan(10)
      expect(issued.codeVerifier).to.be.a('string').with.length.greaterThan(20)
      expect(issued.codeChallengeMethod).to.equal('S256')
      const recomputed = createHash('sha256').update(issued.codeVerifier).digest('base64url')
      expect(issued.codeChallenge).to.equal(recomputed)
      expect(store.size).to.equal(1)
    })

    it('issue uses plain method when configured', async () => {
      const store = new PkceStore(ctx, { challengeMethod: 'plain' })
      const issued = store.issue('https://app/callback')
      expect(issued.codeChallengeMethod).to.equal('plain')
      expect(issued.codeChallenge).to.equal(issued.codeVerifier)
    })

    it('consume returns and removes a known state', async () => {
      const store = new PkceStore(ctx)
      const { state, codeVerifier } = store.issue('https://app/callback', { foo: 'bar' })
      const entry = store.consume(state)
      expect(entry).to.exist
      expect(entry!.codeVerifier).to.equal(codeVerifier)
      expect(entry!.redirectUri).to.equal('https://app/callback')
      expect(entry!.payload).to.deep.equal({ foo: 'bar' })
      expect(store.size).to.equal(0)
    })

    it('consume returns undefined for unknown state', async () => {
      const store = new PkceStore(ctx)
      expect(store.consume('not-issued')).to.be.undefined
    })

    it('consume returns undefined and removes after TTL expiry', async () => {
      const store = new PkceStore(ctx, { ttl: 1000 })
      const { state } = store.issue('https://app/callback')
      clock.tick(1500)
      // ctx.timeout fires the cleanup; even if it didn't, consume() rejects expired
      expect(store.consume(state)).to.be.undefined
      expect(store.size).to.equal(0)
    })

    it('issued states are unique across calls', async () => {
      const store = new PkceStore(ctx)
      const states = new Set<string>()
      for (let i = 0; i < 50; i++) states.add(store.issue('https://app/callback').state)
      expect(states.size).to.equal(50)
    })
  })
})
