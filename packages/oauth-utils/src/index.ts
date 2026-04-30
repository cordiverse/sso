import { Context } from 'cordis'
import { createHash, randomBytes } from 'node:crypto'
import type {} from '@cordisjs/plugin-timer'

/**
 * Build the response for an OAuth callback handler.
 *
 * - If `redirectUrl` is provided, return a 302 redirect with the token in the
 *   URL fragment (`#token=...`) on success, or `?error=...` on failure. The
 *   fragment is preferred so the token never appears in server access logs and
 *   is not sent in `Referer` headers.
 * - If `redirectUrl` is omitted, fall back to a JSON response — useful for
 *   SPAs / native flows that drive the OAuth dance themselves.
 */
export function callbackResponse(
  result: { token?: string; error?: string; status?: number },
  redirectUrl?: string,
): Response {
  if (!redirectUrl) {
    if (result.token) return Response.json({ token: result.token })
    return Response.json({ error: result.error ?? 'UNKNOWN' }, { status: result.status ?? 401 })
  }
  const url = new URL(redirectUrl)
  if (result.token) {
    url.hash = `token=${encodeURIComponent(result.token)}`
  } else {
    url.searchParams.set('error', result.error ?? 'UNKNOWN')
  }
  return new Response(null, { status: 302, headers: { Location: url.toString() } })
}

export interface PkceEntry {
  /** The PKCE code_verifier; sent to the token endpoint. */
  codeVerifier: string
  /** The redirect_uri used in the authorize request; some providers require it during token exchange. */
  redirectUri: string
  /** Application-defined extra payload (e.g. caller-supplied state, post-login `next` URL). */
  payload?: any
  /** Wall-clock expiry, in epoch ms. */
  expiresAt: number
}

export interface PkceStoreOptions {
  /** TTL for an issued challenge, ms. Defaults to 10 minutes. */
  ttl?: number
  /** Hash algorithm for `code_challenge`. Only `'S256'` is meaningful in OAuth 2.1; `'plain'` is provided for compatibility. */
  challengeMethod?: 'S256' | 'plain'
}

export interface PkceIssueResult {
  state: string
  codeVerifier: string
  codeChallenge: string
  codeChallengeMethod: 'S256' | 'plain'
}

/**
 * In-memory store for PKCE + state pairs.
 *
 * `issue()` mints a fresh `state` (also serves as CSRF token) and a PKCE
 * `codeVerifier`/`codeChallenge`. The verifier is held server-side until the
 * matching callback comes back; `consume(state)` returns and removes it.
 *
 * Each entry self-disposes after `ttl` via `ctx.timeout(...)`, so plugin
 * teardown clears any in-flight challenges automatically.
 */
export class PkceStore {
  private store = new Map<string, PkceEntry>()
  private ttl: number
  private challengeMethod: 'S256' | 'plain'

  constructor(public ctx: Context, options: PkceStoreOptions = {}) {
    this.ttl = options.ttl ?? 10 * 60 * 1000
    this.challengeMethod = options.challengeMethod ?? 'S256'
  }

  /**
   * Generate a new PKCE pair + state and remember the verifier for later.
   *
   * @param redirectUri  The redirect_uri to be quoted on the authorize URL.
   * @param payload      Arbitrary data to remember alongside the challenge.
   */
  issue(redirectUri: string, payload?: any): PkceIssueResult {
    const state = randomBytes(16).toString('base64url')
    return this.register(state, redirectUri, payload)
  }

  /**
   * Generate a PKCE pair + remember it under a caller-chosen `state`.
   * Useful when the SSO entry-point hands you a state you have to round-trip.
   * Prefer `issue()` if you don't need a specific state.
   */
  register(state: string, redirectUri: string, payload?: any): PkceIssueResult {
    const codeVerifier = randomBytes(32).toString('base64url')
    const codeChallenge = this.challengeMethod === 'S256'
      ? createHash('sha256').update(codeVerifier).digest('base64url')
      : codeVerifier
    this.store.set(state, {
      codeVerifier,
      redirectUri,
      payload,
      expiresAt: Date.now() + this.ttl,
    })
    this.ctx.timeout(() => this.store.delete(state), this.ttl)
    return { state, codeVerifier, codeChallenge, codeChallengeMethod: this.challengeMethod }
  }

  /**
   * Look up and remove a previously issued challenge. Returns `undefined` if
   * the state is unknown or already expired.
   */
  consume(state: string): PkceEntry | undefined {
    const entry = this.store.get(state)
    if (!entry) return undefined
    this.store.delete(state)
    if (Date.now() > entry.expiresAt) return undefined
    return entry
  }

  /** Inspect the in-flight count (mainly for tests / debugging). */
  get size(): number {
    return this.store.size
  }
}
