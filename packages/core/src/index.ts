import { Context, Inject, Service } from 'cordis'
import type { Awaitable } from 'cosmokit'
import type { Database } from '@cordisjs/plugin-database'
import { randomUUID } from 'node:crypto'

declare module 'cordis' {
  interface Context {
    sso: Sso
  }

  interface Events {
    'sso/auth'(event: Sso.AuthEvent): void
    'sso/provider-meta'(metas: Sso.ProviderMeta[], next: () => Awaitable<Sso.ProviderMeta[]>): Awaitable<Sso.ProviderMeta[]>
  }
}

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.user': User
    'sso.identity': Identity
    'sso.session': Session
  }
}

@Inject('sso')
@Inject('database')
export abstract class SsoProvider {
  abstract name: string
  abstract type: Sso.ProviderType
  abstract interactive: boolean
  abstract autoRegister: boolean

  constructor(public ctx: Context) {}

  * [Service.init]() {
    yield this.ctx.sso.register(this)
  }

  resolve?(credentials: any): Promise<{ identityId: number; data?: any } | null>
  register?(credentials: any, db?: Database): Promise<{ data?: any } | void>
  // Called by Sso.unlink() before the sso.identity row is deleted. Each
  // provider is responsible for cleaning up its own sso.<name> table so the
  // foreign key constraint doesn't block the identity delete. Called inside
  // the same transaction as the identity+session cleanup, so throwing here
  // rolls back the whole unlink.
  unlink?(identityId: number, db?: Database): Promise<void>
  // Map a human-typed login identifier (username / email / phone) to the
  // owning userId. Optional — only providers whose identities are keyed by
  // something a user would type (password, mail, sms) implement this.
  // Used by webauthn's identifier-first challenge path to narrow
  // allowCredentials to one user's passkeys; never consulted as a security
  // gate, so returning null when the identifier isn't recognised is fine.
  resolveUser?(identifier: string): Promise<number | null>
  getAuthUrl?(redirectUri: string, state: string, link?: { userId: number }): string
  challenge?(target: any): Promise<{ challengeId: string }>
  verify?(challengeId: string, response: string): Promise<boolean>
  // Challenge-based login finish step. Distinct from verify() because the
  // session endpoint needs the identityId to mint a token, not just a bool.
  // Currently only the webauthn provider implements this.
  authenticate?(challengeId: string, response: string): Promise<{ identityId: number } | null>
}

export interface User {
  id: number
  name?: string
  display?: string
  createdAt: Date
  updatedAt: Date
}

export interface Identity {
  id: number
  userId: number
  provider: string
  createdAt: Date
}

export interface Session {
  token: string
  userId: number
  identityId: number
  createdAt: Date
  expiresAt: Date
}

export namespace Sso {
  export interface Config {
    sessionMaxAge?: number
  }

  export interface AuthEvent {
    provider: string
    credentials: any
    request?: any
  }

  // Provider protocol shape — determines the client-side flow. Deliberately
  // NOT indexed by provider name; adding a new provider should only require
  // picking the right `type`, never editing client-side name tables.
  //
  // - 'credentials' — single POST with {…credentials}. password.
  // - 'challenge'   — two-step: POST /sso/challenge/:provider to get a
  //                   challengeId + a code delivered out-of-band (email/sms),
  //                   then POST /sso/sessions (or /users or /identities)
  //                   with {…credentials, challengeId, code}.
  // - 'redirect'    — browser redirect to a third-party IdP, callback-driven.
  //                   oauth / qq / wechat / twitter / apple.
  // - 'totp'        — bind: POST /sso/identities returns {data: {otpauthUrl}}
  //                   for QR rendering, then POST /sso/verify flips verified.
  //                   Login goes through future 2FA step-up, not a primary
  //                   session endpoint.
  // - 'webauthn'    — bind: POST /sso/challenge returns navigator-options,
  //                   browser ceremony signs, POST /sso/verify writes the
  //                   credential. Login path is the same challenge/finish
  //                   shape (TODO).
  export type ProviderType =
    | 'credentials'
    | 'challenge'
    | 'redirect'
    | 'totp'
    | 'webauthn'

  export interface ProviderMeta {
    name: string
    type: ProviderType
    interactive: boolean
    autoRegister: boolean
  }
}

@Inject('database')
export class Sso extends Service {
  private _providers = new Map<string, SsoProvider>()

  constructor(ctx: Context, public config: Sso.Config = {}) {
    super(ctx, 'sso')

    ctx.database.extend('sso.user', {
      id: 'unsigned(8)',
      // name is the globally unique, user-facing login identifier ("@alice"
      // style). Providers that expose a typed-identifier login (password's
      // "username", mail's "email", sms's "phone") may also be used as
      // hints, but name is THE canonical account-level identifier — it
      // survives provider unlinks and is what webauthn / future identifier-
      // first flows narrow credentials by. Nullable to allow OAuth-only
      // accounts that never picked a handle; SQL allows multiple NULLs
      // under a unique constraint.
      name: 'string(255)',
      // display is the human-readable label shown on profile pages, in
      // OIDC `name`, and in OS passkey managers (via webauthn's
      // userDisplayName). Not unique — two people can both be "Alice".
      // Populated by the registering provider with a sensible initial
      // guess (username for password, email local-part for mail, nickname
      // for OAuth, etc.), and editable by the user afterwards.
      display: 'string(255)',
      createdAt: 'timestamp',
      updatedAt: 'timestamp',
    }, { autoInc: true, unique: [['name']] })

    ctx.database.extend('sso.identity', {
      id: 'unsigned(8)',
      userId: 'unsigned(8)',
      provider: 'string(255)',
      createdAt: 'timestamp',
    }, {
      autoInc: true,
      foreign: { userId: ['sso.user', 'id'] },
    })

    ctx.database.extend('sso.session', {
      token: 'string(255)',
      userId: 'unsigned(8)',
      identityId: 'unsigned(8)',
      createdAt: 'timestamp',
      expiresAt: 'timestamp',
    }, {
      primary: 'token',
      foreign: {
        userId: ['sso.user', 'id'],
        identityId: ['sso.identity', 'id'],
      },
    })
  }

  register(provider: SsoProvider): () => void {
    if (this._providers.has(provider.name)) {
      throw new Error(`SSO provider "${provider.name}" already registered`)
    }
    this._providers.set(provider.name, provider)
    return () => {
      this._providers.delete(provider.name)
    }
  }

  getProviders(): SsoProvider[] {
    return [...this._providers.values()]
  }

  getProvider(name: string): SsoProvider | undefined {
    return this._providers.get(name)
  }

  async getProviderMetas(): Promise<Sso.ProviderMeta[]> {
    const base: Sso.ProviderMeta[] = this.getProviders().map((p) => ({
      name: p.name,
      type: p.type,
      interactive: p.interactive,
      autoRegister: p.autoRegister,
    }))
    return this.ctx.waterfall('sso/provider-meta', base, () => base)
  }

  async createUser(provider: string, db: Database = this.ctx.database, opts: { display?: string } = {}): Promise<{ user: User; identityId: number }> {
    const now = new Date()
    const user = await db.create('sso.user', {
      display: opts.display,
      createdAt: now,
      updatedAt: now,
    })
    const identity = await db.create('sso.identity', {
      userId: user.id,
      provider,
      createdAt: now,
    })
    return { user, identityId: identity.id }
  }

  async getUser(userId: number): Promise<User | null> {
    const [user] = await this.ctx.database.get('sso.user', { id: userId })
    return user ?? null
  }

  async link(userId: number, provider: string, db: Database = this.ctx.database): Promise<{ identityId: number }> {
    const now = new Date()
    const identity = await db.create('sso.identity', {
      userId,
      provider,
      createdAt: now,
    })
    // update user.updatedAt
    await db.set('sso.user', { id: userId }, { updatedAt: now })
    return { identityId: identity.id }
  }

  async unlink(identityId: number): Promise<void> {
    const [identity] = await this.ctx.database.get('sso.identity', { id: identityId })
    if (!identity) throw new Error('identity not found')

    // ensure user has at least one other identity
    const identities = await this.ctx.database.get('sso.identity', { userId: identity.userId })
    if (identities.length <= 1) {
      throw new Error('cannot remove the last identity')
    }

    const provider = this._providers.get(identity.provider)
    await this.ctx.database.transact(async (db) => {
      // Provider clears its own sso.<name> row (FK points here).
      await provider?.unlink?.(identityId, db)
      // Kill any sessions anchored to this identity — anyone logged in with
      // this specific identity will get 401 on their next request.
      await db.remove('sso.session', { identityId })
      await db.remove('sso.identity', { id: identityId })
      await db.set('sso.user', { id: identity.userId }, { updatedAt: new Date() })
    })
  }

  async getIdentities(userId: number): Promise<Identity[]> {
    return this.ctx.database.get('sso.identity', { userId })
  }

  async getIdentity(identityId: number): Promise<Identity | null> {
    const [identity] = await this.ctx.database.get('sso.identity', { id: identityId })
    return identity ?? null
  }

  // Iterate all providers' resolveUser hooks and return every matching
  // userId (deduplicated). Used by identifier-first flows (currently
  // webauthn) where a client-typed hint needs to be mapped to users without
  // committing to a specific provider upfront.
  //
  // Lookup order: sso.user.name (canonical account handle) first, then any
  // provider that implements resolveUser (e.g. mail's email, sms's phone).
  // Collisions ARE possible (e.g. one user's handle is "alice@foo.com",
  // another user's mail is "alice@foo.com"). We return all of them and let
  // callers decide the semantic — most pass ≥1 matches straight through
  // (webauthn concats allowCredentials); a few treat >1 as a server-state
  // error (password.resolve throws because it can't meaningfully check a
  // password against multiple accounts at once).
  async findUserByIdentifier(identifier: string): Promise<number[]> {
    const seen = new Set<number>()
    const [nameHit] = await this.ctx.database.get('sso.user', { name: identifier })
    if (nameHit) seen.add(nameHit.id)
    for (const provider of this._providers.values()) {
      const userId = await provider.resolveUser?.(identifier)
      if (userId) seen.add(userId)
    }
    return [...seen]
  }

  async createSession(userId: number, identityId: number, db: Database = this.ctx.database): Promise<string> {
    const now = new Date()
    const maxAge = this.config.sessionMaxAge ?? 7 * 24 * 60 * 60 * 1000 // 7 days
    const token = randomUUID()
    await db.create('sso.session', {
      token,
      userId,
      identityId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + maxAge),
    })
    return token
  }

  async validateSession(token: string): Promise<User | null> {
    const [session] = await this.ctx.database.get('sso.session', { token })
    if (!session) return null
    if (session.expiresAt < new Date()) {
      await this.ctx.database.remove('sso.session', { token })
      return null
    }
    return this.getUser(session.userId)
  }

  async destroySession(token: string): Promise<void> {
    await this.ctx.database.remove('sso.session', { token })
  }

  async destroyUserSessions(userId: number, except?: string): Promise<void> {
    const sessions = await this.ctx.database.get('sso.session', { userId })
    for (const session of sessions) {
      if (session.token !== except) {
        await this.ctx.database.remove('sso.session', { token: session.token })
      }
    }
  }
}

export default Sso
