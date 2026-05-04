import { Context, Inject, Service } from 'cordis'
import type { Awaitable } from 'cosmokit'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'
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

export function ssoError(status: number, code: string): Error {
  const err: any = new Error(code)
  err.status = status
  err.code = code
  return err
}

@Inject('sso')
@Inject('database')
export abstract class SsoProvider {
  abstract name: string
  abstract category: Sso.Category

  canBePrimary = true
  canStepUp = false
  autoRegister = false
  interactive = true

  constructor(public ctx: Context) {}

  * [Service.init]() {
    yield this.ctx.sso.register(this)
  }

  abstract step(input: unknown, ctx: Sso.StepContext): Promise<Sso.StepResult>

  unlink?(identityId: number, db?: Database): Promise<void>
  resolveUser?(identifier: string): Promise<number | null>
}

@Inject('sso')
@Inject('database')
export abstract class CredentialsProvider<Creds = any> extends SsoProvider {
  readonly category = 'credentials'

  async step(input: Creds, ctx: Sso.StepContext): Promise<Sso.StepResult> {
    if (ctx.kind === 'stepup') throw ssoError(400, 'STEP_NOT_SUPPORTED')

    if (ctx.kind === 'login') {
      const hit = await this.resolve(input)
      if (hit) {
        if (!this.canBePrimary) throw ssoError(400, 'NOT_PRIMARY_FACTOR')
        const identity = await this.ctx.sso.getIdentity(hit.identityId)
        if (!identity) throw ssoError(500, 'IDENTITY_NOT_FOUND')
        const token = await this.ctx.sso.createSession(identity.userId, identity.id)
        return { phase: 'finish', token, userId: identity.userId, identityId: identity.id, created: false }
      }
      if (!this.autoRegister) throw ssoError(401, 'ACCOUNT_NOT_FOUND')
      return this.doRegister(input)
    }

    if (ctx.kind === 'register') {
      return this.doRegister(input)
    }

    if (ctx.kind === 'bind') {
      if (!ctx.userId) throw ssoError(401, 'SESSION_REQUIRED')
      return this.ctx.database.transact(async (db) => {
        const { identityId } = await this.ctx.sso.link(ctx.userId!, this.name, db)
        await this.writeIdentity(ctx.userId!, identityId, input, db)
        return { phase: 'finish', identityId, userId: ctx.userId, created: false }
      })
    }

    throw ssoError(400, 'STEP_NOT_SUPPORTED')
  }

  private async doRegister(input: Creds): Promise<Sso.StepResult> {
    return this.ctx.database.transact(async (db) => {
      const { user, identityId } = await this.ctx.sso.createUser(this.name, db)
      await this.writeIdentity(user.id, identityId, input, db)
      const token = await this.ctx.sso.createSession(user.id, identityId, db)
      return { phase: 'finish', token, userId: user.id, identityId, created: true }
    })
  }

  abstract resolve(creds: Creds): Promise<{ identityId: number } | null>
  abstract writeIdentity(userId: number, identityId: number, creds: Creds, db: Database): Promise<void>
}

@Inject('sso')
@Inject('database')
@Inject('timer')
export abstract class ChallengeProvider<Init = any, Complete = any, Extra = unknown> extends SsoProvider {
  readonly category = 'challenge'

  protected challengeTtl = 10 * 60_000
  protected consumeOnFailure = false

  private pending = new Map<string, Sso.Pending<Extra>>()

  async step(input: any, ctx: Sso.StepContext): Promise<Sso.StepResult> {
    if (input?.challengeId) {
      return this.completeStep(input, ctx)
    }
    return this.issueStep(input, ctx)
  }

  private async issueStep(input: Init, ctx: Sso.StepContext): Promise<Sso.StepResult> {
    const issued = await this.issue(input, ctx)
    const pending: Sso.Pending<Extra> = {
      challengeId: issued.challengeId,
      kind: ctx.kind,
      userId: ctx.userId ?? ctx.stepupUserId,
      extra: issued.extra,
      expiresAt: Date.now() + this.challengeTtl,
    }
    this.pending.set(issued.challengeId, pending)
    this.ctx.timeout(() => this.pending.delete(issued.challengeId), this.challengeTtl)
    return { phase: 'challenge', challengeId: issued.challengeId, response: issued.response, data: issued.data }
  }

  private async completeStep(input: Complete & { challengeId: string }, ctx: Sso.StepContext): Promise<Sso.StepResult> {
    const pending = this.pending.get(input.challengeId)
    if (!pending || Date.now() > pending.expiresAt) {
      this.pending.delete(input.challengeId)
      throw ssoError(401, 'CHALLENGE_EXPIRED')
    }

    let ok = false
    try {
      ok = await this.verify(pending, input)
    } catch (e) {
      if (this.consumeOnFailure) this.pending.delete(input.challengeId)
      throw e
    }
    if (!ok) {
      if (this.consumeOnFailure) this.pending.delete(input.challengeId)
      throw ssoError(401, 'VERIFICATION_FAILED')
    }
    this.pending.delete(input.challengeId)

    const kind = pending.kind
    if (kind === 'login') {
      if (!this.canBePrimary) throw ssoError(400, 'NOT_PRIMARY_FACTOR')
      const hit = await this.resolve(pending)
      if (hit) {
        const identity = await this.ctx.sso.getIdentity(hit.identityId)
        if (!identity) throw ssoError(500, 'IDENTITY_NOT_FOUND')
        const token = await this.ctx.sso.createSession(identity.userId, identity.id)
        return { phase: 'finish', token, userId: identity.userId, identityId: identity.id, created: false }
      }
      if (!this.autoRegister) throw ssoError(401, 'ACCOUNT_NOT_FOUND')
      return this.ctx.database.transact(async (db) => {
        const { user, identityId } = await this.ctx.sso.createUser(this.name, db)
        await this.writeIdentity(user.id, identityId, pending, db)
        const token = await this.ctx.sso.createSession(user.id, identityId, db)
        return { phase: 'finish', token, userId: user.id, identityId, created: true }
      })
    }

    if (kind === 'register') {
      return this.ctx.database.transact(async (db) => {
        const { user, identityId } = await this.ctx.sso.createUser(this.name, db)
        await this.writeIdentity(user.id, identityId, pending, db)
        const token = await this.ctx.sso.createSession(user.id, identityId, db)
        return { phase: 'finish', token, userId: user.id, identityId, created: true }
      })
    }

    if (kind === 'bind') {
      const userId = pending.userId
      if (!userId) throw ssoError(401, 'SESSION_REQUIRED')
      return this.ctx.database.transact(async (db) => {
        const { identityId } = await this.ctx.sso.link(userId, this.name, db)
        await this.writeIdentity(userId, identityId, pending, db)
        return { phase: 'finish', identityId, userId, created: false }
      })
    }

    if (kind === 'stepup') {
      if (!this.canStepUp) throw ssoError(400, 'STEP_NOT_SUPPORTED')
      const userId = pending.userId
      if (!userId) throw ssoError(500, 'NO_STEPUP_USER')
      const identities = await this.ctx.sso.getIdentities(userId)
      const mine = identities.find((i) => i.provider === this.name)
      if (!mine) throw ssoError(500, 'NO_STEPUP_IDENTITY')
      const token = await this.ctx.sso.createSession(userId, mine.id)
      return { phase: 'finish', token, userId, identityId: mine.id, created: false }
    }

    throw ssoError(400, 'STEP_NOT_SUPPORTED')
  }

  abstract issue(input: Init, ctx: Sso.StepContext): Promise<{
    challengeId: string
    response: Sso.ChallengeResponse
    extra: Extra
    data?: unknown
  }>
  abstract verify(pending: Sso.Pending<Extra>, input: Complete & { challengeId: string }): Promise<boolean>
  abstract resolve(pending: Sso.Pending<Extra>): Promise<{ identityId: number } | null>
  abstract writeIdentity(userId: number, identityId: number, pending: Sso.Pending<Extra>, db: Database): Promise<void>
}

@Inject('sso')
@Inject('database')
export abstract class RedirectProvider extends SsoProvider {
  readonly category = 'redirect'

  async step(input: any, ctx: Sso.StepContext): Promise<Sso.StepResult> {
    if (ctx.kind === 'stepup') throw ssoError(400, 'STEP_NOT_SUPPORTED')
    const redirectUri = input?.redirect_uri
    const state = input?.state
    if (!redirectUri || !state) throw ssoError(400, 'INVALID_REQUEST')
    const link = ctx.kind === 'bind' && ctx.userId ? { userId: ctx.userId } : undefined
    const url = await this.getAuthUrl(redirectUri, state, link, ctx)
    return { phase: 'redirect', url }
  }

  abstract getAuthUrl(
    redirectUri: string,
    state: string,
    link: { userId: number } | undefined,
    ctx: Sso.StepContext,
  ): string | Promise<string>
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

  export type Category = 'credentials' | 'challenge' | 'redirect'

  export type IntentKind = 'login' | 'register' | 'bind' | 'stepup'

  export interface StepContext {
    kind: IntentKind
    userId?: number
    stepupId?: string
    stepupUserId?: number
    request?: any
  }

  export type Phase = 'finish' | 'challenge' | 'redirect' | 'stepup'

  export type StepResult =
    | { phase: 'finish'; token?: string; userId?: number; identityId?: number; created?: boolean }
    | { phase: 'challenge'; challengeId: string; response: ChallengeResponse; data?: unknown }
    | { phase: 'redirect'; url: string }
    | { phase: 'stepup'; stepupId: string; factors: StepupFactor[] }

  export type ChallengeResponse =
    | { shape: 'code'; length: number; digits: boolean }
    | { shape: 'webauthn-create'; options: any }
    | { shape: 'webauthn-get'; options: any }

  export interface StepupFactor {
    provider: string
    category: Category
  }

  export interface Pending<Extra = unknown> {
    challengeId: string
    kind: IntentKind
    userId?: number
    extra: Extra
    expiresAt: number
  }

  export interface ProviderMeta {
    name: string
    category: Category
    canBePrimary: boolean
    canStepUp: boolean
    autoRegister: boolean
    interactive: boolean
  }

  export interface StepupEntry {
    stepupId: string
    userId: number
    primaryIdentityId: number
    expiresAt: number
  }
}

@Inject('database')
export class Sso extends Service {
  private _providers = new Map<string, SsoProvider>()
  private _stepups = new Map<string, Sso.StepupEntry>()

  constructor(ctx: Context, public config: Sso.Config = {}) {
    super(ctx, 'sso')

    ctx.database.extend('sso.user', {
      id: 'unsigned(8)',
      name: 'string(255)',
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
      category: p.category,
      canBePrimary: p.canBePrimary,
      canStepUp: p.canStepUp,
      autoRegister: p.autoRegister,
      interactive: p.interactive,
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
    await db.set('sso.user', { id: userId }, { updatedAt: now })
    return { identityId: identity.id }
  }

  async unlink(identityId: number): Promise<void> {
    const [identity] = await this.ctx.database.get('sso.identity', { id: identityId })
    if (!identity) throw new Error('identity not found')

    const identities = await this.ctx.database.get('sso.identity', { userId: identity.userId })
    if (identities.length <= 1) {
      throw new Error('cannot remove the last identity')
    }

    const provider = this._providers.get(identity.provider)
    await this.ctx.database.transact(async (db) => {
      await provider?.unlink?.(identityId, db)
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
    const maxAge = this.config.sessionMaxAge ?? 7 * 24 * 60 * 60 * 1000
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

  issueStepup(userId: number, primaryIdentityId: number, ttl = 5 * 60_000): string {
    const stepupId = randomUUID()
    this._stepups.set(stepupId, {
      stepupId,
      userId,
      primaryIdentityId,
      expiresAt: Date.now() + ttl,
    })
    return stepupId
  }

  consumeStepup(stepupId: string): Sso.StepupEntry | null {
    const entry = this._stepups.get(stepupId)
    if (!entry) return null
    if (Date.now() > entry.expiresAt) {
      this._stepups.delete(stepupId)
      return null
    }
    this._stepups.delete(stepupId)
    return entry
  }

  peekStepup(stepupId: string): Sso.StepupEntry | null {
    const entry = this._stepups.get(stepupId)
    if (!entry) return null
    if (Date.now() > entry.expiresAt) {
      this._stepups.delete(stepupId)
      return null
    }
    return entry
  }
}

export default Sso
