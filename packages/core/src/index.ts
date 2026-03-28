import { Context, Service } from 'cordis'
import type {} from 'minato'
import { Random } from 'cosmokit'

declare module 'cordis' {
  interface Context {
    sso: SSO
  }

  interface Events {
    'sso/auth'(event: SSO.AuthEvent): void
  }
}

declare module 'minato' {
  interface Tables {
    user: User
    sso_identity: Identity
    sso_session: Session
  }
}

export interface SSOProvider {
  name: string
  interactive: boolean
  autoRegister: boolean

  resolve?(credentials: any): Promise<{ identityId: number; data?: any } | null>
  register?(credentials: any): Promise<{ data?: any }>
  getAuthUrl?(redirectUri: string, state: string): string
  challenge?(target: any): Promise<{ challengeId: string }>
  verify?(challengeId: string, response: string): Promise<boolean>
}

export interface User {
  id: number
  name?: string
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

export interface SSOProvider {
  name: string
  interactive: boolean
  autoRegister: boolean

  /** Resolve credentials to an existing identity. */
  resolve?(credentials: any): Promise<{ identityId: number; data?: any } | null>

  /** Register a new identity. Provider should create its own table row using the returned identityId. */
  register?(credentials: any): Promise<{ data?: any }>

  /** Get OAuth authorization URL. */
  getAuthUrl?(redirectUri: string, state: string): string

  /** Initiate a challenge (e.g. send verification code). */
  challenge?(target: any): Promise<{ challengeId: string }>

  /** Verify a challenge response. */
  verify?(challengeId: string, response: string): Promise<boolean>
}

export namespace SSO {
  export interface Config {
    sessionMaxAge?: number
  }

  export interface AuthEvent {
    provider: string
    credentials: any
    request?: any
  }
}

export class SSO extends Service {
  static inject = ['minato']

  private _providers = new Map<string, SSOProvider>()

  constructor(ctx: Context, public config: SSO.Config = {}) {
    super(ctx, 'sso')

    ctx.minato.extend('user', {
      id: 'unsigned(8)',
      name: 'string(255)',
      createdAt: 'timestamp',
      updatedAt: 'timestamp',
    }, { autoInc: true })

    ctx.minato.extend('sso_identity', {
      id: 'unsigned(8)',
      userId: 'unsigned(8)',
      provider: 'string(255)',
      createdAt: 'timestamp',
    }, {
      autoInc: true,
      foreign: { userId: ['user', 'id'] },
    })

    ctx.minato.extend('sso_session', {
      token: 'string(255)',
      userId: 'unsigned(8)',
      identityId: 'unsigned(8)',
      createdAt: 'timestamp',
      expiresAt: 'timestamp',
    }, {
      primary: 'token',
      foreign: {
        userId: ['user', 'id'],
        identityId: ['sso_identity', 'id'],
      },
    })
  }

  register(provider: SSOProvider): () => void {
    if (this._providers.has(provider.name)) {
      throw new Error(`SSO provider "${provider.name}" already registered`)
    }
    this._providers.set(provider.name, provider)
    return () => {
      this._providers.delete(provider.name)
    }
  }

  getProviders(): SSOProvider[] {
    return [...this._providers.values()]
  }

  getProvider(name: string): SSOProvider | undefined {
    return this._providers.get(name)
  }

  async createUser(provider: string): Promise<{ user: User; identityId: number }> {
    const now = new Date()
    const user = await this.ctx.minato.create('user', {
      createdAt: now,
      updatedAt: now,
    })
    const identity = await this.ctx.minato.create('sso_identity', {
      userId: user.id,
      provider,
      createdAt: now,
    })
    return { user, identityId: identity.id }
  }

  async getUser(userId: number): Promise<User | null> {
    const [user] = await this.ctx.minato.get('user', { id: userId })
    return user ?? null
  }

  async link(userId: number, provider: string): Promise<{ identityId: number }> {
    const now = new Date()
    const identity = await this.ctx.minato.create('sso_identity', {
      userId,
      provider,
      createdAt: now,
    })
    // update user.updatedAt
    await this.ctx.minato.set('user', { id: userId }, { updatedAt: now })
    return { identityId: identity.id }
  }

  async unlink(identityId: number): Promise<void> {
    const [identity] = await this.ctx.minato.get('sso_identity', { id: identityId })
    if (!identity) throw new Error('identity not found')

    // ensure user has at least one other identity
    const identities = await this.ctx.minato.get('sso_identity', { userId: identity.userId })
    if (identities.length <= 1) {
      throw new Error('cannot remove the last identity')
    }

    await this.ctx.minato.remove('sso_identity', { id: identityId })
    await this.ctx.minato.set('user', { id: identity.userId }, { updatedAt: new Date() })
  }

  async getIdentities(userId: number): Promise<Identity[]> {
    return this.ctx.minato.get('sso_identity', { userId })
  }

  async getIdentity(identityId: number): Promise<Identity | null> {
    const [identity] = await this.ctx.minato.get('sso_identity', { id: identityId })
    return identity ?? null
  }

  async createSession(userId: number, identityId: number): Promise<string> {
    const now = new Date()
    const maxAge = this.config.sessionMaxAge ?? 7 * 24 * 60 * 60 * 1000 // 7 days
    const token = Random.id(32, 36)
    await this.ctx.minato.create('sso_session', {
      token,
      userId,
      identityId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + maxAge),
    })
    return token
  }

  async validateSession(token: string): Promise<User | null> {
    const [session] = await this.ctx.minato.get('sso_session', { token })
    if (!session) return null
    if (session.expiresAt < new Date()) {
      await this.ctx.minato.remove('sso_session', { token })
      return null
    }
    return this.getUser(session.userId)
  }

  async destroySession(token: string): Promise<void> {
    await this.ctx.minato.remove('sso_session', { token })
  }

  async destroyUserSessions(userId: number, except?: string): Promise<void> {
    const sessions = await this.ctx.minato.get('sso_session', { userId })
    for (const session of sessions) {
      if (session.token !== except) {
        await this.ctx.minato.remove('sso_session', { token: session.token })
      }
    }
  }
}

export default SSO
