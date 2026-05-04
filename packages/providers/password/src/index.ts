import { Context } from 'cordis'
import { createHash, randomBytes } from 'node:crypto'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.password': SsoPassword
  }
}

export interface SsoPassword {
  identityId: number
  hash: string
  salt: string
}

export interface Config {
  minLength?: number
  algorithm?: string
}

function hashPassword(password: string, salt: string, algorithm = 'sha256'): string {
  return createHash(algorithm).update(salt + password).digest('hex')
}

export default class PasswordProvider extends SsoProvider {
  name = 'password'
  type = 'credentials' as const
  interactive = true
  autoRegister = false

  minLength: number
  algorithm: string

  constructor(ctx: Context, config: Config = {}) {
    super(ctx)
    this.minLength = config.minLength ?? 8
    this.algorithm = config.algorithm ?? 'sha256'

    // Password is a pure credential container — the login identifier ("the
    // user's username") lives on sso.user.name, not here. This table only
    // stores the per-identity hash+salt. Unbinding a password identity
    // leaves the sso.user.name intact for mail/webauthn/etc. to keep using.
    ctx.database.extend('sso.password', {
      identityId: 'unsigned(8)',
      hash: 'string(255)',
      salt: 'string(255)',
    }, {
      primary: 'identityId',
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  async resolve(credentials: any) {
    const { username, password } = credentials
    if (!username || !password) return null

    // username → userId via the shared resolver (hits sso.user.name first).
    const userIds = await this.ctx.sso.findUserByIdentifier(username)
    if (userIds.length === 0) return null
    if (userIds.length > 1) {
      // Data-shape invariant violation: one identifier should never pick out
      // two accounts. Likely cause is one user picking another user's email
      // as their handle, or vice versa. Throwing here surfaces as 500 at the
      // HTTP layer so ops notices and fixes the overlap — we deliberately
      // don't try to "guess the right one" with the password, because that
      // would silently authenticate into arbitrary accounts.
      throw new Error(`ambiguous identifier ${JSON.stringify(username)}: matched ${userIds.length} users`)
    }
    const [userId] = userIds

    // userId → the user's password identity (there is at most one; password
    // is not something you'd bind twice).
    const [identity] = await this.ctx.database.get('sso.identity', {
      userId, provider: this.name,
    })
    if (!identity) return null

    const [record] = await this.ctx.database.get('sso.password', { identityId: identity.id })
    if (!record) return null

    const hash = hashPassword(password, record.salt, this.algorithm)
    if (hash !== record.hash) return null

    return { identityId: identity.id }
  }

  async register(credentials: any, db: Database = this.ctx.database) {
    const { identityId, username, password } = credentials
    if (!identityId) throw new Error('identityId required')
    if (!username || !password) throw new Error('username and password required')
    if (password.length < this.minLength) {
      throw new Error(`password must be at least ${this.minLength} characters`)
    }

    // Set sso.user.name. The identity row was just created by the caller
    // (handleRegister / Sso.link) so we can reach the owning user via
    // identityId. If the name is already taken, the unique constraint on
    // sso.user.name will reject the set and the whole transaction rolls back.
    const [identity] = await db.get('sso.identity', { id: identityId })
    if (!identity) throw new Error('identity not found')
    const [existing] = await db.get('sso.user', { name: username })
    if (existing && existing.id !== identity.userId) {
      throw new Error('username already taken')
    }
    const [owner] = await db.get('sso.user', { id: identity.userId })
    await db.set('sso.user', { id: identity.userId }, {
      name: username,
      // Only seed display on the first registering provider — if the user
      // has already picked a display name (or another provider set one),
      // don't clobber it.
      ...(owner?.display ? {} : { display: username }),
    })

    const salt = randomBytes(16).toString('hex')
    const hash = hashPassword(password, salt, this.algorithm)

    await db.create('sso.password', {
      identityId,
      hash,
      salt,
    })
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    // Do NOT clear sso.user.name — it's the account-level handle, other
    // providers (mail, webauthn's display label) still reference it.
    await db.remove('sso.password', { identityId })
  }
}
