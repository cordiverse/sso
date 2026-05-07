import { Context } from 'cordis'
import { createHash, randomBytes } from 'node:crypto'
import { CredentialsProvider, ssoError } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'
import z from 'schemastery'

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

interface PasswordCreds {
  username: string
  password: string
}

function hashPassword(password: string, salt: string, algorithm = 'sha256'): string {
  return createHash(algorithm).update(salt + password).digest('hex')
}

export default class PasswordProvider extends CredentialsProvider<PasswordCreds> {
  static Config: z<Config> = z.object({
    minLength: z.natural().default(8).description('密码最小长度。'),
    algorithm: z.string().default('sha256').description('密码哈希算法。'),
  })

  name = 'password'
  canBePrimary = true
  canStepUp = false
  jitProvisioning = false
  interactive = true

  minLength: number
  algorithm: string

  constructor(ctx: Context, config: Config = {}) {
    super(ctx)
    this.minLength = config.minLength ?? 8
    this.algorithm = config.algorithm ?? 'sha256'

    ctx.database.extend('sso.password', {
      identityId: 'unsigned(8)',
      hash: 'string(255)',
      salt: 'string(255)',
    }, {
      primary: 'identityId',
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  async resolve(creds: PasswordCreds) {
    const { username, password } = creds ?? {} as PasswordCreds
    if (!username || !password) return null

    const userIds = await this.ctx.sso.findUserByIdentifier(username)
    if (userIds.length === 0) return null
    if (userIds.length > 1) {
      throw new Error(`ambiguous identifier ${JSON.stringify(username)}: matched ${userIds.length} users`)
    }
    const [userId] = userIds

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

  async writeIdentity(userId: number, identityId: number, creds: PasswordCreds, db: Database) {
    const { username, password } = creds ?? {} as PasswordCreds
    if (!username || !password) throw ssoError(400, 'INVALID_REQUEST')
    if (password.length < this.minLength) {
      throw ssoError(400, 'PASSWORD_TOO_SHORT')
    }

    const [existing] = await db.get('sso.user', { name: username })
    if (existing && existing.id !== userId) {
      throw ssoError(409, 'USERNAME_TAKEN')
    }
    const [owner] = await db.get('sso.user', { id: userId })
    await db.set('sso.user', { id: userId }, {
      name: username,
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
    await db.remove('sso.password', { identityId })
  }
}
