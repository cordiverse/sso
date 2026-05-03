import { Context } from 'cordis'
import { createHash, randomBytes } from 'node:crypto'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-database'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.password': SsoPassword
  }
}

export interface SsoPassword {
  identityId: number
  username: string
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
  interactive = true
  autoRegister = false

  minLength: number
  algorithm: string

  constructor(ctx: Context, config: Config = {}) {
    super(ctx)
    this.minLength = config.minLength ?? 8
    this.algorithm = config.algorithm ?? 'sha256'

    ctx.database.extend('sso.password', {
      identityId: 'unsigned(8)',
      username: 'string(255)',
      hash: 'string(255)',
      salt: 'string(255)',
    }, {
      primary: 'identityId',
      unique: [['username']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  async resolve(credentials: any) {
    const { username, password } = credentials
    if (!username || !password) return null

    const [record] = await this.ctx.database.get('sso.password', { username })
    if (!record) return null

    const hash = hashPassword(password, record.salt, this.algorithm)
    if (hash !== record.hash) return null

    return { identityId: record.identityId }
  }

  async register(credentials: any, db: Database = this.ctx.database) {
    const { identityId, username, password } = credentials
    if (!identityId) throw new Error('identityId required')
    if (!username || !password) throw new Error('username and password required')
    if (password.length < this.minLength) {
      throw new Error(`password must be at least ${this.minLength} characters`)
    }

    const [existing] = await db.get('sso.password', { username })
    if (existing) throw new Error('username already taken')

    const salt = randomBytes(16).toString('hex')
    const hash = hashPassword(password, salt, this.algorithm)

    await db.create('sso.password', {
      identityId,
      username,
      hash,
      salt,
    })
  }
}
