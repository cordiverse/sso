import { Context } from 'cordis'
import { createHash, randomBytes } from 'node:crypto'
import type { Sso, SsoProvider } from '@cordisjs/plugin-sso'

declare module 'minato' {
  interface Tables {
    sso_password: SSOPassword
  }
}

export interface SSOPassword {
  identityId: number
  username: string
  hash: string
  salt: string
}

export interface Config {
  /** Minimum password length */
  minLength?: number
  /** Hash algorithm */
  algorithm?: string
}

export const name = 'sso-password'
export const inject = ['sso']

function hashPassword(password: string, salt: string, algorithm = 'sha256'): string {
  return createHash(algorithm).update(salt + password).digest('hex')
}

export function apply(ctx: Context, config: Config = {}) {
  const { minLength = 8, algorithm = 'sha256' } = config

  ctx.model.extend('sso_password', {
    identityId: 'unsigned(8)',
    username: 'string(255)',
    hash: 'string(255)',
    salt: 'string(255)',
  }, {
    primary: 'identityId',
    unique: [['username']],
    foreign: { identityId: ['sso_identity', 'id'] },
  })

  const provider: SsoProvider = {
    name: 'password',
    interactive: true,
    autoRegister: false,

    async resolve(credentials: any) {
      const { username, password } = credentials
      if (!username || !password) return null

      const [record] = await ctx.model.get('sso_password', { username })
      if (!record) return null

      const hash = hashPassword(password, record.salt, algorithm)
      if (hash !== record.hash) return null

      return { identityId: record.identityId }
    },

    async register(credentials: any) {
      const { identityId, username, password } = credentials
      if (!identityId) throw new Error('identityId required')
      if (!username || !password) throw new Error('username and password required')
      if (password.length < minLength) {
        throw new Error(`password must be at least ${minLength} characters`)
      }

      // Check if username already taken
      const [existing] = await ctx.model.get('sso_password', { username })
      if (existing) throw new Error('username already taken')

      const salt = randomBytes(16).toString('hex')
      const hash = hashPassword(password, salt, algorithm)

      await ctx.model.create('sso_password', {
        identityId,
        username,
        hash,
        salt,
      })
      return {}
    },
  }

  ctx.sso.register(provider)
}
