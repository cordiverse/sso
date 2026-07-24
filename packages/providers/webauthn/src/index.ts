import { Context, Inject } from 'cordis'
import { randomBytes, randomUUID } from 'node:crypto'
import {
  AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  WebAuthnCredential,
} from '@simplewebauthn/server'
import { ChallengeProvider, Sso, ssoError } from '@cordisjs/plugin-sso'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-timer'
import z from 'schemastery'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.webauthn': SsoWebAuthn
  }
}

export interface SsoWebAuthn {
  identityId: number
  credentialId: string
  publicKey: string
  signCount: number
  deviceType: string
  backedUp: boolean
  deviceName?: string
  transports?: string
  createdAt: Date
  lastUsedAt?: Date
}

export interface Config {
  rpName?: string
  rpId?: string
  origin?: string
  timeout?: number
}

interface WebauthnInit {
  hint?: string
  name?: string
  userName?: string
  displayName?: string
  deviceName?: string
}

interface WebauthnComplete {
  response: any
  deviceName?: string
}

type WebauthnExtra =
  | {
    mode: 'register'
    challenge: string
    userName: string
    displayName: string
    newUserName?: string
    verified?: {
      credentialId: string
      publicKey: string
      signCount: number
      deviceType: string
      backedUp: boolean
      transports?: string
      deviceName?: string
    }
  }
  | {
    mode: 'authenticate'
    challenge: string
    matchedIdentityId?: number
    newSignCount?: number
  }

@Inject('server')
export default class WebAuthnProvider extends ChallengeProvider<WebauthnInit, WebauthnComplete, WebauthnExtra> {
  static Config: z<Config> = z.object({
    rpName: z.string().default('Cordis').description('Relying Party 名称（用户在认证器中看到的站点名）。'),
    rpId: z.string().description('Relying Party ID，默认取自 ctx.server.baseUrl 的 hostname。'),
    origin: z.string().description('期望的 origin，默认取自 ctx.server.baseUrl。'),
    timeout: z.natural().default(60000).description('认证流程超时时间（毫秒）。'),
  })

  name = 'webauthn'
  canBePrimary = true
  canStepUp = true
  jitProvisioning = false
  interactive = true
  multipleIdentities = true

  protected consumeOnFailure = true

  private rpName: string
  private rpId: string
  private origin: string

  constructor(ctx: Context, config: Config = {}) {
    super(ctx)
    const base = new URL(ctx.server.baseUrl)
    let hostname = base.hostname
    if (hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]') {
      hostname = 'localhost'
    }
    const port = base.port ? `:${base.port}` : ''
    this.rpName = config.rpName ?? 'Cordis'
    this.rpId = config.rpId ?? hostname
    this.origin = config.origin ?? `${base.protocol}//${hostname}${port}`
    this.challengeTtl = config.timeout ?? 60000

    ctx.database.extend('sso.webauthn', {
      identityId: 'unsigned(8)',
      credentialId: 'string(512)',
      publicKey: 'text',
      signCount: 'unsigned(8)',
      deviceType: 'string(32)',
      backedUp: { type: 'boolean', initial: false },
      deviceName: 'string(255)',
      transports: 'string(255)',
      createdAt: 'timestamp',
      lastUsedAt: 'timestamp',
    }, {
      primary: 'identityId',
      unique: [['credentialId']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })
  }

  private async getCredentialsForUser(userId: number): Promise<WebAuthnCredential[]> {
    const identities = await this.ctx.sso.getIdentities(userId)
    const ids = identities.filter((i) => i.provider === this.name).map((i) => i.id)
    if (!ids.length) return []
    const records = await this.ctx.database.get('sso.webauthn', { identityId: { $in: ids } })
    return records.map((r) => ({
      id: r.credentialId,
      publicKey: Buffer.from(r.publicKey, 'base64'),
      counter: r.signCount,
      transports: r.transports ? JSON.parse(r.transports) : undefined,
    }))
  }

  async issue(input: WebauthnInit, ctx: Sso.StepContext) {
    const challengeId = randomUUID()
    if (ctx.kind === 'register' || ctx.kind === 'bind') {
      let userName = input?.userName ?? input?.name
      let displayName = input?.displayName
      if (ctx.userId && (!userName || !displayName)) {
        const [owner] = await this.ctx.database.get('sso.user', { id: ctx.userId })
        userName = userName ?? owner?.name ?? owner?.display ?? undefined
        displayName = displayName ?? owner?.display ?? owner?.name ?? userName
      }
      userName = userName ?? 'User'
      displayName = displayName ?? userName
      const existing = ctx.userId ? await this.getCredentialsForUser(ctx.userId) : []
      const userIdBytes = ctx.userId
        ? Buffer.from(String(ctx.userId))
        : randomBytes(16)
      const options = await generateRegistrationOptions({
        rpName: this.rpName,
        rpID: this.rpId,
        userID: userIdBytes,
        userName,
        userDisplayName: displayName,
        timeout: this.challengeTtl,
        attestationType: 'none',
        authenticatorSelection: { userVerification: 'preferred' },
        excludeCredentials: existing.map((c) => ({ id: c.id, transports: c.transports })),
      })
      return {
        challengeId,
        response: { shape: 'webauthn-create' as const, options },
        extra: {
          mode: 'register' as const,
          challenge: options.challenge,
          userName,
          displayName,
          newUserName: ctx.kind === 'register' ? input?.name : undefined,
        },
        data: options,
      }
    }

    // authenticate (login or stepup)
    let authCredentials: WebAuthnCredential[] = []
    if (ctx.userId) {
      authCredentials = await this.getCredentialsForUser(ctx.userId)
    } else if (input?.hint) {
      const userIds = await this.ctx.sso.findUserByIdentifier(input.hint)
      for (const id of userIds) {
        authCredentials = authCredentials.concat(await this.getCredentialsForUser(id))
      }
    }
    const options = await generateAuthenticationOptions({
      rpID: this.rpId,
      timeout: this.challengeTtl,
      allowCredentials: authCredentials.map((c) => ({ id: c.id, transports: c.transports })),
      userVerification: 'preferred',
    })
    return {
      challengeId,
      response: { shape: 'webauthn-get' as const, options },
      extra: {
        mode: 'authenticate' as const,
        challenge: options.challenge,
      },
      data: options,
    }
  }

  async verify(pending: Sso.Pending<WebauthnExtra>, input: WebauthnComplete) {
    const responseBody = input?.response
    if (!responseBody) return false
    const body = typeof responseBody === 'string' ? JSON.parse(responseBody) : responseBody

    if (pending.extra.mode === 'register') {
      try {
        const verification = await verifyRegistrationResponse({
          response: body as RegistrationResponseJSON,
          expectedChallenge: pending.extra.challenge,
          expectedOrigin: this.origin,
          expectedRPID: this.rpId,
        })
        if (!verification.verified || !verification.registrationInfo) return false
        const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo
        pending.extra.verified = {
          credentialId: credential.id,
          publicKey: Buffer.from(credential.publicKey).toString('base64'),
          signCount: credential.counter,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
          transports: body.response?.transports ? JSON.stringify(body.response.transports) : undefined,
          deviceName: input.deviceName,
        }
        return true
      } catch { return false }
    }

    // authenticate
    try {
      const credentialId = body.id
      const [record] = await this.ctx.database.get('sso.webauthn', { credentialId })
      if (!record) return false
      if (pending.userId) {
        const identity = await this.ctx.sso.getIdentity(record.identityId)
        if (!identity || identity.userId !== pending.userId) return false
      }
      const credential: WebAuthnCredential = {
        id: record.credentialId,
        publicKey: Buffer.from(record.publicKey, 'base64'),
        counter: record.signCount,
        transports: record.transports ? JSON.parse(record.transports) : undefined,
      }
      const verification = await verifyAuthenticationResponse({
        response: body as AuthenticationResponseJSON,
        expectedChallenge: pending.extra.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        credential,
      })
      if (!verification.verified) return false
      pending.extra.matchedIdentityId = record.identityId
      pending.extra.newSignCount = verification.authenticationInfo.newCounter
      await this.ctx.database.set('sso.webauthn', { credentialId }, {
        signCount: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date(),
      })
      return true
    } catch { return false }
  }

  async resolve(pending: Sso.Pending<WebauthnExtra>) {
    if (pending.extra.mode !== 'authenticate') return null
    if (!pending.extra.matchedIdentityId) return null
    return { identityId: pending.extra.matchedIdentityId }
  }

  async writeIdentity(userId: number, identityId: number, pending: Sso.Pending<WebauthnExtra>, db: Database) {
    if (pending.extra.mode !== 'register') throw ssoError(400, 'INVALID_REQUEST')
    const verified = pending.extra.verified
    if (!verified) throw ssoError(500, 'VERIFICATION_STATE_LOST')
    await db.create('sso.webauthn', {
      identityId,
      credentialId: verified.credentialId,
      publicKey: verified.publicKey,
      signCount: verified.signCount,
      deviceType: verified.deviceType,
      backedUp: verified.backedUp,
      deviceName: verified.deviceName,
      transports: verified.transports,
      createdAt: new Date(),
    })
    if (pending.kind === 'register' && pending.extra.newUserName) {
      const [owner] = await db.get('sso.user', { id: userId })
      const update: { name?: string; display?: string } = { name: pending.extra.newUserName }
      if (!owner?.display) update.display = pending.extra.displayName
      await db.set('sso.user', { id: userId }, update)
    } else {
      const [owner] = await db.get('sso.user', { id: userId })
      if (owner && !owner.display) {
        await db.set('sso.user', { id: userId }, { display: pending.extra.displayName })
      }
    }
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    await db.remove('sso.webauthn', { identityId })
  }
}
