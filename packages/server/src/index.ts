import { Context } from 'cordis'
import type { SSO } from '@cordisjs/plugin-sso'

declare module 'cordis' {
  interface Context {
    'sso.server': SSOServer
  }
}

export interface SSOServer {
  route(method: 'get' | 'post' | 'put' | 'delete', path: string, handler: RouteHandler): void
}

export type RouteHandler = (ctx: RouteContext) => Promise<any>

export interface RouteContext {
  /** Raw request */
  request: any
  /** Session token from Authorization header (if present) */
  token?: string
  /** Request body (parsed JSON) */
  body?: any
  /** URL params */
  params: Record<string, string>
  /** Query string params */
  query: Record<string, string>
}

export const name = 'sso-server'
export const inject = ['sso', 'server']

export function apply(ctx: Context) {
  const sso: SSO = ctx.sso

  // Provide sso.server sub-service
  const server: SSOServer = {
    route(method, path, handler) {
      const fullPath = `/sso${path}`
      ctx.server[method](fullPath, async (koa) => {
        const token = extractToken(koa.request.headers.authorization)
        const routeCtx: RouteContext = {
          request: koa.request,
          token,
          body: koa.request.body,
          params: koa.params ?? {},
          query: koa.query ?? {},
        }
        try {
          const result = await handler(routeCtx)
          koa.body = result ?? { ok: true }
        } catch (error: any) {
          koa.status = error.status ?? 400
          koa.body = { error: error.code ?? error.message }
        }
      })
    },
  }

  ctx.provide('sso.server', server)

  // List available providers
  server.route('get', '/providers', async () => {
    return sso.getProviders().map((p) => ({
      name: p.name,
      interactive: p.interactive,
      autoRegister: p.autoRegister,
    }))
  })

  // Login via credentials
  server.route('post', '/auth/:provider', async ({ params, body, request }) => {
    const provider = sso.getProvider(params.provider)
    if (!provider) throw createError(404, 'PROVIDER_NOT_FOUND')
    if (!provider.resolve) throw createError(400, 'RESOLVE_NOT_SUPPORTED')

    // Hook: sso/auth waterfall (captcha, rate limit, audit, etc.)
    await ctx.waterfall('sso/auth', { provider: params.provider, credentials: body, request })

    const result = await provider.resolve(body)
    if (!result) {
      if (provider.autoRegister && provider.register) {
        return handleRegister(sso, provider, body)
      }
      throw createError(401, 'ACCOUNT_NOT_FOUND')
    }

    const identity = await sso.getIdentity(result.identityId)
    if (!identity) throw createError(500, 'IDENTITY_NOT_FOUND')

    const token = await sso.createSession(identity.userId, identity.id)
    return { token }
  })

  // Register
  server.route('post', '/register/:provider', async ({ params, body }) => {
    const provider = sso.getProvider(params.provider)
    if (!provider) throw createError(404, 'PROVIDER_NOT_FOUND')
    return handleRegister(sso, provider, body)
  })

  // Get OAuth URL
  server.route('get', '/auth/:provider', async ({ params, query }) => {
    const provider = sso.getProvider(params.provider)
    if (!provider?.getAuthUrl) throw createError(400, 'OAUTH_NOT_SUPPORTED')
    const redirectUri = query.redirect_uri ?? ''
    const state = query.state ?? ''
    const url = provider.getAuthUrl(redirectUri, state)
    return { url }
  })

  // OAuth callback
  server.route('get', '/callback/:provider', async ({ params, query }) => {
    const provider = sso.getProvider(params.provider)
    if (!provider?.resolve) throw createError(404, 'PROVIDER_NOT_FOUND')
    const result = await provider.resolve(query)
    if (!result) {
      if (provider.autoRegister && provider.register) {
        return handleRegister(sso, provider, query)
      }
      throw createError(401, 'ACCOUNT_NOT_FOUND')
    }
    const identity = await sso.getIdentity(result.identityId)
    if (!identity) throw createError(500, 'IDENTITY_NOT_FOUND')
    const token = await sso.createSession(identity.userId, identity.id)
    return { token }
  })

  // Challenge (e.g. send verification code)
  server.route('post', '/challenge/:provider', async ({ params, body }) => {
    const provider = sso.getProvider(params.provider)
    if (!provider?.challenge) throw createError(400, 'CHALLENGE_NOT_SUPPORTED')
    const result = await provider.challenge(body)
    return result
  })

  // Verify challenge
  server.route('post', '/verify/:provider', async ({ params, body }) => {
    const provider = sso.getProvider(params.provider)
    if (!provider?.verify) throw createError(400, 'VERIFY_NOT_SUPPORTED')
    const { challengeId, response } = body
    const ok = await provider.verify(challengeId, response)
    if (!ok) throw createError(401, 'VERIFICATION_FAILED')
    // After verification, provider should have resolved an identity
    // The actual session creation depends on the provider's flow
    return { ok: true }
  })

  // Link a new provider (requires session)
  server.route('post', '/link/:provider', async ({ params, token }) => {
    const user = await requireSession(sso, token)
    const provider = sso.getProvider(params.provider)
    if (!provider) throw createError(404, 'PROVIDER_NOT_FOUND')
    const { identityId } = await sso.link(user.id, params.provider)
    return { identityId }
  })

  // Unlink an identity (requires session)
  server.route('post', '/unlink/:id', async ({ params, token }) => {
    const user = await requireSession(sso, token)
    const identityId = parseInt(params.id)
    const identity = await sso.getIdentity(identityId)
    if (!identity || identity.userId !== user.id) {
      throw createError(404, 'IDENTITY_NOT_FOUND')
    }
    await sso.unlink(identityId)
    return { ok: true }
  })

  // List current user's identities (requires session)
  server.route('get', '/identities', async ({ token }) => {
    const user = await requireSession(sso, token)
    return sso.getIdentities(user.id)
  })

  // Logout
  server.route('post', '/logout', async ({ token }) => {
    if (token) await sso.destroySession(token)
    return { ok: true }
  })
}

async function handleRegister(sso: SSO, provider: any, credentials: any) {
  if (!provider.register) throw createError(400, 'REGISTER_NOT_SUPPORTED')
  const { user, identityId } = await sso.createUser(provider.name)
  await provider.register({ ...credentials, identityId })
  const token = await sso.createSession(user.id, identityId)
  return { token, userId: user.id }
}

async function requireSession(sso: SSO, token?: string) {
  if (!token) throw createError(401, 'SESSION_REQUIRED')
  const user = await sso.validateSession(token)
  if (!user) throw createError(401, 'SESSION_INVALID')
  return user
}

function extractToken(header?: string): string | undefined {
  if (!header) return
  const [type, token] = header.split(' ')
  if (type.toLowerCase() === 'bearer') return token
}

function createError(status: number, code: string) {
  const error: any = new Error(code)
  error.status = status
  error.code = code
  return error
}
