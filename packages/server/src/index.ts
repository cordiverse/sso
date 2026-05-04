import { Context } from 'cordis'
import type {} from '@cordisjs/plugin-sso'
import { Request } from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-database'

export const name = 'sso-server'
export const inject = ['sso', 'server', 'database']

export function apply(ctx: Context) {
  // List available providers
  ctx.server.get('/sso/providers', async () => {
    return Response.json(await ctx.sso.getProviderMetas())
  })

  // Create a session via credentials (= login)
  ctx.server.post('/sso/sessions/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')
    if (!provider.resolve) return errorResponse(400, 'RESOLVE_NOT_SUPPORTED')

    const body = await safeJson(req)
    await ctx.parallel('sso/auth', { provider: req.params.provider, credentials: body, request: req })

    const result = await provider.resolve(body)
    if (!result) {
      if (provider.autoRegister && provider.register) {
        return Response.json(await handleRegister(ctx, provider, body))
      }
      return errorResponse(401, 'INVALID_CREDENTIALS')
    }

    const identity = await ctx.sso.getIdentity(result.identityId)
    if (!identity) return errorResponse(500, 'IDENTITY_NOT_FOUND')

    const token = await ctx.sso.createSession(identity.userId, identity.id)
    return Response.json({ token })
  })

  // Destroy current session (= logout)
  ctx.server.delete('/sso/sessions', async (req) => {
    const token = extractToken(req)
    if (token) await ctx.sso.destroySession(token)
    return Response.json({ ok: true })
  })

  // Challenge-based login finish. The client first calls /sso/challenge/:provider
  // to get a challengeId + options, runs the provider-specific ceremony
  // (WebAuthn signs, etc.), and POSTs the result here to exchange for a
  // session token. Currently only webauthn implements provider.authenticate.
  ctx.server.post('/sso/sessions/:provider/finish', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')
    if (!provider.authenticate) return errorResponse(400, 'AUTHENTICATE_NOT_SUPPORTED')
    const body = await safeJson(req)
    const { challengeId, response } = body
    if (!challengeId || response === undefined) return errorResponse(400, 'INVALID_REQUEST')
    const result = await provider.authenticate(challengeId, response)
    if (!result) return errorResponse(401, 'VERIFICATION_FAILED')
    const identity = await ctx.sso.getIdentity(result.identityId)
    if (!identity) return errorResponse(500, 'IDENTITY_NOT_FOUND')
    const token = await ctx.sso.createSession(identity.userId, identity.id)
    return Response.json({ token, userId: identity.userId })
  })

  // Create a new user (= register)
  ctx.server.post('/sso/users/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')
    const body = await safeJson(req)
    return Response.json(await handleRegister(ctx, provider, body))
  })

  // Current user (requires session)
  ctx.server.get('/sso/me', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    return Response.json(user)
  })

  // Get OAuth authorization URL. When `intent=link` is passed the caller
  // must supply a valid session; the logged-in userId is baked into the
  // OAuth state so the callback handler can attach the credential to the
  // existing user instead of creating a new one.
  ctx.server.get('/sso/oauth-url/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider?.getAuthUrl) return errorResponse(400, 'OAUTH_NOT_SUPPORTED')
    const url = new URL(req.url, 'http://localhost')
    const redirectUri = url.searchParams.get('redirect_uri') ?? ''
    const state = url.searchParams.get('state') ?? ''
    let link: { userId: number } | undefined
    if (url.searchParams.get('intent') === 'link') {
      const token = extractToken(req)
      const user = await requireSession(ctx.sso, token)
      if (!user) return errorResponse(401, 'SESSION_REQUIRED')
      link = { userId: user.id }
    }
    const authUrl = provider.getAuthUrl(redirectUri, state, link)
    return Response.json({ url: authUrl })
  })

  // OAuth callback: each OAuth provider registers `/sso/callback/<name>` itself
  // (qq, wechat, twitter, apple, oauth). The shapes diverge enough — PKCE, JWT
  // id_token, form_post body, weibo's token-in-query — that a one-size handler
  // here would force all providers through the same Request -> credentials
  // shape. Keeping it provider-local trades a bit of repetition for clarity.

  // Challenge (e.g. send verification code)
  ctx.server.post('/sso/challenge/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider?.challenge) return errorResponse(400, 'CHALLENGE_NOT_SUPPORTED')
    const body = await safeJson(req)
    const result = await provider.challenge(body)
    return Response.json(result)
  })

  // Verify challenge
  ctx.server.post('/sso/verify/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider?.verify) return errorResponse(400, 'VERIFY_NOT_SUPPORTED')
    const body = await safeJson(req)
    const { challengeId, response } = body
    const ok = await provider.verify(challengeId, response)
    if (!ok) return errorResponse(401, 'VERIFICATION_FAILED')
    return Response.json({ ok: true })
  })

  // List current user's identities (requires session)
  ctx.server.get('/sso/identities', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    return Response.json(await ctx.sso.getIdentities(user.id))
  })

  // Link a new provider to current user (requires session). If the body
  // carries credentials, provider.register is invoked in the same transaction
  // so the identity row and the provider-specific row are either both
  // persisted or both rolled back. Providers whose register is driven by an
  // OAuth callback (qq/wechat/twitter/apple/oauth) don't take a body here;
  // for them the identity row is a placeholder until the callback runs.
  ctx.server.post('/sso/identities/:provider', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')
    const body = await safeJson(req)
    const hasCredentials = body && Object.keys(body).length > 0
    const result = await ctx.database.transact(async (db) => {
      const { identityId } = await ctx.sso.link(user.id, req.params.provider, db)
      if (hasCredentials && provider.register) {
        const reg = await provider.register({ ...body, identityId }, db)
        return { identityId, data: reg?.data }
      }
      return { identityId }
    })
    return Response.json(result.data ? result : { identityId: result.identityId })
  })

  // Unlink an identity (requires session)
  ctx.server.delete('/sso/identities/:id', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    const identityId = parseInt(req.params.id)
    const identity = await ctx.sso.getIdentity(identityId)
    if (!identity || identity.userId !== user.id) {
      return errorResponse(404, 'IDENTITY_NOT_FOUND')
    }
    await ctx.sso.unlink(identityId)
    return Response.json({ ok: true })
  })
}

async function handleRegister(ctx: Context, provider: any, credentials: any) {
  if (!provider.register) throw createError(400, 'REGISTER_NOT_SUPPORTED')
  return ctx.database.transact(async (db) => {
    const { user, identityId } = await ctx.sso.createUser(provider.name, db)
    const result = await provider.register({ ...credentials, identityId }, db)
    const token = await ctx.sso.createSession(user.id, identityId, db)
    return { token, userId: user.id, ...(result?.data ? { data: result.data } : {}) }
  })
}

async function requireSession(sso: any, token?: string) {
  if (!token) return null
  return sso.validateSession(token)
}

function extractToken(req: Request): string | undefined {
  const header = req.headers.get('authorization')
  if (!header) return
  const [type, token] = header.split(' ')
  if (type.toLowerCase() === 'bearer') return token
}

async function safeJson(req: Request): Promise<any> {
  try { return await req.json() } catch { return {} }
}

function createError(status: number, code: string) {
  const error: any = new Error(code)
  error.status = status
  error.code = code
  return error
}

function errorResponse(status: number, code: string) {
  return Response.json({ error: code }, { status })
}
