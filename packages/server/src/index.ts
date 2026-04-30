import { Context } from 'cordis'
import type { Sso } from '@cordisjs/plugin-sso'
import { Request } from '@cordisjs/plugin-server'

export const name = 'sso-server'
export const inject = ['sso', 'server']

export function apply(ctx: Context) {
  // List available providers
  ctx.server.get('/sso/providers', async () => {
    return Response.json(await ctx.sso.getProviderMetas())
  })

  // Login via credentials
  ctx.server.post('/sso/auth/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')
    if (!provider.resolve) return errorResponse(400, 'RESOLVE_NOT_SUPPORTED')

    const body = await safeJson(req)
    await ctx.parallel('sso/auth', { provider: req.params.provider, credentials: body, request: req })

    const result = await provider.resolve(body)
    if (!result) {
      if (provider.autoRegister && provider.register) {
        return Response.json(await handleRegister(ctx.sso, provider, body))
      }
      return errorResponse(401, 'ACCOUNT_NOT_FOUND')
    }

    const identity = await ctx.sso.getIdentity(result.identityId)
    if (!identity) return errorResponse(500, 'IDENTITY_NOT_FOUND')

    const token = await ctx.sso.createSession(identity.userId, identity.id)
    return Response.json({ token })
  })

  // Register
  ctx.server.post('/sso/register/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')
    const body = await safeJson(req)
    return Response.json(await handleRegister(ctx.sso, provider, body))
  })

  // Get OAuth URL
  ctx.server.get('/sso/auth/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider?.getAuthUrl) return errorResponse(400, 'OAUTH_NOT_SUPPORTED')
    const url = new URL(req.url, 'http://localhost')
    const redirectUri = url.searchParams.get('redirect_uri') ?? ''
    const state = url.searchParams.get('state') ?? ''
    const authUrl = provider.getAuthUrl(redirectUri, state)
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

  // Link a new provider (requires session)
  ctx.server.post('/sso/link/:provider', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')
    const { identityId } = await ctx.sso.link(user.id, req.params.provider)
    return Response.json({ identityId })
  })

  // Unlink an identity (requires session)
  ctx.server.post('/sso/unlink/:id', async (req) => {
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

  // List current user's identities (requires session)
  ctx.server.get('/sso/identities', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    return Response.json(await ctx.sso.getIdentities(user.id))
  })

  // Logout
  ctx.server.post('/sso/logout', async (req) => {
    const token = extractToken(req)
    if (token) await ctx.sso.destroySession(token)
    return Response.json({ ok: true })
  })
}

async function handleRegister(sso: Sso, provider: any, credentials: any) {
  if (!provider.register) throw createError(400, 'REGISTER_NOT_SUPPORTED')
  const { user, identityId } = await sso.createUser(provider.name)
  await provider.register({ ...credentials, identityId })
  const token = await sso.createSession(user.id, identityId)
  return { token, userId: user.id }
}

async function requireSession(sso: Sso, token?: string) {
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
