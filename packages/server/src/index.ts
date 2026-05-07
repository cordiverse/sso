import { Context } from 'cordis'
import type { Sso } from '@cordisjs/plugin-sso'
import {} from '@cordisjs/plugin-sso'
import { Request } from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-database'
import z from 'schemastery'

export const name = 'sso-server'
export const inject = ['sso', 'server', 'database']

export interface Config {}

export const Config: z<Config> = z.object({})

export function apply(ctx: Context) {
  ctx.server.get('/sso/providers', async () => {
    return Response.json(await ctx.sso.getProviderMetas())
  })

  ctx.server.post('/sso/sessions/:provider', async (req) => {
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')

    const body = await safeJson(req)
    await ctx.parallel('sso/auth', { provider: req.params.provider, credentials: body, request: req })

    const stepCtx: Sso.StepContext = { kind: 'login', request: req }
    if (body?.stepupId) {
      const entry = ctx.sso.peekStepup(String(body.stepupId))
      if (!entry) return errorResponse(401, 'STEPUP_EXPIRED')
      stepCtx.kind = 'stepup'
      stepCtx.stepupId = entry.stepupId
      stepCtx.stepupUserId = entry.userId
    } else if (body?.intent === 'register') {
      stepCtx.kind = 'register'
    }

    return runStep(provider, body, stepCtx)
  })

  ctx.server.delete('/sso/sessions', async (req) => {
    const token = extractToken(req)
    if (token) await ctx.sso.destroySession(token)
    return Response.json({ ok: true })
  })

  ctx.server.get('/sso/me', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    return Response.json(user)
  })

  ctx.server.get('/sso/identities', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    return Response.json(await ctx.sso.getIdentities(user.id))
  })

  ctx.server.post('/sso/identities/:provider', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    const provider = ctx.sso.getProvider(req.params.provider)
    if (!provider) return errorResponse(404, 'PROVIDER_NOT_FOUND')
    const body = await safeJson(req)
    return runStep(provider, body, { kind: 'bind', userId: user.id, request: req })
  })

  ctx.server.delete('/sso/identities/:id', async (req) => {
    const token = extractToken(req)
    const user = await requireSession(ctx.sso, token)
    if (!user) return errorResponse(401, 'SESSION_REQUIRED')
    const identityId = parseInt(req.params.id)
    const identity = await ctx.sso.getIdentity(identityId)
    if (!identity || identity.userId !== user.id) {
      return errorResponse(404, 'IDENTITY_NOT_FOUND')
    }
    try {
      await ctx.sso.unlink(identityId)
    } catch (e: any) {
      if (e?.message === 'cannot remove the last identity') {
        return errorResponse(400, 'LAST_IDENTITY')
      }
      throw e
    }
    return Response.json({ ok: true })
  })
}

async function runStep(provider: any, body: any, stepCtx: Sso.StepContext): Promise<Response> {
  try {
    const result = await provider.step(body ?? {}, stepCtx)
    return Response.json(result)
  } catch (e: any) {
    if (typeof e?.status === 'number' && typeof e?.code === 'string') {
      return errorResponse(e.status, e.code)
    }
    throw e
  }
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

function errorResponse(status: number, code: string) {
  return Response.json({ error: code }, { status })
}
