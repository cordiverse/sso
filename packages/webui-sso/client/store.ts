import { reactive } from 'vue'
import { startAuthentication, startRegistration } from '@simplewebauthn/browser'
import type { ChallengeResponse, Identity, StepResult, User } from '../shared'

const TOKEN_KEY = 'cordis:webui-sso:token'

export type FlowKind = 'login' | 'register' | 'bind'

interface SsoStore {
  token: string | null
  user: User | null
  ready: boolean
}

export const store = reactive<SsoStore>({
  token: localStorage.getItem(TOKEN_KEY),
  user: null,
  ready: false,
})

function setToken(token: string | null) {
  store.token = token
  if (token) {
    localStorage.setItem(TOKEN_KEY, token)
  } else {
    localStorage.removeItem(TOKEN_KEY)
  }
}

async function request<T>(method: string, path: string, body?: any, withAuth = false): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['content-type'] = 'application/json'
  if (withAuth && store.token) headers['authorization'] = `Bearer ${store.token}`
  const res = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const isJson = res.headers.get('content-type')?.toLowerCase().includes('application/json')

  if (!res.ok) {
    let code = `HTTP_${res.status}`
    if (isJson) {
      try {
        const data = await res.json()
        if (data?.error) code = data.error
      } catch {}
    }
    if (res.status === 401 && withAuth) {
      setToken(null)
      store.user = null
    }
    throw new SsoError(code, res.status)
  }

  if (res.status === 204) return undefined as T
  if (!isJson) {
    throw new SsoError('UNEXPECTED_RESPONSE', res.status)
  }
  return await res.json() as T
}

export class SsoError extends Error {
  constructor(public code: string, public status: number) {
    super(code)
  }
}

export async function refresh(): Promise<void> {
  if (!store.token) {
    store.user = null
    store.ready = true
    return
  }
  try {
    store.user = await request<User>('GET', '/sso/me', undefined, true)
  } catch {
    store.user = null
  } finally {
    store.ready = true
  }
}

export interface FlowInteract {
  collectCode?(meta: { length: number; digits: boolean; data?: any; providerName: string }): Promise<string>
}

export interface FlowOptions {
  interact?: FlowInteract
}

function endpointFor(kind: FlowKind, providerName: string): { method: string; path: string; withAuth: boolean } {
  if (kind === 'bind') {
    return { method: 'POST', path: `/sso/identities/${providerName}`, withAuth: true }
  }
  return { method: 'POST', path: `/sso/sessions/${providerName}`, withAuth: false }
}

export async function ssoStep(kind: FlowKind, providerName: string, body: any = {}): Promise<StepResult> {
  const { method, path, withAuth } = endpointFor(kind, providerName)
  const payload = { ...body }
  if (kind === 'register') payload.intent = 'register'
  const result = await request<StepResult>(method, path, payload, withAuth)
  if (result.phase === 'finish' && result.token) {
    setToken(result.token)
    await refresh()
  }
  return result
}

async function stepRequest(kind: FlowKind, providerName: string, body: any): Promise<StepResult> {
  return ssoStep(kind, providerName, body)
}

export async function runFlow(
  kind: FlowKind,
  providerName: string,
  initialBody: any = {},
  options: FlowOptions = {},
): Promise<StepResult> {
  let body: any = initialBody
  while (true) {
    const result = await stepRequest(kind, providerName, body)
    if (result.phase === 'finish') {
      if (result.token) {
        setToken(result.token)
        await refresh()
      }
      return result
    }
    if (result.phase === 'redirect') {
      location.assign(result.url)
      return result
    }
    if (result.phase === 'challenge') {
      body = await handleChallenge(providerName, result.challengeId, result.response, result.data, options.interact)
      continue
    }
    if (result.phase === 'stepup') {
      return result
    }
    throw new SsoError('UNKNOWN_PHASE', 500)
  }
}

async function handleChallenge(
  providerName: string,
  challengeId: string,
  response: ChallengeResponse,
  data: any,
  interact?: FlowInteract,
): Promise<any> {
  if (response.shape === 'code') {
    if (!interact?.collectCode) {
      throw new SsoError('INTERACT_REQUIRED', 400)
    }
    const code = await interact.collectCode({
      length: response.length,
      digits: response.digits,
      data,
      providerName,
    })
    return { challengeId, code }
  }
  if (response.shape === 'webauthn-create') {
    const attestation = await startRegistration({ optionsJSON: response.options })
    return { challengeId, response: attestation }
  }
  if (response.shape === 'webauthn-get') {
    const assertion = await startAuthentication({ optionsJSON: response.options })
    return { challengeId, response: assertion }
  }
  throw new SsoError('UNKNOWN_CHALLENGE_SHAPE', 400)
}

export async function logout(): Promise<void> {
  try {
    await request('DELETE', '/sso/sessions', undefined, true)
  } catch {}
  setToken(null)
  store.user = null
}

export async function listIdentities(): Promise<Identity[]> {
  return await request<Identity[]>('GET', '/sso/identities', undefined, true)
}

export async function unlink(identityId: number): Promise<void> {
  await request<{ ok: true }>('DELETE', `/sso/identities/${identityId}`, undefined, true)
}

const OAUTH_STATE_KEY = 'cordis:webui-sso:oauth-state'
const OAUTH_INTENT_KEY = 'cordis:webui-sso:oauth-intent'

export function buildOAuthRedirectUri(): string {
  const url = new URL(location.href)
  url.hash = '#/sso'
  url.search = ''
  return url.toString()
}

export function generateState(): string {
  return crypto.randomUUID()
}

export function rememberOAuthContext(provider: string, state: string) {
  sessionStorage.setItem(OAUTH_STATE_KEY, state)
  sessionStorage.setItem(OAUTH_INTENT_KEY, provider)
}

export function consumeOAuthCallback(): { token?: string; error?: string } {
  const hash = location.hash
  const queryStart = hash.lastIndexOf('?')
  const params = new URLSearchParams(queryStart >= 0 ? hash.slice(queryStart + 1) : '')
  const tokenFromQuery = params.get('token') ?? undefined
  const errorFromQuery = params.get('error') ?? undefined
  let token = tokenFromQuery
  let error = errorFromQuery
  if (!token && !error && hash.startsWith('#') && hash.includes('=') && !hash.startsWith('#/')) {
    const flat = new URLSearchParams(hash.slice(1))
    token = flat.get('token') ?? undefined
    error = flat.get('error') ?? undefined
  }
  if (!token && !error) return {}

  if (queryStart >= 0) {
    history.replaceState(null, '', location.pathname + location.search + hash.slice(0, queryStart))
  } else {
    history.replaceState(null, '', location.pathname + location.search + '#/sso')
  }

  if (token) {
    setToken(token)
    sessionStorage.removeItem(OAUTH_STATE_KEY)
    sessionStorage.removeItem(OAUTH_INTENT_KEY)
  }
  return { token, error }
}

export async function startRedirectFlow(kind: FlowKind, providerName: string): Promise<void> {
  const state = generateState()
  rememberOAuthContext(providerName, state)
  await runFlow(kind, providerName, {
    redirect_uri: buildOAuthRedirectUri(),
    state,
  })
}
