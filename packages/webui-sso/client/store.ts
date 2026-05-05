import { reactive } from 'vue'
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
    const { startRegistration } = await import('@simplewebauthn/browser')
    const attestation = await startRegistration({ optionsJSON: response.options })
    return { challengeId, response: attestation }
  }
  if (response.shape === 'webauthn-get') {
    const { startAuthentication } = await import('@simplewebauthn/browser')
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

export function buildOAuthRedirectUri(providerName: string): string {
  return `${location.origin}/sso/callback/${providerName}`
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
  if (!hash.startsWith('#') || hash.startsWith('#/') || !hash.includes('=')) return {}
  const params = new URLSearchParams(hash.slice(1))
  const token = params.get('token') ?? undefined
  const error = params.get('error') ?? undefined
  if (!token && !error) return {}

  history.replaceState(null, '', location.pathname + location.search)
  if (token) setToken(token)
  sessionStorage.removeItem(OAUTH_STATE_KEY)
  sessionStorage.removeItem(OAUTH_INTENT_KEY)
  return { token, error }
}

const OAUTH_MESSAGE_TYPE = 'cordis:webui-sso:oauth'

function isOAuthPopup(): boolean {
  try {
    return !!window.opener && window.opener !== window
  } catch {
    return false
  }
}

export function reportOAuthToOpener(): boolean {
  if (!isOAuthPopup()) return false
  const hash = location.hash
  if (!hash.startsWith('#') || hash.startsWith('#/') || !hash.includes('=')) return false
  const params = new URLSearchParams(hash.slice(1))
  const token = params.get('token') ?? undefined
  const error = params.get('error') ?? undefined
  if (!token && !error) return false
  try {
    window.opener!.postMessage({ type: OAUTH_MESSAGE_TYPE, token, error }, location.origin)
  } catch {}
  window.close()
  return true
}

export async function runOAuthFlow(kind: FlowKind, providerName: string): Promise<{ token?: string; error?: string }> {
  const popup = window.open('about:blank', `cordis-oauth-${providerName}`, 'width=600,height=700')
  if (!popup) {
    await startRedirectFlow(kind, providerName)
    return {}
  }

  const resultPromise = new Promise<{ token?: string; error?: string }>((resolve) => {
    let polled: ReturnType<typeof setInterval>
    const cleanup = () => {
      window.removeEventListener('message', onMessage)
      clearInterval(polled)
    }
    const onMessage = (e: MessageEvent) => {
      if (e.origin !== location.origin) return
      if (e.data?.type !== OAUTH_MESSAGE_TYPE) return
      cleanup()
      resolve({ token: e.data.token, error: e.data.error })
    }
    window.addEventListener('message', onMessage)
    polled = setInterval(() => {
      if (popup.closed) {
        cleanup()
        resolve({ error: 'USER_CANCELED' })
      }
    }, 500)
  })

  const state = generateState()
  rememberOAuthContext(providerName, state)
  try {
    const result = await ssoStep(kind, providerName, {
      redirect_uri: buildOAuthRedirectUri(providerName),
      state,
    })
    if (result.phase !== 'redirect') {
      popup.close()
      return { error: 'UNEXPECTED_PHASE' }
    }
    popup.location.href = result.url
  } catch (e: any) {
    popup.close()
    return { error: e?.code ?? 'UNKNOWN' }
  }

  const res = await resultPromise
  if (res.token) {
    setToken(res.token)
    sessionStorage.removeItem(OAUTH_STATE_KEY)
    sessionStorage.removeItem(OAUTH_INTENT_KEY)
    await refresh()
  }
  return res
}

export async function startRedirectFlow(kind: FlowKind, providerName: string): Promise<void> {
  const state = generateState()
  rememberOAuthContext(providerName, state)
  await runFlow(kind, providerName, {
    redirect_uri: buildOAuthRedirectUri(providerName),
    state,
  })
}
