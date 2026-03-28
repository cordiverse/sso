import { Context } from 'cordis'
import type {} from '@cordisjs/plugin-sso'

export type CaptchaType = 'recaptcha' | 'hcaptcha' | 'turnstile'

export interface Config {
  /** CAPTCHA provider type */
  type: CaptchaType
  /** Site key (exposed to frontend) */
  siteKey: string
  /** Secret key (server-side verification) */
  secretKey: string
  /** Only apply to these SSO providers (empty = all) */
  providers?: string[]
  /** Minimum score threshold for reCAPTCHA v3 (0.0 - 1.0, default: 0.5) */
  minScore?: number
}

const VERIFY_URLS: Record<CaptchaType, string> = {
  recaptcha: 'https://www.google.com/recaptcha/api/siteverify',
  hcaptcha: 'https://api.hcaptcha.com/siteverify',
  turnstile: 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
}

export const name = 'sso-captcha'
export const inject = ['sso']

export function apply(ctx: Context, config: Config) {
  const { type, secretKey, providers, minScore = 0.5 } = config

  ctx.on('sso/auth', async (event: any) => {
    // Check if this provider requires captcha
    if (providers?.length && !providers.includes(event.provider)) return

    const token = event.request?.headers?.['x-captcha-token']
      ?? event.credentials?.captchaToken
    if (!token) {
      const error: any = new Error('CAPTCHA_REQUIRED')
      error.status = 400
      error.code = 'CAPTCHA_REQUIRED'
      error.data = {
        type: config.type,
        siteKey: config.siteKey,
      }
      throw error
    }

    // Verify with provider
    const verifyUrl = VERIFY_URLS[type]
    const res = await fetch(verifyUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: secretKey,
        response: token,
      }),
    })
    const data = await res.json() as any

    if (!data.success) {
      const error: any = new Error('CAPTCHA_FAILED')
      error.status = 403
      error.code = 'CAPTCHA_FAILED'
      error.data = {
        errors: data['error-codes'],
      }
      throw error
    }

    // reCAPTCHA v3 score check
    if (type === 'recaptcha' && typeof data.score === 'number') {
      if (data.score < minScore) {
        const error: any = new Error('CAPTCHA_SCORE_TOO_LOW')
        error.status = 403
        error.code = 'CAPTCHA_SCORE_TOO_LOW'
        error.data = { score: data.score, minScore }
        throw error
      }
    }
  })

  // Expose captcha info in provider metadata for frontend
  const originalGetProviders = ctx.sso.getProviders.bind(ctx.sso)
  ctx.sso.getProviders = function () {
    return originalGetProviders().map(p => ({
      ...p,
      captcha: (!providers?.length || providers.includes(p.name))
        ? { type: config.type, siteKey: config.siteKey }
        : null,
    }))
  }
}
