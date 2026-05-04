import { Context, Inject } from 'cordis'
import { RedirectProvider, Sso } from '@cordisjs/plugin-sso'
import { callbackResponse, handleOAuthCallback, StateStore } from '@cordisjs/oauth-utils'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.qq': SsoQq
  }
}

export interface SsoQq {
  identityId: number
  openId: string
  unionId?: string
  accessToken: string
  refreshToken?: string
  displayName?: string
  avatar?: string
  tokenExpiresAt?: Date
}

export interface Config {
  appId: string
  appKey: string
  redirectUrl?: string
}

function parseCallback(text: string): any {
  const match = text.match(/callback\(\s*(.*?)\s*\);?/s)
  if (match) return JSON.parse(match[1])
  return JSON.parse(text)
}

@Inject('server')
@Inject('timer')
export default class QqProvider extends RedirectProvider {
  name = 'qq'
  canBePrimary = true
  canStepUp = false
  autoRegister = true
  interactive = true

  private state: StateStore

  constructor(ctx: Context, private config: Config) {
    super(ctx)

    this.state = new StateStore(ctx)

    ctx.database.extend('sso.qq', {
      identityId: 'unsigned(8)',
      openId: 'string(255)',
      unionId: 'string(255)',
      accessToken: 'string(255)',
      refreshToken: 'string(255)',
      displayName: 'string(255)',
      avatar: 'text',
      tokenExpiresAt: 'timestamp',
    }, {
      primary: 'identityId',
      unique: [['openId']],
      foreign: { identityId: ['sso.identity', 'id'] },
    })

    ctx.server.get('/sso/callback/qq', async (req) => {
      const url = new URL(req.url, 'http://localhost')
      const code = url.searchParams.get('code')!
      const state = url.searchParams.get('state')!
      const entry = this.state.consume(state)
      if (!entry) return callbackResponse({ error: 'INVALID_STATE', status: 400 }, this.config.redirectUrl)
      const linkUserId = entry.payload?.link?.userId as number | undefined
      const redirect_uri = entry.redirectUri

      try {
        const tokenData = await this.getAccessToken(code, redirect_uri)
        const { access_token, refresh_token, expires_in } = tokenData
        const meData = await this.getOpenId(access_token)
        const userInfo = await this.getUserInfo(access_token, meData.openid)

        const [existing] = await this.ctx.database.get('sso.qq', { openId: meData.openid })
        let resolveResult: { identityId: number } | null = null
        if (existing) {
          await this.ctx.database.set('sso.qq', { identityId: existing.identityId }, {
            accessToken: access_token,
            refreshToken: refresh_token,
            unionId: meData.unionid,
            displayName: userInfo.nickname,
            avatar: userInfo.figureurl_qq_2 ?? userInfo.figureurl_qq_1,
            tokenExpiresAt: expires_in ? new Date(Date.now() + +expires_in * 1000) : undefined,
          })
          resolveResult = { identityId: existing.identityId }
        }

        return await handleOAuthCallback({
          ctx,
          providerName: 'qq',
          autoRegister: this.autoRegister,
          linkUserId,
          resolveResult,
          display: userInfo.nickname,
          registerFn: async (identityId, db) => {
            await db.create('sso.qq', {
              identityId,
              openId: meData.openid,
              unionId: meData.unionid,
              accessToken: access_token,
              refreshToken: refresh_token,
              displayName: userInfo.nickname,
              avatar: userInfo.figureurl_qq_2 ?? userInfo.figureurl_qq_1,
              tokenExpiresAt: expires_in ? new Date(Date.now() + +expires_in * 1000) : undefined,
            })
          },
          redirectUrl: this.config.redirectUrl,
        })
      } catch (e) {
        console.warn('[sso-qq]', e)
        return callbackResponse({ error: 'OAUTH_CALLBACK_FAILED', status: 500 }, this.config.redirectUrl)
      }
    })
  }

  private async getAccessToken(code: string, redirectUri: string) {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.appId,
      client_secret: this.config.appKey,
      code,
      redirect_uri: redirectUri,
    })
    const res = await fetch(`https://graph.qq.com/oauth2.0/token?${params}`)
    const text = await res.text()
    if (text.includes('callback')) {
      const data = parseCallback(text)
      if (data.error) throw new Error(data.error_description)
    }
    const result: any = {}
    new URLSearchParams(text).forEach((v, k) => result[k] = v)
    return result
  }

  private async getOpenId(accessToken: string) {
    const res = await fetch(`https://graph.qq.com/oauth2.0/me?access_token=${accessToken}&unionid=1`)
    return parseCallback(await res.text())
  }

  private async getUserInfo(accessToken: string, openId: string) {
    const params = new URLSearchParams({ access_token: accessToken, oauth_consumer_key: this.config.appId, openid: openId })
    const res = await fetch(`https://graph.qq.com/user/get_user_info?${params}`)
    return res.json() as Promise<any>
  }

  getAuthUrl(redirectUri: string, state: string, link: { userId: number } | undefined, _ctx: Sso.StepContext) {
    this.state.register(state, redirectUri, link ? { link } : undefined)
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.appId,
      redirect_uri: redirectUri,
      state,
      scope: 'get_user_info',
    })
    return `https://graph.qq.com/oauth2.0/authorize?${params}`
  }

  async unlink(identityId: number, db: Database = this.ctx.database) {
    await db.remove('sso.qq', { identityId })
  }
}
