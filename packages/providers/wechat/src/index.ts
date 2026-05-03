import { Context, Inject } from 'cordis'
import { SsoProvider } from '@cordisjs/plugin-sso'
import { callbackResponse, StateStore } from '@cordisjs/oauth-utils'
import type { Database } from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-timer'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    'sso.wechat': SsoWeChat
  }
}

export interface SsoWeChat {
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
  appSecret: string
  scope?: string
  /** See OAuth provider's `redirectUrl` — same fragment-token semantics. */
  redirectUrl?: string
}

@Inject('server')
@Inject('timer')
export default class WeChatProvider extends SsoProvider {
  name = 'wechat'
  interactive = true
  autoRegister = true

  private state: StateStore

  constructor(ctx: Context, private config: Config) {
    super(ctx)

    this.state = new StateStore(ctx)

    ctx.database.extend('sso.wechat', {
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

    ctx.server.get('/sso/callback/wechat', async (req) => {
      const url = new URL(req.url, 'http://localhost')
      const code = url.searchParams.get('code')!
      const state = url.searchParams.get('state')!
      const entry = this.state.consume(state)
      if (!entry) return callbackResponse({ error: 'INVALID_STATE', status: 400 }, this.config.redirectUrl)
      const result = await this.resolve!({ code, state })
      if (result) {
        const identity = await ctx.sso.getIdentity(result.identityId)
        const token = await ctx.sso.createSession(identity!.userId, identity!.id)
        return callbackResponse({ token }, this.config.redirectUrl)
      }
      if (this.autoRegister) {
        const { user, identityId } = await ctx.sso.createUser('wechat')
        await this.register!({ identityId, code })
        const token = await ctx.sso.createSession(user.id, identityId)
        return callbackResponse({ token }, this.config.redirectUrl)
      }
      return callbackResponse({ error: 'ACCOUNT_NOT_FOUND', status: 401 }, this.config.redirectUrl)
    })
  }

  private async getAccessToken(code: string) {
    const params = new URLSearchParams({
      appid: this.config.appId,
      secret: this.config.appSecret,
      code,
      grant_type: 'authorization_code',
    })
    const res = await fetch(`https://api.weixin.qq.com/sns/oauth2/access_token?${params}`)
    return res.json() as Promise<any>
  }

  private async getUserInfo(accessToken: string, openId: string) {
    const params = new URLSearchParams({ access_token: accessToken, openid: openId })
    const res = await fetch(`https://api.weixin.qq.com/sns/userinfo?${params}`)
    return res.json() as Promise<any>
  }

  getAuthUrl(redirectUri: string, state: string) {
    this.state.register(state, redirectUri)
    const scope = this.config.scope ?? 'snsapi_login'
    const params = new URLSearchParams({
      appid: this.config.appId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope,
      state,
    })
    return `https://open.weixin.qq.com/connect/qrconnect?${params}#wechat_redirect`
  }

  async resolve(credentials: any) {
    const { code } = credentials
    if (!code) return null
    const tokenData = await this.getAccessToken(code)
    if (tokenData.errcode) return null
    const { access_token, openid, unionid, refresh_token, expires_in } = tokenData
    const userInfo = await this.getUserInfo(access_token, openid)
    const [existing] = await this.ctx.database.get('sso.wechat', { openId: openid })
    if (existing) {
      await this.ctx.database.set('sso.wechat', { identityId: existing.identityId }, {
        accessToken: access_token,
        refreshToken: refresh_token,
        unionId: unionid,
        displayName: userInfo.nickname,
        avatar: userInfo.headimgurl,
        tokenExpiresAt: expires_in ? new Date(Date.now() + expires_in * 1000) : undefined,
      })
      return { identityId: existing.identityId }
    }
    return null
  }

  async register(credentials: any, db: Database = this.ctx.database) {
    const { identityId, code } = credentials
    if (!identityId) throw new Error('identityId required')
    const tokenData = await this.getAccessToken(code)
    const { access_token, openid, unionid, refresh_token, expires_in } = tokenData
    const userInfo = await this.getUserInfo(access_token, openid)
    await db.create('sso.wechat', {
      identityId,
      openId: openid,
      unionId: unionid,
      accessToken: access_token,
      refreshToken: refresh_token,
      displayName: userInfo.nickname,
      avatar: userInfo.headimgurl,
      tokenExpiresAt: expires_in ? new Date(Date.now() + expires_in * 1000) : undefined,
    })
  }
}
