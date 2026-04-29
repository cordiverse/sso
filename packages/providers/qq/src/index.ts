import { Context, Inject } from 'cordis'
import { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-database'

declare module '@cordisjs/plugin-database' {
  interface Tables {
    sso_qq: SsoQq
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
}

function parseCallback(text: string): any {
  const match = text.match(/callback\(\s*(.*?)\s*\);?/s)
  if (match) return JSON.parse(match[1])
  return JSON.parse(text)
}

@Inject('server')
export default class QqProvider extends SsoProvider {
  name = 'qq'
  interactive = true
  autoRegister = true

  constructor(ctx: Context, private config: Config) {
    super(ctx)

    ctx.model.extend('sso_qq', {
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
      const redirect_uri = url.searchParams.get('redirect_uri')!
      const result = await this.resolve!({ code, state, redirect_uri })
      if (result) {
        const identity = await ctx.sso.getIdentity(result.identityId)
        const token = await ctx.sso.createSession(identity!.userId, identity!.id)
        return Response.json({ token })
      }
      if (this.autoRegister) {
        const { user, identityId } = await ctx.sso.createUser('qq')
        await this.register!({ identityId, code, redirect_uri })
        const token = await ctx.sso.createSession(user.id, identityId)
        return Response.json({ token })
      }
      return Response.json({ error: 'ACCOUNT_NOT_FOUND' }, { status: 401 })
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

  getAuthUrl(redirectUri: string, state: string) {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.appId,
      redirect_uri: redirectUri,
      state,
      scope: 'get_user_info',
    })
    return `https://graph.qq.com/oauth2.0/authorize?${params}`
  }

  async resolve(credentials: any) {
    const { code, redirect_uri } = credentials
    if (!code) return null
    const tokenData = await this.getAccessToken(code, redirect_uri)
    const { access_token, refresh_token, expires_in } = tokenData
    const meData = await this.getOpenId(access_token)
    const userInfo = await this.getUserInfo(access_token, meData.openid)
    const [existing] = await this.ctx.model.get('sso_qq', { openId: meData.openid })
    if (existing) {
      await this.ctx.model.set('sso_qq', { identityId: existing.identityId }, {
        accessToken: access_token,
        refreshToken: refresh_token,
        unionId: meData.unionid,
        displayName: userInfo.nickname,
        avatar: userInfo.figureurl_qq_2 ?? userInfo.figureurl_qq_1,
        tokenExpiresAt: expires_in ? new Date(Date.now() + +expires_in * 1000) : undefined,
      })
      return { identityId: existing.identityId }
    }
    return null
  }

  async register(credentials: any) {
    const { identityId, code, redirect_uri } = credentials
    if (!identityId) throw new Error('identityId required')
    const tokenData = await this.getAccessToken(code, redirect_uri)
    const meData = await this.getOpenId(tokenData.access_token)
    const userInfo = await this.getUserInfo(tokenData.access_token, meData.openid)
    await this.ctx.model.create('sso_qq', {
      identityId,
      openId: meData.openid,
      unionId: meData.unionid,
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      displayName: userInfo.nickname,
      avatar: userInfo.figureurl_qq_2 ?? userInfo.figureurl_qq_1,
      tokenExpiresAt: tokenData.expires_in ? new Date(Date.now() + +tokenData.expires_in * 1000) : undefined,
    })
    return {}
  }
}
