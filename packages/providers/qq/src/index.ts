import { Context } from 'cordis'
import type { SSO, SSOProvider } from '@cordisjs/plugin-sso'

declare module 'minato' {
  interface Tables {
    sso_qq: SSOQQ
  }
}

export interface SSOQQ {
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

export const name = 'sso-qq'
export const inject = ['sso', 'sso.server']

// QQ API returns JSONP-like format: callback( {"key":"value"} );
function parseCallback(text: string): any {
  const match = text.match(/callback\(\s*(.*?)\s*\);?/s)
  if (match) return JSON.parse(match[1])
  // Try plain JSON
  return JSON.parse(text)
}

export function apply(ctx: Context, config: Config) {
  ctx.minato.extend('sso_qq', {
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
    foreign: { identityId: ['sso_identity', 'id'] },
  })

  // Step 1: Exchange code for access_token
  async function getAccessToken(code: string, redirectUri: string) {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: config.appId,
      client_secret: config.appKey,
      code,
      redirect_uri: redirectUri,
    })
    const res = await fetch(`https://graph.qq.com/oauth2.0/token?${params}`)
    const text = await res.text()
    // Response format: access_token=xxx&expires_in=7776000&refresh_token=xxx
    // or callback format on error
    if (text.includes('callback')) {
      const data = parseCallback(text)
      if (data.error) throw new Error(data.error_description)
    }
    const result: any = {}
    new URLSearchParams(text).forEach((v, k) => result[k] = v)
    return result
  }

  // Step 2: Get OpenID from access_token
  async function getOpenId(accessToken: string) {
    const res = await fetch(`https://graph.qq.com/oauth2.0/me?access_token=${accessToken}&unionid=1`)
    const text = await res.text()
    return parseCallback(text) // { openid, unionid, client_id }
  }

  // Step 3: Get user info
  async function getUserInfo(accessToken: string, openId: string) {
    const params = new URLSearchParams({
      access_token: accessToken,
      oauth_consumer_key: config.appId,
      openid: openId,
    })
    const res = await fetch(`https://graph.qq.com/user/get_user_info?${params}`)
    return res.json() as Promise<any>
  }

  const provider: SSOProvider = {
    name: 'qq',
    interactive: true,
    autoRegister: true,

    getAuthUrl(redirectUri: string, state: string) {
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: config.appId,
        redirect_uri: redirectUri,
        state,
        scope: 'get_user_info',
      })
      return `https://graph.qq.com/oauth2.0/authorize?${params}`
    },

    async resolve(credentials: any) {
      const { code, redirect_uri } = credentials
      if (!code) return null

      const tokenData = await getAccessToken(code, redirect_uri)
      const { access_token, refresh_token, expires_in } = tokenData
      const meData = await getOpenId(access_token)
      const { openid, unionid } = meData
      const userInfo = await getUserInfo(access_token, openid)

      const [existing] = await ctx.minato.get('sso_qq', { openId: openid })
      if (existing) {
        await ctx.minato.set('sso_qq', { identityId: existing.identityId }, {
          accessToken: access_token,
          refreshToken: refresh_token,
          unionId: unionid,
          displayName: userInfo.nickname,
          avatar: userInfo.figureurl_qq_2 ?? userInfo.figureurl_qq_1,
          tokenExpiresAt: expires_in ? new Date(Date.now() + +expires_in * 1000) : undefined,
        })
        return { identityId: existing.identityId }
      }

      return null
    },

    async register(credentials: any) {
      const { identityId, code, redirect_uri } = credentials
      if (!identityId) throw new Error('identityId required')

      const tokenData = await getAccessToken(code, redirect_uri)
      const meData = await getOpenId(tokenData.access_token)
      const userInfo = await getUserInfo(tokenData.access_token, meData.openid)

      await ctx.minato.create('sso_qq', {
        identityId,
        openId: meData.openid,
        unionId: meData.unionid,
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        displayName: userInfo.nickname,
        avatar: userInfo.figureurl_qq_2 ?? userInfo.figureurl_qq_1,
        tokenExpiresAt: tokenData.expires_in
          ? new Date(Date.now() + +tokenData.expires_in * 1000) : undefined,
      })
      return {}
    },
  }

  ctx['sso.server'].route('get', '/callback/qq', async (routeCtx) => {
    const { code, state } = routeCtx.query
    const result = await provider.resolve!({ code, state, redirect_uri: routeCtx.query.redirect_uri })
    if (result) {
      const identity = await ctx.sso.getIdentity(result.identityId)
      const token = await ctx.sso.createSession(identity!.userId, identity!.id)
      return { token }
    }
    if (provider.autoRegister) {
      const { user, identityId } = await ctx.sso.createUser('qq')
      await provider.register!({ identityId, code, redirect_uri: routeCtx.query.redirect_uri })
      const token = await ctx.sso.createSession(user.id, identityId)
      return { token }
    }
    return { error: 'ACCOUNT_NOT_FOUND' }
  })

  ctx.sso.register(provider)
}
