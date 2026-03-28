import { Context } from 'cordis'
import type { SsoProvider } from '@cordisjs/plugin-sso'
import type {} from 'minato'

declare module 'minato' {
  interface Tables {
    sso_oauth: SsoOAuth
  }
}

export interface SsoOAuth {
  identityId: number
  provider: string // "github", "google", etc.
  externalId: string
  accessToken: string
  refreshToken?: string
  displayName?: string
  email?: string
  avatar?: string
  scope?: string
  tokenExpiresAt?: Date
}

/** Defines how to interact with a specific OAuth provider */
export interface OAuthPreset {
  /** Provider name (used as sso_identity.provider and sso_oauth.provider) */
  name: string
  /** Authorization URL */
  authorizeUrl: string
  /** Token exchange URL */
  tokenUrl: string
  /** User info URL */
  userInfoUrl: string
  /** Default scope */
  defaultScope: string
  /** Extra params to add to authorize URL */
  authorizeParams?: Record<string, string>
  /** Extra params to add to token request body */
  tokenParams?: Record<string, string>
  /** How to send the access token when fetching user info (default: "header") */
  tokenTransport?: 'header' | 'query'
  /** Extract user data from the userinfo response */
  extractUser(data: any): {
    externalId: string
    displayName?: string
    email?: string
    avatar?: string
  }
  /** Related identities implied by this login */
  getRelated?(data: any): { provider: string; key: any }[]
}

export const github: OAuthPreset = {
  name: 'github',
  authorizeUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userInfoUrl: 'https://api.github.com/user',
  defaultScope: 'read:user user:email',
  extractUser: (data) => ({
    externalId: String(data.id),
    displayName: data.login,
    email: data.email,
    avatar: data.avatar_url,
  }),
}

export const google: OAuthPreset = {
  name: 'google',
  authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
  defaultScope: 'openid email profile',
  authorizeParams: { access_type: 'offline', prompt: 'consent' },
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: data.id,
    displayName: data.name,
    email: data.email,
    avatar: data.picture,
  }),
}

export const microsoft: OAuthPreset = {
  name: 'microsoft',
  authorizeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
  tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
  defaultScope: 'openid email profile User.Read',
  authorizeParams: { response_mode: 'query' },
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: data.id,
    displayName: data.displayName,
    email: data.mail ?? data.userPrincipalName,
    avatar: undefined, // MS Graph photo needs separate request
  }),
}

export const discord: OAuthPreset = {
  name: 'discord',
  authorizeUrl: 'https://discord.com/oauth2/authorize',
  tokenUrl: 'https://discord.com/api/oauth2/token',
  userInfoUrl: 'https://discord.com/api/users/@me',
  defaultScope: 'identify email',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: data.id,
    displayName: data.global_name ?? data.username,
    email: data.email,
    avatar: data.avatar
      ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png`
      : undefined,
  }),
}

export const gitlab: OAuthPreset = {
  name: 'gitlab',
  authorizeUrl: 'https://gitlab.com/oauth/authorize',
  tokenUrl: 'https://gitlab.com/oauth/token',
  userInfoUrl: 'https://gitlab.com/api/v4/user',
  defaultScope: 'read_user',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: String(data.id),
    displayName: data.username,
    email: data.email,
    avatar: data.avatar_url,
  }),
}

export const facebook: OAuthPreset = {
  name: 'facebook',
  authorizeUrl: 'https://www.facebook.com/v21.0/dialog/oauth',
  tokenUrl: 'https://graph.facebook.com/v21.0/oauth/access_token',
  userInfoUrl: 'https://graph.facebook.com/me?fields=id,name,email,picture',
  defaultScope: 'email public_profile',
  extractUser: (data) => ({
    externalId: data.id,
    displayName: data.name,
    email: data.email,
    avatar: data.picture?.data?.url,
  }),
}

export const linkedin: OAuthPreset = {
  name: 'linkedin',
  authorizeUrl: 'https://www.linkedin.com/oauth/v2/authorization',
  tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
  userInfoUrl: 'https://api.linkedin.com/v2/userinfo',
  defaultScope: 'openid email profile',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: data.sub,
    displayName: data.name,
    email: data.email,
    avatar: data.picture,
  }),
}

export const slack: OAuthPreset = {
  name: 'slack',
  authorizeUrl: 'https://slack.com/openid/connect/authorize',
  tokenUrl: 'https://slack.com/api/openid.connect.token',
  userInfoUrl: 'https://slack.com/api/openid.connect.userInfo',
  defaultScope: 'openid email profile',
  extractUser: (data) => ({
    externalId: data.sub ?? data['https://slack.com/user_id'],
    displayName: data.name,
    email: data.email,
    avatar: data.picture,
  }),
}

export const gitee: OAuthPreset = {
  name: 'gitee',
  authorizeUrl: 'https://gitee.com/oauth/authorize',
  tokenUrl: 'https://gitee.com/oauth/token',
  userInfoUrl: 'https://gitee.com/api/v5/user',
  defaultScope: 'user_info',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => ({
    externalId: String(data.id),
    displayName: data.login,
    email: data.email,
    avatar: data.avatar_url,
  }),
}

export const dingtalk: OAuthPreset = {
  name: 'dingtalk',
  authorizeUrl: 'https://login.dingtalk.com/oauth2/auth',
  tokenUrl: 'https://api.dingtalk.com/v1.0/oauth2/userAccessToken',
  userInfoUrl: 'https://api.dingtalk.com/v1.0/contact/users/me',
  defaultScope: 'openid',
  tokenParams: { grantType: 'authorization_code' },
  extractUser: (data) => ({
    externalId: data.openId ?? data.unionId,
    displayName: data.nick,
    email: data.email,
    avatar: data.avatarUrl,
  }),
}

export const weibo: OAuthPreset = {
  name: 'weibo',
  authorizeUrl: 'https://api.weibo.com/oauth2/authorize',
  tokenUrl: 'https://api.weibo.com/oauth2/access_token',
  userInfoUrl: 'https://api.weibo.com/2/users/show.json',
  defaultScope: '',
  tokenTransport: 'query',
  extractUser: (data) => ({
    externalId: String(data.id ?? data.uid),
    displayName: data.screen_name ?? data.name,
    email: undefined, // Weibo doesn't provide email
    avatar: data.avatar_large ?? data.profile_image_url,
  }),
}

export const feishu: OAuthPreset = {
  name: 'feishu',
  authorizeUrl: 'https://passport.feishu.cn/suite/passport/oauth/authorize',
  tokenUrl: 'https://open.feishu.cn/open-apis/authen/v1/oidc/access_token',
  userInfoUrl: 'https://open.feishu.cn/open-apis/authen/v1/user_info',
  defaultScope: '',
  tokenParams: { grant_type: 'authorization_code' },
  extractUser: (data) => {
    const user = data.data ?? data
    return {
      externalId: user.open_id,
      displayName: user.name,
      email: user.email,
      avatar: user.avatar_url,
    }
  },
  getRelated: (data) => {
    const user = data.data ?? data
    return [
      { provider: 'satori', key: { platform: 'lark', pid: user.open_id } },
    ]
  },
}

export function lark(isFeishu = false): OAuthPreset {
  if (isFeishu) return feishu
  const domain = 'https://open.larksuite.com'
  const authDomain = 'https://passport.larksuite.com'
  return {
    name: 'lark',
    authorizeUrl: `${authDomain}/suite/passport/oauth/authorize`,
    tokenUrl: `${domain}/open-apis/authen/v1/oidc/access_token`,
    userInfoUrl: `${domain}/open-apis/authen/v1/user_info`,
    defaultScope: '',
    tokenParams: { grant_type: 'authorization_code' },
    extractUser: (data) => {
      const user = data.data ?? data
      return {
        externalId: user.open_id,
        displayName: user.name,
        email: user.email,
        avatar: user.avatar_url,
      }
    },
    getRelated: (data) => {
      const user = data.data ?? data
      return [
        { provider: 'satori', key: { platform: 'lark', pid: user.open_id } },
      ]
    },
  }
}

export interface Config {
  preset: OAuthPreset | string
  clientId: string
  clientSecret: string
  scope?: string
  /** Custom endpoints (used when preset is 'none' or to override preset values) */
  name?: string
  authorizeUrl?: string
  tokenUrl?: string
  userInfoUrl?: string
}

const builtinPresets: Record<string, OAuthPreset> = {
  github, google, microsoft, discord, gitlab,
  facebook, linkedin, slack, gitee, dingtalk, weibo, feishu,
}

export const name = 'sso-oauth'
export const inject = ['sso', 'sso.server']
export const reusable = true

export function apply(ctx: Context, config: Config) {
  let preset: OAuthPreset
  if (typeof config.preset === 'string') {
    if (config.preset === 'lark') {
      preset = lark()
    } else if (config.preset === 'none') {
      // Manual configuration
      if (!config.name || !config.authorizeUrl || !config.tokenUrl || !config.userInfoUrl) {
        throw new Error('preset "none" requires name, authorizeUrl, tokenUrl, and userInfoUrl')
      }
      preset = {
        name: config.name,
        authorizeUrl: config.authorizeUrl,
        tokenUrl: config.tokenUrl,
        userInfoUrl: config.userInfoUrl,
        defaultScope: config.scope ?? '',
        extractUser: (data) => ({
          externalId: String(data.id ?? data.sub ?? data.user_id),
          displayName: data.name ?? data.login ?? data.username ?? data.display_name,
          email: data.email,
          avatar: data.avatar_url ?? data.avatar ?? data.picture,
        }),
      }
    } else if (builtinPresets[config.preset]) {
      preset = builtinPresets[config.preset]
    } else {
      throw new Error(`unknown preset: ${config.preset}`)
    }
  } else {
    preset = config.preset
  }

  const providerName = preset.name
  const scope = config.scope ?? preset.defaultScope

  // Extend table (only once, shared across all OAuth providers)
  ctx.model.extend('sso_oauth', {
    identityId: 'unsigned(8)',
    provider: 'string(255)',
    externalId: 'string(255)',
    accessToken: 'string(255)',
    refreshToken: 'string(255)',
    displayName: 'string(255)',
    email: 'string(255)',
    avatar: 'text',
    scope: 'string(255)',
    tokenExpiresAt: 'timestamp',
  }, {
    primary: 'identityId',
    unique: [['provider', 'externalId']],
    foreign: { identityId: ['sso_identity', 'id'] },
  })

  async function exchangeToken(code: string, redirectUri?: string): Promise<any> {
    const body: Record<string, string> = {
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      ...preset.tokenParams,
    }
    if (redirectUri) body.redirect_uri = redirectUri

    // Lark needs app_access_token instead of client_secret
    let headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }

    if (providerName === 'lark') {
      // Lark uses app_access_token auth
      const appTokenRes = await fetch(preset.tokenUrl.replace('/authen/v1/oidc/access_token', '/auth/v3/app_access_token/internal'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app_id: config.clientId, app_secret: config.clientSecret }),
      })
      const appTokenData = await appTokenRes.json() as any
      headers['Authorization'] = `Bearer ${appTokenData.app_access_token}`
      delete body.client_id
      delete body.client_secret
    }

    const res = await fetch(preset.tokenUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    })
    return res.json()
  }

  async function fetchUserInfo(accessToken: string): Promise<any> {
    const headers: Record<string, string> = {}
    let url = preset.userInfoUrl

    if (preset.tokenTransport === 'query') {
      url += `?access_token=${accessToken}`
    } else {
      headers['Authorization'] = `Bearer ${accessToken}`
    }

    const res = await fetch(url, { headers })
    return res.json()
  }

  const provider: SsoProvider = {
    name: providerName,
    interactive: true,
    autoRegister: true,

    getAuthUrl(redirectUri: string, state: string) {
      const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: redirectUri,
        state,
        ...(scope ? { scope } : {}),
        ...(preset.authorizeParams ?? {}),
      })
      // Lark uses app_id instead of client_id
      if (providerName === 'lark') {
        params.delete('client_id')
        params.set('app_id', config.clientId)
      }
      return `${preset.authorizeUrl}?${params}`
    },

    async resolve(credentials: any) {
      const { code, redirect_uri } = credentials
      if (!code) return null

      const tokenData = await exchangeToken(code, redirect_uri) as any
      if (tokenData.error) return null

      const accessToken = tokenData.access_token ?? tokenData.data?.access_token
      if (!accessToken) return null

      const userInfoData = await fetchUserInfo(accessToken)
      const userInfo = preset.extractUser(userInfoData)

      const [existing] = await ctx.model.get('sso_oauth', {
        provider: providerName,
        externalId: userInfo.externalId,
      })

      if (existing) {
        await ctx.model.set('sso_oauth', { identityId: existing.identityId }, {
          accessToken,
          refreshToken: tokenData.refresh_token ?? existing.refreshToken,
          displayName: userInfo.displayName,
          email: userInfo.email,
          avatar: userInfo.avatar,
          scope,
          tokenExpiresAt: tokenData.expires_in
            ? new Date(Date.now() + tokenData.expires_in * 1000)
            : undefined,
        })
        const result: any = { identityId: existing.identityId }
        if (preset.getRelated) {
          result.related = preset.getRelated(userInfoData)
        }
        return result
      }

      return null
    },

    async register(credentials: any) {
      const { identityId, code, redirect_uri } = credentials
      if (!identityId) throw new Error('identityId required')

      const tokenData = await exchangeToken(code, redirect_uri) as any
      const accessToken = tokenData.access_token ?? tokenData.data?.access_token
      const userInfoData = await fetchUserInfo(accessToken)
      const userInfo = preset.extractUser(userInfoData)

      await ctx.model.create('sso_oauth', {
        identityId,
        provider: providerName,
        externalId: userInfo.externalId,
        accessToken,
        refreshToken: tokenData.refresh_token,
        displayName: userInfo.displayName,
        email: userInfo.email,
        avatar: userInfo.avatar,
        scope,
        tokenExpiresAt: tokenData.expires_in
          ? new Date(Date.now() + tokenData.expires_in * 1000)
          : undefined,
      })
      return {}
    },
  }

  // Register callback route
  ctx['sso.server'].route('get', `/callback/${providerName}`, async (routeCtx) => {
    const { code, state } = routeCtx.query
    const result = await provider.resolve!({ code, state, redirect_uri: routeCtx.query.redirect_uri })
    if (result) {
      const identity = await ctx.sso.getIdentity(result.identityId)
      const token = await ctx.sso.createSession(identity!.userId, identity!.id)
      return { token }
    }
    if (provider.autoRegister) {
      const { user, identityId } = await ctx.sso.createUser(providerName)
      await provider.register!({ identityId, code, redirect_uri: routeCtx.query.redirect_uri })
      const token = await ctx.sso.createSession(user.id, identityId)
      return { token }
    }
    return { error: 'ACCOUNT_NOT_FOUND' }
  })

  ctx.sso.register(provider)
}
