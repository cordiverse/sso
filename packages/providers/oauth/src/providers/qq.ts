import { OAuthBaseConfig, OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, StateEntry } from '../base'
import z from 'schemastery'

function parseCallback(text: string): any {
  const match = text.match(/callback\(\s*(.*?)\s*\);?/s)
  if (match) return JSON.parse(match[1])
  return JSON.parse(text)
}

class QqProvider extends OAuthBaseProvider<QqProvider.Config> {
  name = 'qq'
  protected readonly authorizeUrl = 'https://graph.qq.com/oauth2.0/authorize'
  protected readonly tokenUrl = 'https://graph.qq.com/oauth2.0/token'
  protected readonly scope = 'get_user_info'

  protected override get clientId() { return this.config.appId }
  protected override get clientSecret() { return this.config.appKey }

  protected override readonly pkceMethod = false

  // QQ's token endpoint uses query-string params and returns either a `callback(...)`
  // JSONP error payload or a URL-encoded form on success.
  protected override async exchangeToken(
    code: string,
    redirectUri: string,
    _entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code,
      redirect_uri: redirectUri,
    })
    const res = await fetch(`${this.tokenUrl}?${params}`)
    const text = await res.text()
    if (text.includes('callback')) {
      const data = parseCallback(text)
      if (data.error) throw new Error(data.error_description)
    }
    const result: any = {}
    new URLSearchParams(text).forEach((v, k) => (result[k] = v))
    return result
  }

  // QQ requires two stages for userInfo: first /oauth2.0/me returns openid + unionid,
  // then /user/get_user_info returns the display fields. Both JSONP.
  protected override async fetchUserInfo(tokenData: OAuthTokenResponse): Promise<OAuthUserInfo> {
    const accessToken = tokenData.access_token!
    const meRes = await fetch(`https://graph.qq.com/oauth2.0/me?access_token=${accessToken}&unionid=1`)
    const meData = parseCallback(await meRes.text())

    const params = new URLSearchParams({
      access_token: accessToken,
      oauth_consumer_key: this.clientId,
      openid: meData.openid,
    })
    const userRes = await fetch(`https://graph.qq.com/user/get_user_info?${params}`)
    const user = await userRes.json() as any

    return {
      externalId: meData.openid,
      display: user.nickname,
      avatar: user.figureurl_qq_2 ?? user.figureurl_qq_1,
      unionId: meData.unionid,
      raw: user,
    }
  }

  // No revokeGrant — QQ Connect does not expose a programmatic revoke endpoint;
  // users must revoke the app authorization from their QQ security console.
}

namespace QqProvider {
  export interface Config extends OAuthBaseConfig {
    preset: 'qq'
    appId: string
    appKey: string
  }

  export const Config: z<Config> = z.intersect([
    z.object({
      preset: z.const('qq').required(),
      appId: z.string().required().description('QQ 互联应用 App ID。'),
      appKey: z.string().required().role('secret').description('QQ 互联应用 App Key。'),
    }),
    OAuthBaseConfig,
  ])
}

export default QqProvider
