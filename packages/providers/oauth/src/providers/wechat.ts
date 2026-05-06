import { OAuthBaseConfig, OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, StateEntry } from '../base'

class WeChatProvider extends OAuthBaseProvider<WeChatProvider.Config> {
  name = 'wechat'
  protected readonly authorizeUrl = 'https://open.weixin.qq.com/connect/qrconnect'
  protected readonly tokenUrl = 'https://api.weixin.qq.com/sns/oauth2/access_token'
  protected get scope() { return this.config.scope ?? 'snsapi_login' }
  protected override get usesPkce() { return false }

  protected override get clientId() { return this.config.appId }
  protected override get clientSecret() { return this.config.appSecret }

  protected override async exchangeToken(
    code: string,
    _redirectUri: string,
    _entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const params = new URLSearchParams({
      appid: this.config.appId,
      secret: this.config.appSecret,
      code,
      grant_type: 'authorization_code',
    })
    const res = await fetch(`${this.tokenUrl}?${params}`)
    const data = await res.json() as any
    if (data.errcode) throw new Error(`wechat token exchange failed: ${data.errcode} ${data.errmsg}`)
    return data
  }

  // WeChat's userInfo needs BOTH access_token AND openid (returned on token step).
  protected override async fetchUserInfo(tokenData: any): Promise<OAuthUserInfo> {
    const params = new URLSearchParams({ access_token: tokenData.access_token, openid: tokenData.openid })
    const res = await fetch(`https://api.weixin.qq.com/sns/userinfo?${params}`)
    const user = await res.json() as any
    return {
      externalId: tokenData.openid,
      display: user.nickname,
      avatar: user.headimgurl,
      unionId: tokenData.unionid,
      raw: user,
    }
  }

  // WeChat's authorize URL uses `appid` (not `client_id`) and requires a
  // `#wechat_redirect` fragment suffix. No PKCE.
  protected override buildAuthorizeParams(
    redirectUri: string,
    state: string,
    _link: { userId: number } | undefined,
    _extras: Record<string, string>,
  ): URLSearchParams {
    return new URLSearchParams({
      appid: this.config.appId,
      redirect_uri: redirectUri,
      response_type: 'code',
      scope: this.scope,
      state,
    })
  }

  override async getAuthUrl(
    redirectUri: string,
    state: string,
    link: { userId: number } | undefined,
    ctx: any,
  ): Promise<string> {
    const url = await super.getAuthUrl(redirectUri, state, link, ctx)
    return `${url}#wechat_redirect`
  }
}

namespace WeChatProvider {
  export interface Config extends OAuthBaseConfig {
    appId: string
    appSecret: string
  }
}

export default WeChatProvider
