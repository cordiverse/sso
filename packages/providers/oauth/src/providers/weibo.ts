import { OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, StandardOAuthConfig, StateEntry } from '../base'

class WeiboProvider extends OAuthBaseProvider<WeiboProvider.Config> {
  name = 'weibo'
  protected readonly authorizeUrl = 'https://api.weibo.com/oauth2/authorize'
  protected readonly tokenUrl = 'https://api.weibo.com/oauth2/access_token'
  protected get userInfoUrl() { return 'https://api.weibo.com/2/users/show.json' }
  protected get scope() { return this.config.scope ?? '' }
  protected override get usesPkce() { return false }

  protected override async exchangeToken(
    code: string,
    redirectUri: string,
    _entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const body = new URLSearchParams({
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    })
    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    return res.json() as Promise<OAuthTokenResponse>
  }

  // Weibo's userInfo requires `access_token` + `uid` as query params, not Bearer.
  protected override async fetchUserInfo(tokenData: OAuthTokenResponse): Promise<OAuthUserInfo> {
    const uid = (tokenData as any).uid ?? (tokenData as any).id
    const params = new URLSearchParams({ access_token: tokenData.access_token!, uid: String(uid) })
    const res = await fetch(`${this.userInfoUrl}?${params}`)
    const user = await res.json() as any
    return {
      externalId: String(user.id ?? user.uid),
      name: user.screen_name,
      display: user.screen_name ?? user.name,
      avatar: user.avatar_large ?? user.profile_image_url,
      raw: user,
    }
  }
}

namespace WeiboProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default WeiboProvider
