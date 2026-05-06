import { OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, SsoOAuth, StandardOAuthConfig, StateEntry } from '../base'
import z from 'schemastery'

class WeiboProvider extends OAuthBaseProvider<WeiboProvider.Config> {
  name = 'weibo'
  protected readonly authorizeUrl = 'https://api.weibo.com/oauth2/authorize'
  protected readonly tokenUrl = 'https://api.weibo.com/oauth2/access_token'
  protected readonly revokeUrl = 'https://api.weibo.com/oauth2/revokeoauth2'
  protected readonly userInfoUrl = 'https://api.weibo.com/2/users/show.json'
  protected readonly scope = this.config.scope ?? ''

  protected override readonly pkceMethod = false

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

  // Weibo: GET /oauth2/revokeoauth2?access_token=<token>.
  protected async revokeGrant(row: SsoOAuth) {
    if (!row.accessToken) return
    const res = await fetch(`${this.revokeUrl}?access_token=${encodeURIComponent(row.accessToken)}`)
    if (!res.ok) throw new Error(`weibo revoke failed: HTTP ${res.status}`)
  }
}

namespace WeiboProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'weibo'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('weibo').required() }),
    StandardOAuthConfig,
  ])
}

export default WeiboProvider
