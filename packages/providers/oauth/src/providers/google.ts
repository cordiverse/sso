import { OAuthBaseProvider, OAuthUserInfo, SsoOAuth, StandardOAuthConfig } from '../base'

class GoogleProvider extends OAuthBaseProvider<GoogleProvider.Config> {
  name = 'google'
  protected readonly authorizeUrl = 'https://accounts.google.com/o/oauth2/v2/auth'
  protected readonly tokenUrl = 'https://oauth2.googleapis.com/token'
  protected readonly revokeUrl = 'https://oauth2.googleapis.com/revoke'
  protected readonly userInfoUrl = 'https://www.googleapis.com/oauth2/v2/userinfo'
  protected readonly scope = this.config.scope ?? 'openid email profile'

  // Google wants access_type=offline + prompt=consent to issue a refresh_token.
  protected override buildAuthorizeParams(
    redirectUri: string,
    state: string,
    link: { userId: number } | undefined,
    extras: Record<string, string>,
    payload?: any,
  ): URLSearchParams {
    const params = super.buildAuthorizeParams(redirectUri, state, link, extras, payload)
    params.set('access_type', 'offline')
    params.set('prompt', 'consent')
    return params
  }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.sub ?? data.id,
      display: data.name,
      email: data.email,
      avatar: data.picture,
    }
  }

  // Google: POST https://oauth2.googleapis.com/revoke?token=<token>. No auth
  // header needed (token identifies the app). Revoking refresh_token also
  // kills the access_token.
  protected async revokeGrant(row: SsoOAuth) {
    const token = row.refreshToken ?? row.accessToken
    if (!token) return
    const res = await fetch(this.revokeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token }),
    })
    if (!res.ok) throw new Error(`google revoke failed: HTTP ${res.status}`)
  }
}

namespace GoogleProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default GoogleProvider
