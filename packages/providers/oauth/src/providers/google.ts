import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

class GoogleProvider extends OAuthBaseProvider<GoogleProvider.Config> {
  name = 'google'
  protected readonly authorizeUrl = 'https://accounts.google.com/o/oauth2/v2/auth'
  protected readonly tokenUrl = 'https://oauth2.googleapis.com/token'
  protected get userInfoUrl() { return 'https://www.googleapis.com/oauth2/v2/userinfo' }
  protected get scope() { return this.config.scope ?? 'openid email profile' }

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
}

namespace GoogleProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default GoogleProvider
