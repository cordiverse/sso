import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

class FacebookProvider extends OAuthBaseProvider<FacebookProvider.Config> {
  name = 'facebook'
  protected readonly authorizeUrl = 'https://www.facebook.com/v21.0/dialog/oauth'
  protected readonly tokenUrl = 'https://graph.facebook.com/v21.0/oauth/access_token'
  protected get userInfoUrl() { return 'https://graph.facebook.com/me?fields=id,name,email,picture' }
  protected get scope() { return this.config.scope ?? 'email public_profile' }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.id,
      display: data.name,
      email: data.email,
      avatar: data.picture?.data?.url,
    }
  }
}

namespace FacebookProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default FacebookProvider
