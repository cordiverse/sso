import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

class LinkedinProvider extends OAuthBaseProvider<LinkedinProvider.Config> {
  name = 'linkedin'
  protected readonly authorizeUrl = 'https://www.linkedin.com/oauth/v2/authorization'
  protected readonly tokenUrl = 'https://www.linkedin.com/oauth/v2/accessToken'
  protected get userInfoUrl() { return 'https://api.linkedin.com/v2/userinfo' }
  protected get scope() { return this.config.scope ?? 'openid email profile' }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.sub,
      display: data.name,
      email: data.email,
      avatar: data.picture,
    }
  }
}

namespace LinkedinProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default LinkedinProvider
