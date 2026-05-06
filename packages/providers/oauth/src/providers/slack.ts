import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

class SlackProvider extends OAuthBaseProvider<SlackProvider.Config> {
  name = 'slack'
  protected readonly authorizeUrl = 'https://slack.com/openid/connect/authorize'
  protected readonly tokenUrl = 'https://slack.com/api/openid.connect.token'
  protected get userInfoUrl() { return 'https://slack.com/api/openid.connect.userInfo' }
  protected get scope() { return this.config.scope ?? 'openid email profile' }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.sub ?? data['https://slack.com/user_id'],
      display: data.name,
      email: data.email,
      avatar: data.picture,
    }
  }
}

namespace SlackProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default SlackProvider
