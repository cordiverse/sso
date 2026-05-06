import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

class GiteeProvider extends OAuthBaseProvider<GiteeProvider.Config> {
  name = 'gitee'
  protected readonly authorizeUrl = 'https://gitee.com/oauth/authorize'
  protected readonly tokenUrl = 'https://gitee.com/oauth/token'
  protected get userInfoUrl() { return 'https://gitee.com/api/v5/user' }
  protected get scope() { return this.config.scope ?? 'user_info' }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: String(data.id),
      name: data.login,
      display: data.name ?? data.login,
      email: data.email,
      avatar: data.avatar_url,
    }
  }
}

namespace GiteeProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default GiteeProvider
