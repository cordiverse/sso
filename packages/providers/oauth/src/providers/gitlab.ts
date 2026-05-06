import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

class GitlabProvider extends OAuthBaseProvider<GitlabProvider.Config> {
  name = 'gitlab'
  protected readonly authorizeUrl = 'https://gitlab.com/oauth/authorize'
  protected readonly tokenUrl = 'https://gitlab.com/oauth/token'
  protected get userInfoUrl() { return 'https://gitlab.com/api/v4/user' }
  protected get scope() { return this.config.scope ?? 'read_user' }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: String(data.id),
      name: data.username,
      display: data.name ?? data.username,
      email: data.email,
      avatar: data.avatar_url,
    }
  }
}

namespace GitlabProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default GitlabProvider
