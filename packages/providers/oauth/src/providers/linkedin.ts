import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'
import z from 'schemastery'

class LinkedinProvider extends OAuthBaseProvider<LinkedinProvider.Config> {
  name = 'linkedin'
  protected readonly authorizeUrl = 'https://www.linkedin.com/oauth/v2/authorization'
  protected readonly tokenUrl = 'https://www.linkedin.com/oauth/v2/accessToken'
  protected readonly userInfoUrl = 'https://api.linkedin.com/v2/userinfo'
  protected readonly scope = this.config.scope ?? 'openid email profile'

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.sub,
      display: data.name,
      email: data.email,
      avatar: data.picture,
    }
  }

  // No revokeGrant — LinkedIn does not expose a programmatic revoke endpoint;
  // users must remove the app grant via linkedin.com/psettings/permitted-services.
}

namespace LinkedinProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'linkedin'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('linkedin').required() }),
    StandardOAuthConfig,
  ])
}

export default LinkedinProvider
