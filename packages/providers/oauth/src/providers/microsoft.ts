import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'
import z from 'schemastery'

class MicrosoftProvider extends OAuthBaseProvider<MicrosoftProvider.Config> {
  name = 'microsoft'
  protected readonly authorizeUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
  protected readonly tokenUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
  protected readonly userInfoUrl = 'https://graph.microsoft.com/v1.0/me'
  protected readonly scope = this.config.scope ?? 'openid email profile User.Read'

  protected override buildAuthorizeParams(
    redirectUri: string,
    state: string,
    link: { userId: number } | undefined,
    extras: Record<string, string>,
    payload?: any,
  ): URLSearchParams {
    const params = super.buildAuthorizeParams(redirectUri, state, link, extras, payload)
    params.set('response_mode', 'query')
    return params
  }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.sub ?? data.id,
      display: data.name ?? data.displayName,
      email: data.email ?? data.mail ?? data.userPrincipalName ?? data.preferred_username,
    }
  }

  // No revokeGrant — Microsoft Entra does not expose a per-app programmatic
  // revoke. Admins can revoke tenant-wide via Graph, but there's no per-user
  // consent-withdrawal endpoint. Users must remove the app from myapps.microsoft.com.
}

namespace MicrosoftProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'microsoft'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('microsoft').required() }),
    StandardOAuthConfig,
  ])
}

export default MicrosoftProvider
