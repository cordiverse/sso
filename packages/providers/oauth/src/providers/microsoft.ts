import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

class MicrosoftProvider extends OAuthBaseProvider<MicrosoftProvider.Config> {
  name = 'microsoft'
  protected readonly authorizeUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
  protected readonly tokenUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
  protected get userInfoUrl() { return 'https://graph.microsoft.com/v1.0/me' }
  protected get scope() { return this.config.scope ?? 'openid email profile User.Read' }

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
  // No revokeGrant — Microsoft doesn't expose a programmatic grant-revoke API;
  // users must remove the app consent manually from their account settings.
}

namespace MicrosoftProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default MicrosoftProvider
