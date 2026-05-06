import { OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, StandardOAuthConfig, StateEntry } from '../base'
import z from 'schemastery'

class DingtalkProvider extends OAuthBaseProvider<DingtalkProvider.Config> {
  name = 'dingtalk'
  protected readonly authorizeUrl = 'https://login.dingtalk.com/oauth2/auth'
  protected readonly tokenUrl = 'https://api.dingtalk.com/v1.0/oauth2/userAccessToken'
  protected readonly userInfoUrl = 'https://api.dingtalk.com/v1.0/contact/users/me'
  protected readonly scope = this.config.scope ?? 'openid'

  // DingTalk's token endpoint expects the body parameter in camelCase
  // (`grantType`) instead of the RFC 6749 `grant_type`, and uses its own
  // field names for credentials.
  protected override async exchangeToken(
    code: string,
    redirectUri: string,
    _entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        clientId: this.clientId,
        clientSecret: this.clientSecret,
        code,
        redirectUri,
        grantType: 'authorization_code',
      }),
    })
    const data = await res.json() as any
    // DingTalk returns `accessToken` not `access_token`; normalize to our shape.
    return {
      access_token: data.accessToken,
      refresh_token: data.refreshToken,
      expires_in: data.expireIn,
      ...data,
    }
  }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.openId ?? data.unionId,
      display: data.nick,
      email: data.email,
      avatar: data.avatarUrl,
      unionId: data.unionId,
    }
  }

  // No revokeGrant — DingTalk does not expose a programmatic grant-revoke API;
  // users must disable the app from their workspace admin console.
}

namespace DingtalkProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'dingtalk'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('dingtalk').required() }),
    StandardOAuthConfig,
  ])
}

export default DingtalkProvider
