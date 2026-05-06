import { OAuthBaseProvider, OAuthUserInfo, SsoOAuth, StandardOAuthConfig } from '../base'
import z from 'schemastery'

class FacebookProvider extends OAuthBaseProvider<FacebookProvider.Config> {
  name = 'facebook'
  protected readonly authorizeUrl = 'https://www.facebook.com/v21.0/dialog/oauth'
  protected readonly tokenUrl = 'https://graph.facebook.com/v21.0/oauth/access_token'
  protected readonly userInfoUrl = 'https://graph.facebook.com/me?fields=id,name,email,picture'
  protected readonly scope = this.config.scope ?? 'email public_profile'

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.id,
      display: data.name,
      email: data.email,
      avatar: data.picture?.data?.url,
    }
  }

  // Facebook: DELETE /me/permissions with Bearer — revokes all permissions.
  protected async revokeGrant(row: SsoOAuth) {
    if (!row.accessToken) return
    const res = await fetch(`https://graph.facebook.com/v21.0/me/permissions?access_token=${encodeURIComponent(row.accessToken)}`, {
      method: 'DELETE',
    })
    if (!res.ok) throw new Error(`facebook revoke failed: HTTP ${res.status}`)
  }
}

namespace FacebookProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'facebook'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('facebook').required() }),
    StandardOAuthConfig,
  ])
}

export default FacebookProvider
