import { OAuthBaseProvider, OAuthUserInfo, SsoOAuth, StandardOAuthConfig } from '../base'
import z from 'schemastery'

class SlackProvider extends OAuthBaseProvider<SlackProvider.Config> {
  name = 'slack'
  protected readonly authorizeUrl = 'https://slack.com/openid/connect/authorize'
  protected readonly tokenUrl = 'https://slack.com/api/openid.connect.token'
  protected readonly revokeUrl = 'https://slack.com/api/auth.revoke'
  protected readonly userInfoUrl = 'https://slack.com/api/openid.connect.userInfo'
  protected readonly scope = this.config.scope ?? 'openid email profile'

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.sub ?? data['https://slack.com/user_id'],
      display: data.name,
      email: data.email,
      avatar: data.picture,
    }
  }

  // Slack: POST auth.revoke with `token=<access_token>`; JSON { ok } response.
  protected async revokeGrant(row: SsoOAuth) {
    if (!row.accessToken) return
    const res = await fetch(this.revokeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: row.accessToken }),
    })
    const data = await res.json() as any
    if (!data.ok && data.error !== 'token_revoked' && data.error !== 'invalid_auth') {
      throw new Error(`slack revoke failed: ${data.error ?? 'unknown'}`)
    }
  }
}

namespace SlackProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'slack'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('slack').required() }),
    StandardOAuthConfig,
  ])
}

export default SlackProvider
