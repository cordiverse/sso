import { OAuthBaseProvider, OAuthUserInfo, SsoOAuth, StandardOAuthConfig } from '../base'
import z from 'schemastery'

class GitlabProvider extends OAuthBaseProvider<GitlabProvider.Config> {
  name = 'gitlab'
  protected readonly authorizeUrl = 'https://gitlab.com/oauth/authorize'
  protected readonly tokenUrl = 'https://gitlab.com/oauth/token'
  protected readonly revokeUrl = 'https://gitlab.com/oauth/revoke'
  protected readonly userInfoUrl = 'https://gitlab.com/api/v4/user'
  protected readonly scope = this.config.scope ?? 'read_user'

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: String(data.id),
      name: data.username,
      display: data.name ?? data.username,
      email: data.email,
      avatar: data.avatar_url,
    }
  }

  // GitLab: RFC 7009 revoke; credentials sent in body.
  protected async revokeGrant(row: SsoOAuth) {
    const token = row.refreshToken ?? row.accessToken
    if (!token) return
    const res = await fetch(this.revokeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        token,
        token_type_hint: row.refreshToken ? 'refresh_token' : 'access_token',
      }),
    })
    if (!res.ok) throw new Error(`gitlab revoke failed: HTTP ${res.status}`)
  }
}

namespace GitlabProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'gitlab'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('gitlab').required() }),
    StandardOAuthConfig,
  ])
}

export default GitlabProvider
