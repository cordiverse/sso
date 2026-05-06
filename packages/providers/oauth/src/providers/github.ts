import { OAuthBaseProvider, OAuthUserInfo, SsoOAuth, StandardOAuthConfig } from '../base'
import z from 'schemastery'

class GithubProvider extends OAuthBaseProvider<GithubProvider.Config> {
  name = 'github'
  protected readonly authorizeUrl = 'https://github.com/login/oauth/authorize'
  protected readonly tokenUrl = 'https://github.com/login/oauth/access_token'
  protected readonly userInfoUrl = 'https://api.github.com/user'
  protected readonly scope = this.config.scope ?? 'read:user user:email'

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: String(data.id),
      name: data.login,
      display: data.name ?? data.login,
      email: data.email,
      avatar: data.avatar_url,
    }
  }

  // GitHub: DELETE /applications/:client_id/grant with Basic auth.
  protected async revokeGrant(row: SsoOAuth) {
    if (!row.accessToken) return
    const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')
    const res = await fetch(`https://api.github.com/applications/${this.clientId}/grant`, {
      method: 'DELETE',
      headers: {
        Authorization: `Basic ${basic}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ access_token: row.accessToken }),
    })
    if (!res.ok && res.status !== 404) {
      throw new Error(`github revoke failed: HTTP ${res.status}`)
    }
  }
}

namespace GithubProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'github'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('github').required() }),
    StandardOAuthConfig,
  ])
}

export default GithubProvider
