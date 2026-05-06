import { OAuthBaseProvider, OAuthUserInfo, SsoOAuth, StandardOAuthConfig } from '../base'

class DiscordProvider extends OAuthBaseProvider<DiscordProvider.Config> {
  name = 'discord'
  protected readonly authorizeUrl = 'https://discord.com/oauth2/authorize'
  protected readonly tokenUrl = 'https://discord.com/api/oauth2/token'
  protected readonly revokeUrl = 'https://discord.com/api/oauth2/token/revoke'
  protected readonly userInfoUrl = 'https://discord.com/api/users/@me'
  protected readonly scope = this.config.scope ?? 'identify email'

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.id,
      name: data.username,
      display: data.global_name ?? data.username,
      email: data.email,
      avatar: data.avatar ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png` : undefined,
    }
  }

  // Discord: RFC 7009 revoke with HTTP Basic auth.
  protected async revokeGrant(row: SsoOAuth) {
    if (!row.accessToken) return
    const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')
    const res = await fetch(this.revokeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({
        token: row.accessToken,
        token_type_hint: 'access_token',
      }),
    })
    if (!res.ok) throw new Error(`discord revoke failed: HTTP ${res.status}`)
  }
}

namespace DiscordProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default DiscordProvider
