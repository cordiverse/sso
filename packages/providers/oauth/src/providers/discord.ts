import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

class DiscordProvider extends OAuthBaseProvider<DiscordProvider.Config> {
  name = 'discord'
  protected readonly authorizeUrl = 'https://discord.com/oauth2/authorize'
  protected readonly tokenUrl = 'https://discord.com/api/oauth2/token'
  protected get userInfoUrl() { return 'https://discord.com/api/users/@me' }
  protected get scope() { return this.config.scope ?? 'identify email' }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: data.id,
      name: data.username,
      display: data.global_name ?? data.username,
      email: data.email,
      avatar: data.avatar ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png` : undefined,
    }
  }
}

namespace DiscordProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default DiscordProvider
