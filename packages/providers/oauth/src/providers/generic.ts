import { OAuthBaseProvider, OAuthUserInfo, StandardOAuthConfig } from '../base'

/**
 * Generic RFC 6749 OAuth 2 provider. For custom / self-hosted IdPs where the
 * four URLs and standard credential fields are enough — fill them into config
 * and go. For anything weirder (ES256 client_secret, two-stage token,
 * custom response shapes), write a dedicated subclass instead.
 *
 * `extractUser` tries a handful of common field names (sub/id/user_id,
 * name/login/username/display_name, avatar_url/picture). If your IdP doesn't
 * match, either massage the response upstream or fork into a new subclass.
 */
class GenericProvider extends OAuthBaseProvider<GenericProvider.Config> {
  get name() { return this.config.name }
  protected get authorizeUrl() { return this.config.authorizeUrl }
  protected get tokenUrl() { return this.config.tokenUrl }
  protected get userInfoUrl() { return this.config.userInfoUrl }
  protected get scope() { return this.config.scope ?? '' }
  protected override get usesPkce() { return this.config.pkce !== false }

  protected extractUser(data: any): OAuthUserInfo {
    return {
      externalId: String(data.id ?? data.sub ?? data.user_id),
      name: data.login ?? data.username ?? data.preferred_username,
      display: data.name ?? data.display_name ?? data.login ?? data.username,
      email: data.email,
      avatar: data.avatar_url ?? data.avatar ?? data.picture,
    }
  }
}

namespace GenericProvider {
  export interface Config extends StandardOAuthConfig {
    name: string
    authorizeUrl: string
    tokenUrl: string
    userInfoUrl: string
    /** Optional: disable PKCE for IdPs that don't support it. Defaults to true. */
    pkce?: boolean
  }
}

export default GenericProvider
