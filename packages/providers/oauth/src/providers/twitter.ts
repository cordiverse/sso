import { OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, StandardOAuthConfig, StateEntry } from '../base'

class TwitterProvider extends OAuthBaseProvider<TwitterProvider.Config> {
  name = 'twitter'
  protected readonly authorizeUrl = 'https://twitter.com/i/oauth2/authorize'
  protected readonly tokenUrl = 'https://api.twitter.com/2/oauth2/token'
  protected get scope() { return this.config.scope ?? 'tweet.read users.read offline.access' }

  // Twitter uses HTTP Basic auth for client credentials and a form-encoded body.
  protected override async exchangeToken(
    code: string,
    redirectUri: string,
    entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const basicAuth = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')
    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${basicAuth}`,
      },
      body: new URLSearchParams({
        code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
        code_verifier: (entry as PkceEntry).codeVerifier,
      }),
    })
    return res.json() as Promise<OAuthTokenResponse>
  }

  // /2/users/me wraps the response in a `data` key and needs explicit user.fields.
  protected override async fetchUserInfo(tokenData: OAuthTokenResponse): Promise<OAuthUserInfo> {
    const res = await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    })
    const user = ((await res.json()) as any).data
    return {
      externalId: user.id,
      name: user.username,
      display: user.name || user.username,
      avatar: user.profile_image_url,
      raw: user,
    }
  }
}

namespace TwitterProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default TwitterProvider
