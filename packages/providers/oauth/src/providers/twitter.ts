import { OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, SsoOAuth, StandardOAuthConfig, StateEntry } from '../base'
import z from 'schemastery'

class TwitterProvider extends OAuthBaseProvider<TwitterProvider.Config> {
  name = 'twitter'
  protected readonly authorizeUrl = 'https://twitter.com/i/oauth2/authorize'
  protected readonly tokenUrl = 'https://api.twitter.com/2/oauth2/token'
  protected readonly revokeUrl = 'https://api.twitter.com/2/oauth2/revoke'
  protected readonly scope = this.config.scope ?? 'tweet.read users.read offline.access'

  // Twitter uses HTTP Basic auth for client credentials and a form-encoded body.
  protected override async exchangeToken(
    code: string,
    redirectUri: string,
    entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')
    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${basic}`,
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

  // Twitter: RFC 7009 revoke with Basic auth.
  protected async revokeGrant(row: SsoOAuth) {
    const token = row.refreshToken ?? row.accessToken
    if (!token) return
    const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')
    const res = await fetch(this.revokeUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({
        token,
        token_type_hint: row.refreshToken ? 'refresh_token' : 'access_token',
      }),
    })
    if (!res.ok) throw new Error(`twitter revoke failed: HTTP ${res.status}`)
  }
}

namespace TwitterProvider {
  export interface Config extends StandardOAuthConfig {
    preset: 'twitter'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('twitter').required() }),
    StandardOAuthConfig,
  ])
}

export default TwitterProvider
