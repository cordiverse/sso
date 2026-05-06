import { OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, StandardOAuthConfig, StateEntry } from '../base'

/**
 * Shared scaffolding for Lark (open.larksuite.com) / Feishu (open.feishu.cn).
 * Same OAuth protocol; only the four base URLs differ. The two concrete
 * subclasses set `name` and the URL fields.
 */
export abstract class LarkFeishuProvider extends OAuthBaseProvider<StandardOAuthConfig> {
  protected abstract readonly appTokenUrl: string
  protected readonly scope = this.config.scope ?? ''

  // Lark/Feishu authorize URL uses `app_id` (not `client_id`).
  protected override buildAuthorizeParams(
    redirectUri: string,
    state: string,
    _link: { userId: number } | undefined,
    extras: Record<string, string>,
  ): URLSearchParams {
    return new URLSearchParams({
      response_type: 'code',
      app_id: this.clientId,
      redirect_uri: redirectUri,
      state,
      ...(this.scope ? { scope: this.scope } : {}),
      ...extras,
    })
  }

  // Two-stage token exchange: first fetch an app_access_token, then call the
  // user-token endpoint with that app token in the Authorization header (and
  // no client_id/secret in body).
  protected override async exchangeToken(
    code: string,
    _redirectUri: string,
    _entry: PkceEntry | StateEntry,
  ): Promise<OAuthTokenResponse> {
    const appTokenRes = await fetch(this.appTokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ app_id: this.clientId, app_secret: this.clientSecret }),
    })
    const appTokenData = await appTokenRes.json() as any
    const appToken = appTokenData.app_access_token
    if (!appToken) throw new Error(`${this.name}: failed to obtain app_access_token`)

    const res = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${appToken}`,
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
      }),
    })
    const data = await res.json() as any
    // Lark wraps the token payload inside `data`.
    const payload = data.data ?? data
    return {
      access_token: payload.access_token,
      refresh_token: payload.refresh_token,
      expires_in: payload.expires_in,
      ...payload,
    }
  }

  protected extractUser(data: any): OAuthUserInfo {
    const user = data.data ?? data
    return {
      externalId: user.open_id,
      display: user.name,
      email: user.email,
      avatar: user.avatar_url,
    }
  }
}
