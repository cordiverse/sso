import { OAuthBaseProvider, OAuthTokenResponse, OAuthUserInfo, PkceEntry, StandardOAuthConfig, StateEntry } from '../base'

interface Domain {
  authorizeUrl: string
  tokenUrl: string
  userInfoUrl: string
  appTokenUrl: string
}

const domains: Record<'lark' | 'feishu', Domain> = {
  lark: {
    authorizeUrl: 'https://passport.larksuite.com/suite/passport/oauth/authorize',
    tokenUrl: 'https://open.larksuite.com/open-apis/authen/v1/oidc/access_token',
    userInfoUrl: 'https://open.larksuite.com/open-apis/authen/v1/user_info',
    appTokenUrl: 'https://open.larksuite.com/open-apis/auth/v3/app_access_token/internal',
  },
  feishu: {
    authorizeUrl: 'https://passport.feishu.cn/suite/passport/oauth/authorize',
    tokenUrl: 'https://open.feishu.cn/open-apis/authen/v1/oidc/access_token',
    userInfoUrl: 'https://open.feishu.cn/open-apis/authen/v1/user_info',
    appTokenUrl: 'https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal',
  },
}

class LarkProvider extends OAuthBaseProvider<LarkProvider.Config> {
  private get domain() { return this.config.domain ?? 'lark' }
  get name() { return this.domain }
  protected get authorizeUrl() { return domains[this.domain].authorizeUrl }
  protected get tokenUrl() { return domains[this.domain].tokenUrl }
  protected get userInfoUrl() { return domains[this.domain].userInfoUrl }
  private get appTokenUrl() { return domains[this.domain].appTokenUrl }
  protected get scope() { return this.config.scope ?? '' }

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

  // Lark/Feishu: two-stage token exchange. First fetch an app_access_token
  // from `/auth/v3/app_access_token/internal`, then call the user-token
  // endpoint with that app token in the Authorization header (and no
  // client_id/secret in body).
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

namespace LarkProvider {
  export interface Config extends StandardOAuthConfig {
    /**
     * `lark` (international, open.larksuite.com) or `feishu` (China, open.feishu.cn).
     * Defaults to `lark`. Both use the same protocol; only the domain differs.
     */
    domain?: 'lark' | 'feishu'
  }
}

export default LarkProvider
