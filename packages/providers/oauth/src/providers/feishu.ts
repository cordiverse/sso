import { StandardOAuthConfig } from '../base'
import { LarkFeishuProvider } from '../shared/lark-feishu'

class FeishuProvider extends LarkFeishuProvider {
  name = 'feishu'
  protected readonly authorizeUrl = 'https://passport.feishu.cn/suite/passport/oauth/authorize'
  protected readonly tokenUrl = 'https://open.feishu.cn/open-apis/authen/v1/oidc/access_token'
  protected readonly userInfoUrl = 'https://open.feishu.cn/open-apis/authen/v1/user_info'
  protected readonly appTokenUrl = 'https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal'
}

namespace FeishuProvider {
  export interface Config extends StandardOAuthConfig {}
}

export default FeishuProvider
