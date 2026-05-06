import { LarkFeishuConfig, LarkFeishuProvider } from '../shared/lark-feishu'
import z from 'schemastery'

class LarkProvider extends LarkFeishuProvider {
  name = 'lark'
  protected readonly authorizeUrl = 'https://passport.larksuite.com/suite/passport/oauth/authorize'
  protected readonly tokenUrl = 'https://open.larksuite.com/open-apis/authen/v1/oidc/access_token'
  protected readonly userInfoUrl = 'https://open.larksuite.com/open-apis/authen/v1/user_info'
  protected readonly appTokenUrl = 'https://open.larksuite.com/open-apis/auth/v3/app_access_token/internal'
}

namespace LarkProvider {
  export interface Config extends LarkFeishuConfig {
    preset: 'lark'
  }

  export const Config: z<Config> = z.intersect([
    z.object({ preset: z.const('lark').required() }),
    LarkFeishuConfig,
  ])
}

export default LarkProvider
