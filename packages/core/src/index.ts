import { Context, Service } from 'cordis'

export default class SSO extends Service {
  constructor(ctx: Context) {
    super(ctx, 'sso')
  }
}
