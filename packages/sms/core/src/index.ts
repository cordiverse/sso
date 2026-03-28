import { Context, Service } from 'cordis'

declare module 'cordis' {
  interface Context {
    sms: SmsService
  }
}

export abstract class SmsService extends Service {
  constructor(ctx: Context, public config: SmsService.Config = {}) {
    super(ctx, 'sms')
  }

  /** Send an SMS message to the given phone number */
  abstract send(phone: string, content: string): Promise<void>
}

export namespace SmsService {
  export interface Config {
    /** Default sender ID / phone number (if supported by provider) */
    from?: string
  }
}

export default SmsService
