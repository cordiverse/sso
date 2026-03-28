import { Context } from 'cordis'
import { SmsService } from '@cordisjs/sms'

export interface Config extends SmsService.Config {
  accountSid: string
  authToken: string
  from: string
}

export class TwilioSmsService extends SmsService {
  constructor(ctx: Context, public config: Config) {
    super(ctx, config)
  }

  async send(phone: string, content: string) {
    const { accountSid, authToken, from } = this.config
    const auth = Buffer.from(`${accountSid}:${authToken}`).toString('base64')
    const res = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          To: phone,
          From: from,
          Body: content,
        }),
      },
    )
    if (!res.ok) {
      const err = await res.json() as any
      throw new Error(`Twilio error: ${err.message ?? res.statusText}`)
    }
  }
}

export default TwilioSmsService
