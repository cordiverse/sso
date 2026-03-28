import { Context } from 'cordis'
import { createHmac } from 'node:crypto'
import { SmsService } from '@cordisjs/sms'

export interface Config extends SmsService.Config {
  secretId: string
  secretKey: string
  sdkAppId: string
  signName: string
  templateId: string
  region?: string
}

export class TencentSmsService extends SmsService {
  constructor(ctx: Context, public config: Config) {
    super(ctx, config)
  }

  async send(phone: string, content: string) {
    const {
      secretId,
      secretKey,
      sdkAppId,
      signName,
      templateId,
      region = 'ap-guangzhou',
    } = this.config

    // Tencent Cloud API v3 (TC3-HMAC-SHA256)
    const service = 'sms'
    const host = 'sms.tencentcloudapi.com'
    const now = Math.floor(Date.now() / 1000)
    const date = new Date(now * 1000).toISOString().slice(0, 10)

    // Ensure phone has country code
    const phoneNumber = phone.startsWith('+') ? phone : `+86${phone}`

    const payload = JSON.stringify({
      SmsSdkAppId: sdkAppId,
      SignName: signName,
      TemplateId: templateId,
      TemplateParamSet: [content],
      PhoneNumberSet: [phoneNumber],
    })

    const hashedPayload = createHmac('sha256', '').update(payload).copy().digest('hex')
    // Actually need SHA256 hash, not HMAC
    const { createHash } = await import('node:crypto')
    const payloadHash = createHash('sha256').update(payload).digest('hex')

    const canonicalRequest = [
      'POST',
      '/',
      '',
      `content-type:application/json; charset=utf-8\nhost:${host}\n`,
      'content-type;host',
      payloadHash,
    ].join('\n')

    const credentialScope = `${date}/${service}/tc3_request`
    const stringToSign = [
      'TC3-HMAC-SHA256',
      String(now),
      credentialScope,
      createHash('sha256').update(canonicalRequest).digest('hex'),
    ].join('\n')

    const secretDate = createHmac('sha256', `TC3${secretKey}`).update(date).digest()
    const secretService = createHmac('sha256', secretDate).update(service).digest()
    const secretSigning = createHmac('sha256', secretService).update('tc3_request').digest()
    const signature = createHmac('sha256', secretSigning).update(stringToSign).digest('hex')

    const authorization = `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=content-type;host, Signature=${signature}`

    const res = await fetch(`https://${host}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Host': host,
        'X-TC-Action': 'SendSms',
        'X-TC-Version': '2021-01-11',
        'X-TC-Timestamp': String(now),
        'X-TC-Region': region,
        'Authorization': authorization,
      },
      body: payload,
    })

    const data = await res.json() as any
    const response = data.Response
    if (response?.Error) {
      throw new Error(`Tencent SMS error: ${response.Error.Message}`)
    }
    const status = response?.SendStatusSet?.[0]
    if (status && status.Code !== 'Ok') {
      throw new Error(`Tencent SMS error: ${status.Message}`)
    }
  }
}

export default TencentSmsService
