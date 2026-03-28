import { Context } from 'cordis'
import { createHmac, randomUUID } from 'node:crypto'
import { SmsService } from '@cordisjs/sms'

export interface Config extends SmsService.Config {
  accessKeyId: string
  accessKeySecret: string
  signName: string
  templateCode: string
  /** Template param name for the code (default: "code") */
  templateParam?: string
  endpoint?: string
}

export class AliyunSmsService extends SmsService {
  constructor(ctx: Context, public config: Config) {
    super(ctx, config)
  }

  async send(phone: string, content: string) {
    const {
      accessKeyId,
      accessKeySecret,
      signName,
      templateCode,
      templateParam = 'code',
      endpoint = 'https://dysmsapi.aliyuncs.com',
    } = this.config

    const params: Record<string, string> = {
      Action: 'SendSms',
      Version: '2017-05-25',
      Format: 'JSON',
      SignatureMethod: 'HMAC-SHA1',
      SignatureVersion: '1.0',
      SignatureNonce: randomUUID(),
      Timestamp: new Date().toISOString().replace(/\.\d{3}Z/, 'Z'),
      AccessKeyId: accessKeyId,
      PhoneNumbers: phone,
      SignName: signName,
      TemplateCode: templateCode,
      TemplateParam: JSON.stringify({ [templateParam]: content }),
    }

    // Sign
    const sorted = Object.keys(params).sort()
    const canonicalized = sorted.map(k =>
      `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`,
    ).join('&')
    const stringToSign = `GET&${encodeURIComponent('/')}&${encodeURIComponent(canonicalized)}`
    const signature = createHmac('sha1', accessKeySecret + '&')
      .update(stringToSign)
      .digest('base64')

    params.Signature = signature
    const query = Object.entries(params)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&')

    const res = await fetch(`${endpoint}/?${query}`)
    const data = await res.json() as any
    if (data.Code !== 'OK') {
      throw new Error(`Aliyun SMS error: ${data.Message ?? data.Code}`)
    }
  }
}

export default AliyunSmsService
