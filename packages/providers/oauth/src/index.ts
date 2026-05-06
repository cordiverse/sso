import { Context } from 'cordis'
import type {} from '@cordisjs/plugin-logger'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-timer'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-sso'

import AppleProvider from './providers/apple'
import DingtalkProvider from './providers/dingtalk'
import DiscordProvider from './providers/discord'
import FacebookProvider from './providers/facebook'
import GenericProvider from './providers/generic'
import GiteeProvider from './providers/gitee'
import GithubProvider from './providers/github'
import GitlabProvider from './providers/gitlab'
import GoogleProvider from './providers/google'
import LarkProvider from './providers/lark'
import LinkedinProvider from './providers/linkedin'
import MicrosoftProvider from './providers/microsoft'
import QqProvider from './providers/qq'
import SlackProvider from './providers/slack'
import TwitterProvider from './providers/twitter'
import WeChatProvider from './providers/wechat'
import WeiboProvider from './providers/weibo'

export * from './base'
export * from './utils'

/**
 * Configuration is discriminated on `preset`. Each subclass has its own
 * config shape; base fields (`scope?`, `redirectUrl?`) are common. Use
 * `preset: 'generic'` for custom RFC 6749 IdPs (you supply the four URLs).
 */
export type Config =
  | ({ preset: 'apple' } & AppleProvider.Config)
  | ({ preset: 'dingtalk' } & DingtalkProvider.Config)
  | ({ preset: 'discord' } & DiscordProvider.Config)
  | ({ preset: 'facebook' } & FacebookProvider.Config)
  | ({ preset: 'generic' } & GenericProvider.Config)
  | ({ preset: 'gitee' } & GiteeProvider.Config)
  | ({ preset: 'github' } & GithubProvider.Config)
  | ({ preset: 'gitlab' } & GitlabProvider.Config)
  | ({ preset: 'google' } & GoogleProvider.Config)
  | ({ preset: 'lark' } & LarkProvider.Config)
  | ({ preset: 'linkedin' } & LinkedinProvider.Config)
  | ({ preset: 'microsoft' } & MicrosoftProvider.Config)
  | ({ preset: 'qq' } & QqProvider.Config)
  | ({ preset: 'slack' } & SlackProvider.Config)
  | ({ preset: 'twitter' } & TwitterProvider.Config)
  | ({ preset: 'wechat' } & WeChatProvider.Config)
  | ({ preset: 'weibo' } & WeiboProvider.Config)

const providers = {
  apple: AppleProvider,
  dingtalk: DingtalkProvider,
  discord: DiscordProvider,
  facebook: FacebookProvider,
  generic: GenericProvider,
  gitee: GiteeProvider,
  github: GithubProvider,
  gitlab: GitlabProvider,
  google: GoogleProvider,
  lark: LarkProvider,
  linkedin: LinkedinProvider,
  microsoft: MicrosoftProvider,
  qq: QqProvider,
  slack: SlackProvider,
  twitter: TwitterProvider,
  wechat: WeChatProvider,
  weibo: WeiboProvider,
} as const

export const name = 'sso-oauth'

export function apply(ctx: Context, config: Config) {
  const Provider = (providers as any)[config.preset]
  if (!Provider) throw new Error(`sso-oauth: unknown preset "${(config as any).preset}"`)
  ctx.plugin(Provider, config)
}
