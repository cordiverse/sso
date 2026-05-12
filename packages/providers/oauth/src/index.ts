import { Context } from 'cordis'
import type {} from '@cordisjs/plugin-server'
import type {} from '@cordisjs/plugin-timer'
import type {} from '@cordisjs/plugin-database'
import type {} from '@cordisjs/plugin-sso'
import z from 'schemastery'

import AppleProvider from './providers/apple'
import DingtalkProvider from './providers/dingtalk'
import DiscordProvider from './providers/discord'
import FacebookProvider from './providers/facebook'
import FeishuProvider from './providers/feishu'
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
  | AppleProvider.Config
  | DingtalkProvider.Config
  | DiscordProvider.Config
  | FacebookProvider.Config
  | FeishuProvider.Config
  | GenericProvider.Config
  | GiteeProvider.Config
  | GithubProvider.Config
  | GitlabProvider.Config
  | GoogleProvider.Config
  | LarkProvider.Config
  | LinkedinProvider.Config
  | MicrosoftProvider.Config
  | QqProvider.Config
  | SlackProvider.Config
  | TwitterProvider.Config
  | WeChatProvider.Config
  | WeiboProvider.Config

export const Config: z<Config> = z.intersect([
  z.object({
    preset: z.union([
      'apple', 'dingtalk', 'discord', 'facebook', 'feishu', 'generic',
      'gitee', 'github', 'gitlab', 'google', 'lark', 'linkedin',
      'microsoft', 'qq', 'slack', 'twitter', 'wechat', 'weibo',
    ] as const).required().description('OAuth 服务提供方。'),
  }),
  z.union([
    AppleProvider.Config,
    DingtalkProvider.Config,
    DiscordProvider.Config,
    FacebookProvider.Config,
    FeishuProvider.Config,
    GenericProvider.Config,
    GiteeProvider.Config,
    GithubProvider.Config,
    GitlabProvider.Config,
    GoogleProvider.Config,
    LarkProvider.Config,
    LinkedinProvider.Config,
    MicrosoftProvider.Config,
    QqProvider.Config,
    SlackProvider.Config,
    TwitterProvider.Config,
    WeChatProvider.Config,
    WeiboProvider.Config,
  ]),
] as const)

const providers = {
  apple: AppleProvider,
  dingtalk: DingtalkProvider,
  discord: DiscordProvider,
  facebook: FacebookProvider,
  feishu: FeishuProvider,
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
