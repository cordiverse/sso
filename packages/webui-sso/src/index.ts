import { Context } from 'cordis'
import type {} from '@cordisjs/plugin-sso'
import type {} from '@cordisjs/plugin-webui'
import type {} from '@cordisjs/plugin-timer'
import type { ProviderMeta } from '../shared'
import z from 'schemastery'

export const name = 'webui-sso'

export const inject = ['webui', 'sso', 'timer']

export interface Config {}

export const Config: z<Config> = z.object({})

interface Data {
  providers: ProviderMeta[]
}

export function apply(ctx: Context) {
  const entry = ctx.webui.addEntry<Data>({
    path: '@cordisjs/plugin-webui-sso/dist',
    base: import.meta.url,
    dev: '../client/index.ts',
    prod: '../dist/manifest.json',
  }, { providers: [] })

  async function refresh() {
    const providers = await ctx.sso.getProviderMetas()
    entry.mutate((d) => { d.providers = providers })
  }

  const update = ctx.debounce(refresh, 0)
  ctx.on('internal/plugin', update)
  ctx.on('internal/status', update)
  update()
}
