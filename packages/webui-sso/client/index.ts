import { Context } from '@cordisjs/client'
import {} from '../src'
import Page from './index.vue'
import { consumeOAuthCallback, refresh, reportOAuthToOpener } from './store'
import { ElMessage } from 'element-plus'
import './icons'

export default async (ctx: Context) => {
  if (reportOAuthToOpener()) return

  const { token, error } = consumeOAuthCallback()
  if (error) {
    ElMessage.error(`OAuth 失败: ${error}`)
  }
  await refresh()

  ctx.client.router.page({
    path: '/sso',
    name: '账号',
    icon: 'activity:webui-sso',
    position: 'bottom',
    order: -110,
    component: Page,
  })

  if (token) {
    ctx.client.router.router.push('/sso')
  }
}
