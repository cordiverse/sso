<template>
  <div class="user-page">
    <div class="user-card">
      <div class="user-head">
        <div class="user-info">
          <div class="user-name">{{ store.user?.display || store.user?.name || '用户' }}</div>
          <div class="user-meta">ID {{ store.user?.id }} · 注册于 {{ formatDate(store.user?.createdAt ?? '') }}</div>
        </div>
        <el-button @click="onLogout">登出</el-button>
      </div>
    </div>

    <div class="user-card">
      <div class="card-title">已绑定登录方式</div>
      <div v-if="loading" class="hint">加载中…</div>
      <div v-else-if="!identities.length" class="hint">没有已绑定的登录方式</div>
      <ul v-else class="identity-list">
        <li v-for="ident in identities" :key="ident.id" class="identity-item">
          <div class="identity-info">
            <div class="identity-provider">{{ ident.provider }}</div>
            <div class="identity-time">{{ formatDate(ident.createdAt) }}</div>
          </div>
          <el-button
            size="small"
            type="danger"
            text
            :disabled="identities.length <= 1"
            @click="onUnlink(ident.id, ident.provider)"
          >解绑</el-button>
        </li>
      </ul>
    </div>

    <div v-if="availableLinkTabs.length" class="user-card">
      <div class="card-title">添加登录方式</div>
      <el-tabs v-model="linkTab" class="provider-tabs">
        <el-tab-pane
          v-for="p in linkableCredentialsProviders"
          :key="p.name"
          :name="p.name"
          :label="p.name"
        >
          <credentials-form
            mode="link"
            :loading="loadingFor(p.name)"
            :current-name="store.user?.name"
            @submit="onCredentialsBind(p, $event)"
          />
        </el-tab-pane>
        <el-tab-pane
          v-for="p in linkableChallengeProviders"
          :key="p.name"
          :name="p.name"
          :label="p.name"
        >
          <challenge-form
            :ref="(el) => setChallengeRef(p.name, el)"
            mode="link"
            :provider-name="p.name"
            :category="p.category"
            :loading="loadingFor(p.name)"
            @start="onChallengeStart(p, $event)"
            @complete="onChallengeComplete(p, $event)"
            @reset="() => pendingChallenge[p.name] = null"
          />
        </el-tab-pane>
        <el-tab-pane
          v-for="p in linkableRedirectProviders"
          :key="p.name"
          :name="p.name"
          :label="p.name"
        >
          <redirect-provider
            mode="link"
            :provider-name="p.name"
            :loading="loadingFor(p.name)"
            @start="onRedirectStart(p, $event)"
          />
        </el-tab-pane>
      </el-tabs>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox, ElLoading } from 'element-plus'
import {
  listIdentities,
  unlink as doUnlink,
  logout as doLogout,
  ssoStep,
  store,
  SsoError,
  runOAuthFlow,
} from './store'
import { useRpc } from '@cordisjs/client'
import type { Identity, ProviderMeta, StepResult } from '../shared'
import CredentialsForm from './components/credentials.vue'
import ChallengeForm from './components/challenge.vue'
import RedirectProvider from './components/redirect.vue'

const rpc = useRpc<{ providers: ProviderMeta[] }>()

const identities = ref<Identity[]>([])
const loading = ref(false)
const linkTab = ref<string>('')
const flowLoading = reactive<Record<string, boolean>>({})
const pendingChallenge = reactive<Record<string, string | null>>({})
const challengeRefs = reactive<Record<string, any>>({})

const boundProviders = computed(() => new Set(identities.value.map(i => i.provider)))
const allProviders = computed(() => rpc.value?.providers ?? [])

// credentials/challenge/redirect: one identity per provider usually (we hide
// once bound). webauthn is the exception — multiple passkeys per user.
function isBindable(p: ProviderMeta) {
  if (p.name === 'webauthn') return true
  if (p.name === 'totp') return true
  return !boundProviders.value.has(p.name)
}

const linkableCredentialsProviders = computed(() =>
  allProviders.value.filter(p => p.category === 'credentials' && isBindable(p)),
)
const linkableChallengeProviders = computed(() =>
  allProviders.value.filter(p => p.category === 'challenge' && isBindable(p)),
)
const linkableRedirectProviders = computed(() =>
  allProviders.value.filter(p => p.category === 'redirect' && isBindable(p)),
)

const availableLinkTabs = computed(() => [
  ...linkableCredentialsProviders.value.map(p => p.name),
  ...linkableChallengeProviders.value.map(p => p.name),
  ...linkableRedirectProviders.value.map(p => p.name),
])

async function refreshIdentities() {
  loading.value = true
  try {
    identities.value = await listIdentities()
  } catch {
    identities.value = []
  } finally {
    loading.value = false
  }
}

onMounted(refreshIdentities)

function loadingFor(name: string) {
  return flowLoading[name] ?? false
}

function setChallengeRef(name: string, el: any) {
  if (el) challengeRefs[name] = el
}

async function onCredentialsBind(p: ProviderMeta, payload: { kind: 'login' | 'register' | 'bind'; creds: { username: string; password: string } }) {
  flowLoading[p.name] = true
  try {
    await ssoStep('bind', p.name, payload.creds)
    await refreshIdentities()
    ElMessage.success('绑定成功')
  } catch (e) {
    ElMessage.error(formatLinkError(e))
  } finally {
    flowLoading[p.name] = false
  }
}

async function onChallengeStart(p: ProviderMeta, payload: { kind: 'login' | 'register' | 'bind'; body: any }) {
  flowLoading[p.name] = true
  try {
    const result = await ssoStep('bind', p.name, payload.body)
    await driveChallenge(p, result)
  } catch (e) {
    ElMessage.error(formatLinkError(e))
  } finally {
    flowLoading[p.name] = false
  }
}

async function driveChallenge(p: ProviderMeta, result: StepResult) {
  while (result.phase === 'challenge') {
    if (result.response.shape === 'code') {
      pendingChallenge[p.name] = result.challengeId
      await challengeRefs[p.name]?.applyChallenge?.(result)
      return
    }
    if (result.response.shape === 'webauthn-get') {
      const { startAuthentication } = await import('@simplewebauthn/browser')
      const assertion = await startAuthentication({ optionsJSON: result.response.options })
      result = await ssoStep('bind', p.name, {
        challengeId: result.challengeId,
        response: assertion,
      })
      continue
    }
    if (result.response.shape === 'webauthn-create') {
      const { startRegistration } = await import('@simplewebauthn/browser')
      const attestation = await startRegistration({ optionsJSON: result.response.options })
      result = await ssoStep('bind', p.name, {
        challengeId: result.challengeId,
        response: attestation,
      })
      continue
    }
    return
  }
  if (result.phase === 'finish') {
    await refreshIdentities()
    ElMessage.success('绑定成功')
  }
}

async function onChallengeComplete(p: ProviderMeta, code: string) {
  const challengeId = pendingChallenge[p.name]
  if (!challengeId) return
  flowLoading[p.name] = true
  try {
    const result = await ssoStep('bind', p.name, { challengeId, code })
    pendingChallenge[p.name] = null
    challengeRefs[p.name]?.reset?.()
    await driveChallenge(p, result)
  } catch (e) {
    ElMessage.error(formatLinkError(e))
  } finally {
    flowLoading[p.name] = false
  }
}

async function onRedirectStart(p: ProviderMeta, _kind: 'login' | 'register' | 'bind') {
  flowLoading[p.name] = true
  try {
    const { error } = await runOAuthFlow('bind', p.name)
    if (error) {
      if (error !== 'USER_CANCELED') ElMessage.error(formatLinkError(new SsoError(error, 0)))
      return
    }
    await refreshIdentities()
    ElMessage.success('绑定成功')
  } catch (e) {
    ElMessage.error(formatLinkError(e))
  } finally {
    flowLoading[p.name] = false
  }
}

function formatLinkError(e: unknown) {
  if ((e as any)?.name === 'NotAllowedError') return '已取消'
  if ((e as any)?.name === 'InvalidStateError') return '该设备已经为此账号绑定过通行密钥'
  if (!(e instanceof SsoError)) return '绑定失败，请稍后再试'
  if (e.code === 'SESSION_REQUIRED') return '登录已失效，请重新登录'
  if (e.code === 'CHALLENGE_EXPIRED') return '验证码已过期'
  if (e.code === 'VERIFICATION_FAILED') return '验证码错误'
  if (e.code === 'USERNAME_TAKEN' || e.code === 'EMAIL_TAKEN' || e.code === 'PHONE_TAKEN') return '该标识已被占用'
  if (e.code.startsWith('HTTP_5')) return '绑定失败，服务暂时异常，请稍后再试'
  return `绑定失败：${e.code}`
}

async function onUnlink(id: number, provider: string) {
  if (identities.value.length <= 1) {
    ElMessage.warning('至少要保留一种登录方式')
    return
  }
  try {
    await ElMessageBox.confirm(`确认解绑 ${provider} 登录方式?`, '解绑', { type: 'warning' })
  } catch {
    return
  }
  const loading = ElLoading.service({
    lock: true,
    text: '正在解绑...',
    background: 'rgba(0, 0, 0, 0.5)',
  })
  try {
    await doUnlink(id)
    ElMessage.success('已解绑')
    await refreshIdentities()
  } catch (e) {
    const code = e instanceof SsoError ? e.code : 'unknown'
    const msg = code === 'REVOKE_FAILED'
      ? '撤销授权失败,请稍后重试'
      : `解绑失败: ${code}`
    ElMessage.error(msg)
  } finally {
    loading.close()
  }
}

async function onLogout() {
  await doLogout()
  ElMessage.success('已登出')
}

function formatDate(s: string) {
  try {
    return new Date(s).toLocaleString()
  } catch {
    return s
  }
}
</script>

<style lang="scss" scoped>
.user-page {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 24px;
  max-width: 720px;
  width: 100%;
  margin: 0 auto;
  flex: 1;
}
.user-card {
  background: var(--bg-elevated, var(--bg-secondary));
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-lg, 8px);
  padding: 20px;
}
.user-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.user-name {
  font-size: 18px;
  font-weight: 600;
}
.user-meta {
  margin-top: 4px;
  color: var(--text-tertiary);
  font-size: 13px;
}
.card-title {
  font-weight: 600;
  margin-bottom: 12px;
}
.hint {
  color: var(--text-tertiary);
  font-size: 13px;
}
.identity-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.identity-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-md, 6px);
  background: var(--bg-primary);
}
.identity-provider {
  font-weight: 500;
  text-transform: capitalize;
}
.identity-time {
  font-size: 12px;
  color: var(--text-tertiary);
}
.provider-tabs :deep(.el-tabs__nav-wrap::after) {
  height: 1px;
}
</style>
