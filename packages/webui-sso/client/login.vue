<template>
  <div class="login-page">
    <div class="login-card">
      <div v-if="!availableTabs.length" class="state">
        <div class="state-title">暂无可用的登录方式</div>
        <div class="state-hint">管理员尚未配置任何登录方式，请联系管理员。</div>
      </div>
      <el-tabs v-else v-model="tab" class="provider-tabs">
        <el-tab-pane
          v-for="p in credentialsProviders"
          :key="p.name"
          :name="p.name"
          :label="p.name"
        >
          <credentials-form
            mode="login"
            :loading="loadingFor(p.name)"
            :jit-provisioning="p.jitProvisioning"
            @submit="onCredentials(p, $event)"
          />
        </el-tab-pane>
        <el-tab-pane
          v-for="p in challengeProviders"
          :key="p.name"
          :name="p.name"
          :label="p.name"
        >
          <challenge-form
            :ref="(el) => setChallengeRef(p.name, el)"
            mode="login"
            :provider-name="p.name"
            :category="p.category"
            :loading="loadingFor(p.name)"
            :jit-provisioning="p.jitProvisioning"
            @start="onChallengeStart(p, $event)"
            @complete="onChallengeComplete(p, $event)"
            @reset="() => pendingChallenge[p.name] = null"
          />
        </el-tab-pane>
        <el-tab-pane
          v-for="p in redirectProviders"
          :key="p.name"
          :name="p.name"
          :label="p.name"
        >
          <redirect-provider
            mode="login"
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
import { ref, computed, reactive, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { useRpc } from '@cordisjs/client'
import {
  ssoStep,
  SsoError,
  startRedirectFlow,
} from './store'
import type { ProviderMeta, StepResult } from '../shared'
import CredentialsForm from './components/credentials.vue'
import ChallengeForm from './components/challenge.vue'
import RedirectProvider from './components/redirect.vue'

type SessionKind = 'login' | 'register'

const data = useRpc<{ providers: ProviderMeta[] }>()

const loading = reactive<Record<string, boolean>>({})
const pendingChallenge = reactive<Record<string, string | null>>({})
const challengeRefs = reactive<Record<string, any>>({})
const lastKind = reactive<Record<string, SessionKind>>({})

// Primary login page: only providers that can be primary factors appear.
const interactive = computed(() => (data.value?.providers ?? []).filter(p => p.interactive && p.canBePrimary))

const credentialsProviders = computed(() => interactive.value.filter(p => p.category === 'credentials'))
const challengeProviders = computed(() => interactive.value.filter(p => p.category === 'challenge'))
const redirectProviders = computed(() => interactive.value.filter(p => p.category === 'redirect'))

const availableTabs = computed(() => [
  ...credentialsProviders.value.map(p => p.name),
  ...challengeProviders.value.map(p => p.name),
  ...redirectProviders.value.map(p => p.name),
])

const tab = ref<string>('')

watch(availableTabs, (tabs) => {
  if (tabs.length && !tabs.includes(tab.value)) {
    tab.value = tabs[0]
  }
}, { immediate: true })

function loadingFor(name: string) {
  return loading[name] ?? false
}

function setChallengeRef(name: string, el: any) {
  if (el) challengeRefs[name] = el
}

async function onCredentials(p: ProviderMeta, payload: { kind: 'login' | 'register' | 'bind'; creds: { username: string; password: string } }) {
  const kind = payload.kind === 'bind' ? 'login' : payload.kind
  lastKind[p.name] = kind
  loading[p.name] = true
  try {
    const result = await ssoStep(kind, p.name, payload.creds)
    handleFinalResult(result, kind)
  } catch (e) {
    ElMessage.error(formatAuthError(e, kind))
  } finally {
    loading[p.name] = false
  }
}

async function onChallengeStart(p: ProviderMeta, payload: { kind: 'login' | 'register' | 'bind'; body: any }) {
  const kind = payload.kind === 'bind' ? 'login' : payload.kind
  lastKind[p.name] = kind
  loading[p.name] = true
  try {
    const result = await ssoStep(kind, p.name, payload.body)
    await driveChallenge(p, kind, result)
  } catch (e) {
    ElMessage.error(formatAuthError(e, kind))
  } finally {
    loading[p.name] = false
  }
}

async function driveChallenge(p: ProviderMeta, kind: SessionKind, result: StepResult) {
  while (result.phase === 'challenge') {
    if (result.response.shape === 'code') {
      pendingChallenge[p.name] = result.challengeId
      await challengeRefs[p.name]?.applyChallenge?.(result)
      return
    }
    if (result.response.shape === 'webauthn-get') {
      const { startAuthentication } = await import('@simplewebauthn/browser')
      const assertion = await startAuthentication({ optionsJSON: result.response.options })
      result = await ssoStep(kind, p.name, {
        challengeId: result.challengeId,
        response: assertion,
      })
      continue
    }
    if (result.response.shape === 'webauthn-create') {
      const { startRegistration } = await import('@simplewebauthn/browser')
      const attestation = await startRegistration({ optionsJSON: result.response.options })
      result = await ssoStep(kind, p.name, {
        challengeId: result.challengeId,
        response: attestation,
      })
      continue
    }
    return
  }
  handleFinalResult(result, kind)
}

async function onChallengeComplete(p: ProviderMeta, code: string) {
  const challengeId = pendingChallenge[p.name]
  if (!challengeId) return
  const kind = lastKind[p.name] ?? 'login'
  loading[p.name] = true
  try {
    const result = await ssoStep(kind, p.name, { challengeId, code })
    pendingChallenge[p.name] = null
    challengeRefs[p.name]?.reset?.()
    await driveChallenge(p, kind, result)
  } catch (e) {
    ElMessage.error(formatAuthError(e, kind))
  } finally {
    loading[p.name] = false
  }
}

async function onRedirectStart(p: ProviderMeta, kind: 'login' | 'register' | 'bind') {
  const k = kind === 'bind' ? 'login' : kind
  loading[p.name] = true
  try {
    await startRedirectFlow(k, p.name)
    // location.assign has fired inside runFlow; page is navigating away.
  } catch (e) {
    ElMessage.error(formatAuthError(e, k))
    loading[p.name] = false
  }
}

function handleFinalResult(result: StepResult, kind: SessionKind) {
  if (result.phase === 'finish') {
    const created = (result as any).created
    ElMessage.success(created ? '注册成功' : '登录成功')
    return
  }
  if (result.phase === 'stepup') {
    ElMessage.warning('需要二次验证')
    return
  }
}

function formatAuthError(e: unknown, kind: SessionKind) {
  const action = kind === 'login' ? '登录' : '注册'
  if ((e as any)?.name === 'NotAllowedError') return '已取消'
  if ((e as any)?.name === 'InvalidStateError') return '该设备已经为此账号绑定过通行密钥'
  if (!(e instanceof SsoError)) return `${action}失败，请检查网络后重试`
  if (e.code === 'INVALID_CREDENTIALS' || e.code === 'ACCOUNT_NOT_FOUND') return '账号或密码错误'
  if (e.code === 'SESSION_REQUIRED') return '登录已失效，请重新登录'
  if (e.code === 'CHALLENGE_EXPIRED') return '验证码已过期，请重新发送'
  if (e.code === 'VERIFICATION_FAILED') return '验证码错误'
  if (e.code === 'NOT_PRIMARY_FACTOR') return '该登录方式不能作为首因素'
  if (e.code === 'USERNAME_TAKEN') return '用户名已被占用'
  if (e.code === 'EMAIL_TAKEN' || e.code === 'PHONE_TAKEN') return '该标识已被占用'
  if (e.code.startsWith('HTTP_5')) return `${action}失败，服务暂时异常，请稍后再试`
  return `${action}失败：${e.code}`
}
</script>

<style lang="scss" scoped>
.login-page {
  display: flex;
  flex-direction: column;
  padding: 16px;
  flex: 1;
  min-height: 0;
}
.login-card {
  margin: auto;
  width: 100%;
  max-width: 420px;
  background: var(--bg-elevated, var(--bg-secondary));
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-lg, 8px);
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  box-sizing: border-box;
}
.state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 16px 0;
  text-align: center;
}
.state-title {
  font-weight: 600;
}
.state-hint {
  color: var(--text-tertiary);
  font-size: 13px;
  max-width: 320px;
}
.provider-tabs :deep(.el-tabs__nav-wrap::after) {
  height: 1px;
}
.provider-tabs :deep(.el-tabs__item) {
  text-transform: capitalize;
}
</style>
