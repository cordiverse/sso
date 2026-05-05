<template>
  <el-form label-position="top" class="challenge-form" @submit.prevent="onStart(primaryKind)">
    <!-- step 1: collect initial identifier -->
    <template v-if="!pending">
      <template v-if="providerName === 'mail'">
        <el-form-item label="邮箱">
          <el-input v-model="identifier" type="email" autocomplete="email" :disabled="loading" placeholder="example@mail.com" />
        </el-form-item>
      </template>
      <template v-else-if="providerName === 'sms'">
        <el-form-item label="手机号">
          <el-input v-model="identifier" autocomplete="tel" :disabled="loading" placeholder="+86 13800000000" />
        </el-form-item>
      </template>
      <template v-else-if="providerName === 'webauthn' && mode === 'login' && !registerIntent">
        <el-form-item label="用户名（可选）">
          <el-input v-model="identifier" :disabled="loading" />
        </el-form-item>
      </template>
      <template v-else-if="providerName === 'webauthn' && (mode === 'register' || registerIntent)">
        <el-form-item label="用户名（可选）">
          <el-input v-model="identifier" :disabled="loading" placeholder="留空也可，之后绑其它登录方式时再设置" />
        </el-form-item>
      </template>
      <div class="actions">
        <template v-if="twoButtons">
          <el-button native-type="submit" :loading="loading" @click="registerIntent = false">登录</el-button>
          <el-button type="primary" :loading="loading" @click="registerIntent = true; onStart('register')">注册</el-button>
        </template>
        <el-button
          v-else
          type="primary"
          native-type="submit"
          :loading="loading"
        >{{ singleLabel }}</el-button>
      </div>
    </template>

    <!-- step 2: code prompt -->
    <template v-else>
      <div v-if="pending.otpauthUrl" class="totp-qr">
        <img v-if="qrDataUrl" :src="qrDataUrl" alt="二维码" />
      </div>
      <div v-if="pending.secret" class="totp-secret">
        密钥: <code>{{ pending.secret }}</code>
      </div>
      <el-form-item :label="pending.digits ? `${pending.length} 位验证码` : '验证码'">
        <el-input v-model="code" :disabled="loading" autocomplete="one-time-code" inputmode="numeric" :placeholder="`${pending.length} 位数字`" />
      </el-form-item>
      <div class="actions">
        <el-button :disabled="loading" @click="onReset">返回</el-button>
        <el-button type="primary" :loading="loading" :disabled="!code" @click="onConfirm">确认</el-button>
      </div>
    </template>
  </el-form>
</template>

<script lang="ts" setup>
import { ref, computed, watch } from 'vue'
import QRCode from 'qrcode'
import type { AuthMode, StepResult } from '../../shared'

const props = defineProps<{
  mode: AuthMode
  providerName: string
  category: string
  loading?: boolean
  jitProvisioning?: boolean
}>()

const emit = defineEmits<{
  (e: 'start', payload: { kind: 'login' | 'register' | 'bind'; body: any }): void
  (e: 'complete', code: string): void
  (e: 'reset'): void
}>()

const identifier = ref('')
const code = ref('')
const pending = ref<null | { length: number; digits: boolean; otpauthUrl?: string; secret?: string }>(null)
const qrDataUrl = ref('')
const registerIntent = ref(false)

const twoButtons = computed(() => props.mode !== 'link' && !props.jitProvisioning)
const primaryKind = computed<'login' | 'register' | 'bind'>(() => {
  if (props.mode === 'link') return 'bind'
  if (twoButtons.value) return 'login'
  return 'login'
})

const singleLabel = computed(() => {
  if (props.mode === 'link') return '绑定'
  return '继续'
})

function payloadForStart(kind: 'login' | 'register' | 'bind'): any {
  if (props.providerName === 'mail') return { email: identifier.value }
  if (props.providerName === 'sms') return { phone: identifier.value }
  if (props.providerName === 'webauthn') {
    if (kind === 'register') return { name: identifier.value || undefined }
    return identifier.value ? { hint: identifier.value } : {}
  }
  if (props.providerName === 'totp') return {}
  return { identifier: identifier.value }
}

function onStart(kind: 'login' | 'register' | 'bind') {
  emit('start', { kind, body: payloadForStart(kind) })
}

function onConfirm() {
  emit('complete', code.value)
}

function onReset() {
  pending.value = null
  code.value = ''
  qrDataUrl.value = ''
  registerIntent.value = false
  emit('reset')
}

async function applyChallenge(result: Extract<StepResult, { phase: 'challenge' }>) {
  if (result.response.shape !== 'code') return
  const data = result.data as any | undefined
  pending.value = {
    length: result.response.length,
    digits: result.response.digits,
    otpauthUrl: data?.otpauthUrl,
    secret: data?.secret,
  }
  code.value = ''
  if (data?.otpauthUrl) {
    try {
      qrDataUrl.value = await QRCode.toDataURL(data.otpauthUrl, {
        errorCorrectionLevel: 'M',
        margin: 1,
        width: 240,
      })
    } catch {
      qrDataUrl.value = ''
    }
  }
}

defineExpose({ applyChallenge, reset: onReset })

watch(() => props.providerName, () => onReset())
</script>

<style lang="scss" scoped>
.challenge-form :deep(.el-form-item) {
  margin-bottom: 16px;
}
.actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}
.totp-qr {
  display: flex;
  justify-content: center;
  margin-bottom: 12px;

  img {
    width: 200px;
    height: 200px;
    background: white;
    padding: 8px;
    border-radius: 6px;
  }
}
.totp-secret {
  padding: 8px;
  background: var(--bg-secondary);
  border-radius: 4px;
  font-size: 12px;
  margin-bottom: 12px;
  text-align: center;

  code {
    font-family: monospace;
    letter-spacing: 1px;
  }
}
</style>
