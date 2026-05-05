<template>
  <el-form label-position="top" class="credentials-form" @submit.prevent="onSubmit(primaryKind)">
    <el-form-item v-if="showUsername" label="用户名">
      <el-input
        v-model="username"
        autocomplete="username"
        :disabled="loading"
        placeholder="用户名"
      />
    </el-form-item>
    <el-form-item label="密码">
      <el-input
        v-model="password"
        type="password"
        show-password
        :autocomplete="mode === 'login' ? 'current-password' : 'new-password'"
        :disabled="loading"
      />
    </el-form-item>
    <div class="actions">
      <template v-if="twoButtons">
        <el-button
          native-type="submit"
          :loading="loading"
          :disabled="!canSubmit"
        >登录</el-button>
        <el-button
          type="primary"
          :loading="loading"
          :disabled="!canSubmit"
          @click="onSubmit('register')"
        >注册</el-button>
      </template>
      <el-button
        v-else
        type="primary"
        native-type="submit"
        :loading="loading"
        :disabled="!canSubmit"
      >{{ singleLabel }}</el-button>
    </div>
  </el-form>
</template>

<script lang="ts" setup>
import { ref, computed } from 'vue'
import type { AuthMode } from '../../shared'

const props = defineProps<{
  mode: AuthMode
  loading?: boolean
  // When true, login and register are indistinguishable — single button.
  // When false (e.g. password), two buttons so the user picks intent.
  // Ignored when mode === 'link' (bind is always one button).
  jitProvisioning?: boolean
  // Used in link mode: existing account handle; when present, username input is hidden.
  currentName?: string
}>()

const emit = defineEmits<{
  (e: 'submit', payload: { kind: 'login' | 'register' | 'bind'; creds: { username: string; password: string } }): void
}>()

const username = ref('')
const password = ref('')

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

const showUsername = computed(() => {
  if (props.mode !== 'link') return true
  return !props.currentName
})

const canSubmit = computed(() => {
  if (!password.value) return false
  if (showUsername.value) return !!username.value
  return true
})

function onSubmit(kind: 'login' | 'register' | 'bind') {
  emit('submit', {
    kind,
    creds: {
      username: showUsername.value ? username.value : (props.currentName ?? ''),
      password: password.value,
    },
  })
}
</script>

<style lang="scss" scoped>
.credentials-form :deep(.el-form-item) {
  margin-bottom: 16px;
}
.actions {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}
</style>
