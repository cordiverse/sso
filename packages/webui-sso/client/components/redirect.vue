<template>
  <div class="redirect-provider">
    <p class="hint">{{ hint }}</p>
    <el-button type="primary" :loading="loading" @click="onStart">
      {{ buttonLabel }}
    </el-button>
  </div>
</template>

<script lang="ts" setup>
import { computed } from 'vue'
import type { AuthMode } from '../../shared'

const props = defineProps<{
  mode: AuthMode
  providerName: string
  loading?: boolean
}>()

const emit = defineEmits<{
  (e: 'start', kind: 'login' | 'register' | 'bind'): void
}>()

const hint = computed(() => {
  if (props.mode === 'link') return `使用 ${props.providerName} 账号绑定到当前账户。`
  return `使用 ${props.providerName} 账号登录（新账号自动注册）。`
})

const buttonLabel = computed(() => {
  if (props.mode === 'link') return '绑定'
  return '继续'
})

function onStart() {
  emit('start', props.mode === 'link' ? 'bind' : 'login')
}
</script>

<style lang="scss" scoped>
.redirect-provider {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.hint {
  margin: 0;
  color: var(--text-tertiary);
  font-size: 13px;
}
</style>
