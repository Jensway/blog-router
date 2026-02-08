<template>
  <div class="login">
    <div class="card">
      <h1>共享中心</h1>
      <p class="hint">请填写服务器地址和 API 令牌（在网页版「设置 → API 令牌」中创建）</p>
      <form @submit.prevent="submit">
        <div class="field">
          <label>服务器地址</label>
          <input v-model="baseURL" type="url" placeholder="https://你的服务器:5000" required />
        </div>
        <div class="field">
          <label>API 令牌</label>
          <input v-model="apiToken" type="text" placeholder="粘贴 API 令牌" required />
        </div>
        <p v-if="error" class="error">{{ error }}</p>
        <button type="submit" class="btn" :disabled="loading">连接</button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { setConfig, getConfig, api } from '../api'

const router = useRouter()
const baseURL = ref(getConfig()?.baseURL || '')
const apiToken = ref(getConfig()?.apiToken || '')
const loading = ref(false)
const error = ref('')

async function submit() {
  error.value = ''
  loading.value = true
  try {
    setConfig(baseURL.value.trim(), apiToken.value.trim())
    await api.getPosts({ draft: '0' })
    router.replace('/posts')
  } catch (e) {
    error.value = e.message || '连接失败，请检查地址和令牌'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.card {
  background: var(--white);
  border-radius: 16px;
  padding: 28px;
  width: 100%;
  max-width: 400px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.08);
}
h1 {
  font-size: 24px;
  margin-bottom: 8px;
  color: var(--dark);
}
.hint {
  font-size: 13px;
  color: var(--gray);
  margin-bottom: 24px;
  line-height: 1.5;
}
.field {
  margin-bottom: 16px;
}
.field label {
  display: block;
  font-size: 13px;
  font-weight: 600;
  color: var(--dark);
  margin-bottom: 6px;
}
.field input {
  width: 100%;
  padding: 12px 14px;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  font-size: 15px;
}
.field input:focus {
  outline: none;
  border-color: var(--primary);
}
.error {
  color: var(--danger);
  font-size: 13px;
  margin-bottom: 12px;
}
.btn {
  width: 100%;
  padding: 14px;
  background: var(--primary);
  color: var(--white);
  border: none;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 600;
  margin-top: 8px;
}
.btn:disabled { opacity: 0.7; }
</style>
