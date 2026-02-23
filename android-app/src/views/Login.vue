<template>
  <div class="login-wrapper">
    <div class="animated-bg"></div>
    <div class="card glass-card">
      <div class="brand">
        <img src="/app%20icon.png" alt="App Icon" class="app-icon" @error="handleImgError" />
        <h1>共享中心</h1>
      </div>
      
      <p class="hint">请填写服务器地址和专属设备令牌以连接至您的账号。</p>
      
      <div v-if="discoveredIps.length > 0" class="discovered-ips">
        <p>发现局域网服务器，点击快速填入：</p>
        <div class="ip-tags">
          <span v-for="ip in discoveredIps" :key="ip" class="ip-tag" @click="selectIp(ip)">{{ ip }}</span>
        </div>
      </div>

      <form @submit.prevent="submit" class="login-form">
        <div class="field ip-field">
          <label>服务器地址</label>
          <div class="input-with-btn">
            <input v-model="baseURL" type="text" placeholder="https://msg.fulioa.com" required />
            <button type="button" class="btn-scan" @click="scanLan" :disabled="scanning" title="寻找局域网服务器">
              <span class="scan-icon">{{ scanning ? '↻' : '⌕' }}</span>
              {{ scanning ? '扫描中' : '发现' }}
            </button>
          </div>
        </div>
        
        <div class="field">
          <label>API 令牌 (设备授权码)</label>
          <input v-model="apiToken" type="text" placeholder="请粘贴您的 API 令牌" required />
          <p class="field-help">令牌与您的账号绑定，可在电脑网页端「设置 → API 令牌」生成。</p>
        </div>
        
        <div v-if="error" class="error-box">
          {{ error }}
        </div>
        
        <button type="submit" class="btn-primary" :disabled="loading">
          <span v-if="loading" class="spinner"></span>
          {{ loading ? '连接中...' : '安全连接' }}
        </button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { setConfig, getConfig, api } from '../api'

const router = useRouter()
// Set default to requested URL if not already configured
const baseURL = ref(getConfig()?.baseURL || 'https://msg.fulioa.com')
const apiToken = ref(getConfig()?.apiToken || '')
const loading = ref(false)
const error = ref('')

const scanning = ref(false)
const discoveredIps = ref([])

function handleImgError(e) {
  // If the icon fails to load, hide it to prevent broken image icon
  e.target.style.display = 'none';
}

async function scanLan() {
  scanning.value = true
  discoveredIps.value = []
  error.value = ''
  
  let hostsToTry = []
  if (baseURL.value) {
    hostsToTry.push(baseURL.value)
  }
  
  const commonIps = ['192.168.1.2', '192.168.1.3', '192.168.1.100', '192.168.0.100', '10.0.0.2', '10.0.0.100', 'localhost']
  for (const ip of commonIps) {
    hostsToTry.push(`http://${ip}:5000`)
    hostsToTry.push(`https://${ip}:5000`)
  }

  hostsToTry = [...new Set(hostsToTry)]

  let found = false
  for (const host of hostsToTry) {
    if (found) break
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 1500)
      
      const url = host.startsWith('http') ? `${host}/api/lan-ips` : `http://${host}/api/lan-ips`
      const res = await fetch(url, { signal: controller.signal })
      clearTimeout(timeoutId)
      
      if (res.ok) {
        const data = await res.json()
        if (data && data.ips) {
          discoveredIps.value = data.ips.map(ip => `http://${ip}:${data.port || 5000}`)
          found = true
        }
      }
    } catch (e) {
      // Ignore errors
    }
  }
  
  scanning.value = false
  if (!found) {
    error.value = '未发现局域网服务器。'
  }
}

function selectIp(ip) {
  baseURL.value = ip
}

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
.login-wrapper {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  overflow: hidden;
  background-color: #f1f5f9;
}

/* Premium Dynamic Background Loop */
.animated-bg {
  position: absolute;
  top: -50%;
  left: -50%;
  width: 200%;
  height: 200%;
  background: radial-gradient(circle at 50% 50%, #e0f2fe 0%, #ccfbf1 25%, #f1f5f9 50%, #f8fafc 100%);
  animation: rotateBg 30s linear infinite;
  z-index: 0;
}
@keyframes rotateBg {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.card {
  position: relative;
  z-index: 10;
  width: 100%;
  max-width: 420px;
  padding: 40px 32px;
  border-radius: 24px;
}

/* Glassmorphism Effect */
.glass-card {
  background: rgba(255, 255, 255, 0.75);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid rgba(255, 255, 255, 0.5);
  box-shadow: 0 20px 40px rgba(15, 118, 110, 0.08), 
              inset 0 1px 0 rgba(255,255,255,0.6);
}

.brand {
  text-align: center;
  margin-bottom: 12px;
}
.app-icon {
  width: 72px;
  height: 72px;
  border-radius: 18px;
  margin-bottom: 16px;
  box-shadow: 0 8px 16px rgba(0,0,0,0.1);
}
.brand h1 {
  font-size: 28px;
  font-weight: 800;
  color: var(--dark);
  letter-spacing: -0.5px;
  margin: 0;
}

.hint {
  text-align: center;
  font-size: 14px;
  color: var(--gray);
  margin-bottom: 32px;
  line-height: 1.6;
}

.field { margin-bottom: 20px; }
.field label {
  display: block;
  font-size: 13px;
  font-weight: 700;
  color: var(--dark);
  margin-bottom: 8px;
  letter-spacing: 0.2px;
}
.field-help {
  font-size: 11px;
  color: #94a3b8;
  margin-top: 6px;
}

.field input {
  width: 100%;
  padding: 14px 16px;
  background: rgba(255, 255, 255, 0.9);
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  font-size: 15px;
  color: var(--dark);
  transition: all 0.2s ease;
  box-shadow: inset 0 1px 2px rgba(0,0,0,0.02);
}
.field input:focus {
  outline: none;
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(15, 118, 110, 0.15);
  background: #fff;
}

.input-with-btn {
  display: flex;
  gap: 8px;
}
.input-with-btn input { flex: 1; }
.btn-scan {
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 0 16px;
  background: var(--light);
  border: 1px solid #e2e8f0;
  border-radius: 12px;
  color: var(--primary);
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}
.btn-scan:hover:not(:disabled) {
  background: #e0f2fe;
  border-color: #bae6fd;
}
.btn-scan:disabled { opacity: 0.6; cursor: not-allowed; }
.scan-icon { font-size: 16px; }

.discovered-ips {
  margin-bottom: 24px;
  padding: 16px;
  background: rgba(248, 250, 252, 0.8);
  border-radius: 12px;
  border: 1px dashed #cbd5e1;
}
.discovered-ips p {
  font-size: 12px;
  font-weight: 600;
  color: var(--gray);
  margin-bottom: 10px;
}
.ip-tags { display: flex; flex-wrap: wrap; gap: 8px; }
.ip-tag {
  background: var(--primary);
  color: white;
  padding: 6px 12px;
  border-radius: 16px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  box-shadow: 0 2px 6px rgba(15, 118, 110, 0.2);
  transition: transform 0.1s;
}
.ip-tag:active { transform: scale(0.95); }

.error-box {
  background: #fef2f2;
  border: 1px solid #fecaca;
  color: var(--danger);
  padding: 12px;
  border-radius: 10px;
  font-size: 13px;
  margin-bottom: 20px;
  display: flex;
  align-items: center;
}

.btn-primary {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 100%;
  padding: 16px;
  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
  color: var(--white);
  border: none;
  border-radius: 12px;
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 0.5px;
  cursor: pointer;
  box-shadow: 0 4px 12px rgba(15, 118, 110, 0.3);
  transition: all 0.2s ease;
  margin-top: 12px;
}
.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(15, 118, 110, 0.4);
}
.btn-primary:active:not(:disabled) {
  transform: translateY(1px);
  box-shadow: 0 2px 8px rgba(15, 118, 110, 0.3);
}
.btn-primary:disabled {
  opacity: 0.7;
  cursor: not-allowed;
  background: var(--gray);
  box-shadow: none;
}

.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255,255,255,0.3);
  border-radius: 50%;
  border-top-color: white;
  animation: spin 0.8s linear infinite;
  margin-right: 8px;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
