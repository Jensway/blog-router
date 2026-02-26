<template>
  <div class="page has-bottom-nav">
    <div class="content-area">
      <div class="settings-group">
        <h3 class="group-title">账号与服务器</h3>
        <div class="setting-item">
          <div class="setting-info">
            <span class="setting-name">服务器地址</span>
            <span class="setting-desc">{{ config.baseURL }}</span>
          </div>
        </div>
        <div class="setting-item">
          <div class="setting-info">
            <span class="setting-name">API 令牌</span>
            <span class="setting-desc">已安全保存 ({{ (config.apiToken || '').substring(0, 4) }}...)</span>
          </div>
        </div>
      </div>

      <div class="settings-group">
        <h3 class="group-title">系统信息</h3>
        <div class="setting-item">
          <div class="setting-info">
            <span class="setting-name">版本</span>
            <span class="setting-desc">v1.1 (共享中心 v6.0)</span>
          </div>
        </div>
        <div class="setting-item">
          <div class="setting-info">
            <span class="setting-name">开发者</span>
            <span class="setting-desc">Antigravity (GPT-4o) / Jensway</span>
          </div>
        </div>
      </div>
      <div class="settings-group logout-group" @click="logout">
        <span class="logout-text">注销账号并重新登录</span>
      </div>

      <div class="settings-group exit-group" @click="exitApp">
        <span class="exit-text">退出并关闭应用</span>
      </div>
      
      <div class="bottom-spacer"></div>
    </div>
  </div>
</template>

<script setup>
import { reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getConfig, setConfig } from '../api'
import { App as CapacitorApp } from '@capacitor/app'

const router = useRouter()
const config = reactive({ baseURL: '', apiToken: '' })

onMounted(() => {
  const c = getConfig()
  if (c) {
    config.baseURL = c.baseURL
    config.apiToken = c.apiToken
  }
})

function logout() {
  if (confirm('确定要注销当前账号吗？注销后需要重新填入服务器与API令牌。')) {
    setConfig('', '') 
    router.replace('/login')
  }
}

function exitApp() {
  if (confirm('确定要退出程序吗？')) {
    if (window.Capacitor && window.Capacitor.isNative) {
      CapacitorApp.exitApp()
    } else {
      window.close()
    }
  }
}
</script>

<style scoped>
.page { 
  position: relative;
  min-height: 100%;
  background-color: var(--light);
}

.content-area {
  padding: 20px 20px 100px; /* Enhanced bottom padding to ensure scroll clears */
}

.settings-group {
  margin-bottom: 24px;
  background: var(--white);
  border-radius: 16px;
  padding: 16px;
  box-shadow: var(--shadow-sm);
  border: 1px solid #e2e8f0;
}

.logout-group, .exit-group {
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: background 0.2s;
}
.logout-group:active, .exit-group:active {
  background: #fef2f2;
}
.logout-text {
  color: var(--danger);
  font-weight: 600;
  font-size: 16px;
}
.exit-text {
  color: #64748b;
  font-weight: 600;
  font-size: 16px;
}

.group-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--primary);
  margin-bottom: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.setting-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid #f1f5f9;
}
.setting-item:last-child {
  border-bottom: none;
  padding-bottom: 0;
}

.setting-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.setting-name {
  font-size: 16px;
  font-weight: 600;
  color: var(--dark);
}

.setting-desc {
  font-size: 13px;
  color: #94a3b8;
}

.bottom-spacer {
  height: 30px;
}
</style>
