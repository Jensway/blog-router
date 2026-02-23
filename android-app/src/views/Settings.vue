<template>
  <div class="page has-bottom-nav">
    <header class="header blur-header">
      <div class="header-content">
        <h1>我的设置</h1>
        <button class="icon-btn logout-btn" @click="logout" aria-label="注销" title="切换账号">
          <span class="icon">⎋</span>
        </button>
      </div>
    </header>

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
            <span class="setting-desc">Jensway / GPT-4o Mobile Core</span>
          </div>
        </div>
      </div>
      
      <div class="bottom-spacer"></div>
    </div>
  </div>
</template>

<script setup>
import { reactive, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getConfig, setConfig } from '../api'

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
</script>

<style scoped>
.page { 
  position: relative;
  min-height: 100%;
  background-color: var(--light);
}

.blur-header {
  position: sticky;
  top: 0;
  z-index: 50;
  background: rgba(248, 250, 252, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  padding: 16px 20px 12px;
  border-bottom: 1px solid rgba(0,0,0,0.05);
}

.header-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.header-content h1 { 
  font-size: 28px; 
  font-weight: 800; 
  letter-spacing: -0.5px;
  color: var(--dark);
  margin: 0;
}

.icon-btn {
  width: 44px;
  height: 44px;
  border: none;
  background: var(--white);
  border-radius: 14px;
  font-size: 20px;
  box-shadow: var(--shadow-sm);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.logout-btn {
  background: transparent;
  box-shadow: none;
  border: 1px solid #e2e8f0;
  color: var(--gray);
  font-size: 16px;
}
.logout-btn:hover { background: #fef2f2; border-color: #fecaca; color: var(--danger); }

.content-area {
  padding: 20px;
}

.settings-group {
  margin-bottom: 24px;
  background: var(--white);
  border-radius: 16px;
  padding: 16px;
  box-shadow: var(--shadow-sm);
  border: 1px solid #e2e8f0;
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
