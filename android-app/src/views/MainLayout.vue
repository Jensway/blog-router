<template>
  <div class="main-layout">
    <!-- Universal Brand Header -->
    <header class="app-brand blur-header">
      <h2>数字花园</h2>
      <p>Digital Garden</p>
    </header>

    <!-- iOS/Android Style Top Navigation Bar -->
    <nav class="top-nav">
      <router-link to="/posts" class="nav-item" active-class="active">
        <span class="nav-label">日志中心</span>
      </router-link>
      
      <router-link to="/messages" class="nav-item" active-class="active">
        <span class="nav-label">消息中心</span>
      </router-link>

      <router-link to="/settings" class="nav-item" active-class="active">
        <span class="nav-label">设置</span>
      </router-link>

      <button class="nav-item exit-btn" @click="exitApp">
        <span class="nav-label">退出</span>
      </button>
    </nav>

    <!-- Router View for the Tabs -->
    <div class="tab-content">
      <router-view v-slot="{ Component }">
        <keep-alive>
          <component :is="Component" />
        </keep-alive>
      </router-view>
    </div>
  </div>
</template>

<script setup>
import { App as CapacitorApp } from '@capacitor/app'

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
.main-layout {
  display: flex;
  flex-direction: column;
  height: 100vh;
  width: 100vw;
  overflow: hidden;
  background: var(--light);
}

.tab-content {
  flex: 1;
  overflow-y: auto;
  position: relative;
  background-color: var(--light);
}

.top-nav {
  display: flex;
  justify-content: space-around;
  align-items: flex-end; /* Align closer to the bottom of the top bar */
  height: 56px;
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-bottom: 1px solid rgba(0, 0, 0, 0.05);
  box-shadow: 0 2px 10px rgba(0,0,0,0.02);
  z-index: 100;
  flex-shrink: 0;
}

.blur-header {
  position: sticky;
  top: 0;
  z-index: 101;
  background: rgba(248, 250, 252, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  padding: calc(16px + env(safe-area-inset-top)) 20px 12px;
}

.app-brand {
  padding-top: 4px;
}
.app-brand h2 {
  font-size: 24px;
  font-weight: 800;
  color: var(--dark);
  margin: 0 0 2px;
  letter-spacing: -0.5px;
}
.app-brand p {
  font-size: 13px;
  font-weight: 600;
  color: var(--primary);
  margin: 0;
  letter-spacing: 0.5px;
  text-transform: uppercase;
  opacity: 0.9;
}

.nav-item {
  display: flex;
  align-items: center;
  justify-content: center;
  flex: 1;
  height: 100%;
  color: #94a3b8;
  text-decoration: none;
  transition: all 0.2s;
  padding-bottom: 12px;
  position: relative;
}

.nav-label {
  font-size: 16px;
  font-weight: 600;
}

.nav-item.active {
  color: var(--primary);
}

.nav-item.active::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 30%;
  right: 30%;
  height: 3px;
  height: 3px;
  background: var(--primary);
  border-radius: 3px 3px 0 0;
}

.exit-btn {
  background: transparent;
  border: none;
  color: var(--danger);
  cursor: pointer;
  opacity: 0.8;
}
.exit-btn .nav-label {
  font-size: 14px;
  font-weight: 500;
}
.exit-btn:active {
  transform: scale(0.95);
}

</style>
