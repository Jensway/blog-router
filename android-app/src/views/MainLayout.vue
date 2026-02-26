<template>
  <div class="main-layout">
    <!-- Universal Brand Header -->
    <header class="app-brand blur-header">
      <div class="brand-logo">
        <img src="/Logo3.png" class="brand-img" alt="logo" />
      </div>
      <button class="header-exit-btn" @click="exitApp" title="退出">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-log-out"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>
      </button>
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
  padding: calc(16px + env(safe-area-inset-top)) 0 12px;
}

.app-brand {
  padding-top: 4px;
  position: relative; /* Allows exit button to float absolutely over it */
  display: flex;
  align-items: center;
  justify-content: center;
}
.brand-logo {
  display: block;
  width: 100%; /* Take 100% of the screen width */
}
.brand-img {
  width: 100%; /* Stretch horizontally to fill viewport */
  height: auto; 
  max-height: 48px; 
  object-fit: contain;
  object-position: center center; /* Center the logo beautifully when fully stretched */
  display: block;
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

.header-exit-btn {
  position: absolute;
  right: 16px;
  top: 50%;
  transform: translateY(-50%);
  z-index: 10;
  background: rgba(255,255,255,0.85); /* Frosty background to float legibly */
  backdrop-filter: blur(4px);
  border: none;
  cursor: pointer;
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 6px;
  border-radius: 50%;
  color: #64748b;
  box-shadow: 0 2px 6px rgba(0,0,0,0.06);
  transition: all 0.2s;
  outline: 1px solid rgba(226, 232, 240, 0.5);
}
.header-exit-btn:active {
  transform: translateY(-50%) scale(0.9);
  background: #f1f5f9;
}
</style>
