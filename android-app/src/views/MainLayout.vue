<template>
  <div class="main-layout">
    <!-- Router View for the Tabs -->
    <div class="tab-content">
      <router-view v-slot="{ Component }">
        <keep-alive>
          <component :is="Component" />
        </keep-alive>
      </router-view>
    </div>

    <!-- iOS/Android Style Bottom Navigation Bar -->
    <nav class="bottom-nav">
      <router-link to="/posts" class="nav-item" active-class="active">
        <span class="nav-icon">📝</span>
        <span class="nav-label">日志</label>
      </router-link>
      
      <router-link to="/messages" class="nav-item" active-class="active">
        <span class="nav-icon">💬</span>
        <span class="nav-label">广场</label>
      </router-link>

      <router-link to="/settings" class="nav-item" active-class="active">
        <span class="nav-icon">⚙️</span>
        <span class="nav-label">我的</label>
      </router-link>
    </nav>
  </div>
</template>

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
  /* Add padding bottom to ensure last items aren't hidden behind the nav bar */
  padding-bottom: env(safe-area-inset-bottom); 
}

.bottom-nav {
  display: flex;
  justify-content: space-around;
  align-items: center;
  height: calc(56px + env(safe-area-inset-bottom));
  padding-bottom: env(safe-area-inset-bottom);
  background: rgba(255, 255, 255, 0.9);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-top: 1px solid rgba(0, 0, 0, 0.05);
  box-shadow: 0 -2px 10px rgba(0,0,0,0.02);
  z-index: 100;
}

.nav-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  flex: 1;
  height: 100%;
  color: #94a3b8;
  text-decoration: none;
  transition: all 0.2s;
}

.nav-icon {
  font-size: 22px;
  margin-bottom: 2px;
  filter: grayscale(1);
  opacity: 0.6;
  transition: all 0.2s;
}

.nav-label {
  font-size: 11px;
  font-weight: 500;
}

.nav-item.active {
  color: var(--primary);
}

.nav-item.active .nav-icon {
  filter: grayscale(0);
  opacity: 1;
  transform: translateY(-2px);
}
</style>
