<template>
  <div class="main-layout">
    <!-- Universal Brand Header -->
    <header class="app-brand blur-header">
      <div class="brand-logo">
        <img src="/Logo4.png" class="brand-img" alt="logo" />
      </div>
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
  height: 46px;
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
  padding: env(safe-area-inset-top) 0 12px; /* Remove the extra 16px to make it flush to the top */
}

.app-brand {
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
  height: 100%; /* Cover the entire height */
  max-height: 48px; /* Tightly lock height */
  object-fit: fill; /* Deliberately stretch and deform image horizontally so it spans edge-to-edge without cropping top/bottom */
  object-position: center center;
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
  padding-bottom: 6px;
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

</style>
