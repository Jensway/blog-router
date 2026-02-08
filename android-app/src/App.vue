<template>
  <div class="app">
    <router-view v-slot="{ Component }">
      <transition name="fade" mode="out-in">
        <component :is="Component" />
      </transition>
    </router-view>
    <div v-if="toast.show" class="toast">{{ toast.text }}</div>
  </div>
</template>

<script setup>
import { reactive, provide } from 'vue'

const toast = reactive({ show: false, text: '' })
let timer = null
function showToast(text) {
  toast.text = text
  toast.show = true
  if (timer) clearTimeout(timer)
  timer = setTimeout(() => {
    toast.show = false
    timer = null
  }, 2500)
}
provide('toast', showToast)
</script>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
  --primary: #0f766e;
  --primary-light: #0d9488;
  --danger: #dc2626;
  --dark: #1e293b;
  --gray: #64748b;
  --light: #f1f5f9;
  --white: #fff;
  --safe-top: env(safe-area-inset-top);
  --safe-bottom: env(safe-area-inset-bottom);
}
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--light);
  color: var(--dark);
  font-size: 15px;
  min-height: 100vh;
  padding-top: var(--safe-top);
  padding-bottom: var(--safe-bottom);
}
.app { min-height: 100vh; }
.fade-enter-active, .fade-leave-active { transition: opacity 0.2s ease; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
.toast {
  position: fixed;
  bottom: calc(24px + var(--safe-bottom));
  left: 50%;
  transform: translateX(-50%);
  background: var(--dark);
  color: var(--white);
  padding: 12px 20px;
  border-radius: 8px;
  font-size: 14px;
  z-index: 9999;
  max-width: 90%;
}
</style>
