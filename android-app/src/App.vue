<template>
  <div class="app">
    <router-view v-slot="{ Component }">
      <transition name="fade-slide" mode="out-in">
        <component :is="Component" />
      </transition>
    </router-view>
    
    <transition name="toast-slide">
      <div v-if="toast.show" class="toast">
        <span class="toast-icon">✨</span>
        {{ toast.text }}
      </div>
    </transition>
  </div>
</template>

<script setup>
import { reactive, provide, onMounted } from 'vue'
import { App as CapacitorApp } from '@capacitor/app'
import { useRouter } from 'vue-router'
import { api } from './api'
import { Capacitor } from '@capacitor/core'

const toast = reactive({ show: false, text: '' })
const router = useRouter()
let timer = null
function showToast(text) {
  toast.text = text
  toast.show = true
  if (timer) clearTimeout(timer)
  timer = setTimeout(() => {
    toast.show = false
    timer = null
  }, 3000)
}
provide('toast', showToast)

onMounted(() => {
  // Listen for generic App intent URLs (sometimes used by share targets)
  window.addEventListener('appUrlOpen', async (data) => {
    if (data && data.url) {
      toast.text = '收到外部分享链接...'
      toast.show = true
      setTimeout(() => { toast.show = false }, 3000)
    }
  })

  // Listen for natively bound Android SEND share intents
  // This is triggered by Capacitor-share-extension (mostly for text/legacy)
  window.addEventListener('sendIntentReceived', () => {
    checkIntent()
  })

  // Listen for Native Java Injected Android 13+ Scoped Storage Intents
  window.addEventListener('nativeShareIntent', (e) => {
    if (e.detail && e.detail.url) {
      showToast('获取到相册分享附件')
      
      const sharedData = {
        text: '',
        url: e.detail.url,
        title: 'Share Intent'
      }
      localStorage.setItem('shared_intent_payload', JSON.stringify(sharedData))
      router.push('/messages')
    }
  })

  // Also check on boot in case the app was launched directly from Share
  checkIntent()

  // Hardware Back Button (Swipe-to-Go-Back) listener for Android
  let backPressTime = 0
  CapacitorApp.addListener('backButton', ({ canGoBack }) => {
    const topLevelPaths = ['/', '/posts', '/messages', '/settings', '/login']
    const currentPath = router.currentRoute.value.path
    const isTopLevel = topLevelPaths.includes(currentPath)
    
    if (!isTopLevel && canGoBack) {
      // Ordinary subpage, navigate back normally
      router.back()
    } else {
      // Root tab, require double press to exit
      const now = new Date().getTime()
      if (now - backPressTime < 2000) {
        CapacitorApp.exitApp()
      } else {
        backPressTime = now
        showToast('再按一次退出程序')
      }
    }
  })
})

async function checkIntent() {
  try {
    const ShareExtension = Capacitor.Plugins.ShareExtension
    if (!ShareExtension) return
    
    const result = await ShareExtension.checkSendIntentReceived()
    if (result && (result.text || result.url)) {
      showToast('获取到分享内容')
      
      // Store in transient local storage so the target page can pick it up
      const sharedData = {
        text: result.text || '',
        url: result.url || '',      // typically a file:// URI path to the shared image
        title: result.title || ''
      }
      localStorage.setItem('shared_intent_payload', JSON.stringify(sharedData))

      // Navigate to MessageSquare to let them quickly post it, or let them handle it
      router.push('/messages')
    }
  } catch (err) {
    console.error('Share intent check failed', err)
  }
}
</script>

<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

* { margin: 0; padding: 0; box-sizing: border-box; }
:root {
  --primary: #0ea5e9; /* Sky Blue */
  --primary-light: #38bdf8;
  --primary-dark: #0284c7;
  --danger: #ef4444;
  --dark: #0f172a; /* Slate 900 */
  --gray: #64748b; /* Slate 500 */
  --light: #f8fafc; /* Slate 50 */
  --white: #ffffff;
  --safe-top: env(safe-area-inset-top);
  --safe-bottom: env(safe-area-inset-bottom);
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-md: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
}

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--light);
  color: var(--dark);
  font-size: 15px;
  min-height: 100vh;
  padding-top: var(--safe-top);
  padding-bottom: var(--safe-bottom);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

.app { min-height: 100vh; }

/* Page Transitions */
.fade-slide-enter-active, 
.fade-slide-leave-active { 
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); 
}
.fade-slide-enter-from { 
  opacity: 0; 
  transform: translateY(10px); 
}
.fade-slide-leave-to { 
  opacity: 0; 
  transform: translateY(-10px); 
}

/* Premium Toast */
.toast-slide-enter-active,
.toast-slide-leave-active {
  transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
.toast-slide-enter-from,
.toast-slide-leave-to {
  opacity: 0;
  transform: translate(-50%, 20px) scale(0.9);
}

.toast {
  position: fixed;
  bottom: calc(32px + var(--safe-bottom));
  left: 50%;
  transform: translateX(-50%);
  background: rgba(15, 23, 42, 0.9);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  color: var(--white);
  padding: 14px 24px;
  border-radius: 100px;
  font-size: 14px;
  font-weight: 500;
  z-index: 9999;
  max-width: 90%;
  display: flex;
  align-items: center;
  gap: 8px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.2);
  border: 1px solid rgba(255,255,255,0.1);
}
.toast-icon {
  font-size: 16px;
}
</style>
