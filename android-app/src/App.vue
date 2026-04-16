<template>
  <div class="app">
    <router-view v-slot="{ Component }">
      <transition name="fade-slide" mode="out-in">
        <component :is="Component" />
      </transition>
    </router-view>
    
    <!-- 长提示：毛玻璃模态卡片 (Apple 系风格) -->
    <transition name="fade">
      <div v-if="alert.show" class="alert-overlay" @click.self="alert.show = false">
        <div class="alert-card">
          <div class="alert-body">
            <h3 v-if="alert.title" class="alert-title">{{ alert.title }}</h3>
            <div class="alert-text">{{ alert.text }}</div>
          </div>
          <div class="alert-action" @click="alert.show = false">
            <span>知道了</span>
          </div>
        </div>
      </div>
    </transition>

    <!-- 短提示：胶囊药丸悬浮框 -->
    <transition name="toast-slide">
      <div v-if="toast.show" class="toast">
        <span class="toast-icon">✨</span>
        <span class="toast-content">{{ toast.text }}</span>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { reactive, provide, onMounted } from 'vue'
import { App as CapacitorApp } from '@capacitor/app'
import { useRouter } from 'vue-router'
import { api } from './api'
import { Capacitor, registerPlugin } from '@capacitor/core'

const NativeShareProxy = registerPlugin('NativeShareProxy')
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

  // Setup the NativeShareProxy Queue Drainer
  const checkNativeShareQueue = async () => {
    try {
      const data = await NativeShareProxy.getPendingIntents()
      if (data && data.url) {
        showToast('获取到应用外文件分享')
        const sharedData = { text: '', url: data.url, title: 'Share Intent' }
        localStorage.setItem('shared_intent_payload', JSON.stringify(sharedData))
        if (router.currentRoute.value.path === '/messages') {
          window.dispatchEvent(new CustomEvent('reloadMessagesIntent'))
        } else {
          router.push('/messages')
        }
        // Automatically check if there's more in the queue instantly
        setTimeout(checkNativeShareQueue, 100);
      } else if (data && data.text) {
        showToast('获取到外部文本分享')
        const sharedData = { text: data.text, url: '', title: 'Share Intent Text' }
        localStorage.setItem('shared_intent_payload', JSON.stringify(sharedData))
        if (router.currentRoute.value.path === '/messages') {
          window.dispatchEvent(new CustomEvent('reloadMessagesIntent'))
        } else {
          router.push('/messages')
        }
        setTimeout(checkNativeShareQueue, 100);
      }
    } catch (e) {
      // Silently ignore if executing on standard Web Browsers where plugin doesn't exist
    }
  }

  // Listen for Native Java structural Pings that signal new intents arrived
  window.addEventListener('nativeShareIntentPing', () => {
    checkNativeShareQueue()
  })

  // CRITICAL: WebViews drop evaluateJavascript when backgrounded!
  // Entering the Share Menu pushes the app to the background, and returning triggers appStateChange.
  CapacitorApp.addListener('appStateChange', ({ isActive }) => {
    if (isActive) {
      checkNativeShareQueue()
    }
  })

  // Also check exactly once the root Vue app successfully mounts (Replaces legacy _preloaded logic)
  checkNativeShareQueue()

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

const alert = reactive({ show: false, text: '', title: '' })
function showAlert(text, title = '提示') {
  alert.text = text
  alert.title = title
  alert.show = true
}
provide('alert', showAlert)
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

/* Apple 风长提示：柔和毛玻璃模态卡片 */
.fade-enter-active, .fade-leave-active { transition: opacity 0.25s ease; }
.fade-enter-from, .fade-leave-to { opacity: 0; }

.alert-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.3);
  backdrop-filter: blur(5px);
  -webkit-backdrop-filter: blur(5px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 10000;
}

.alert-card {
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  width: 290px;
  border-radius: 16px;
  box-shadow: 0 16px 40px rgba(0, 0, 0, 0.1);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  animation: popIn 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}

@keyframes popIn {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}

.alert-body {
  padding: 24px 20px 20px;
  text-align: center;
}

.alert-title {
  font-size: 17px;
  font-weight: 600;
  margin-bottom: 8px;
  color: var(--dark);
}

.alert-text {
  font-size: 14px;
  line-height: 1.4;
  color: var(--gray);
  max-height: 300px;
  overflow-y: auto;
  text-align: left; /* 左对齐解决狗啃边 */
}

.alert-action {
  border-top: 1px solid rgba(0, 0, 0, 0.08);
  padding: 14px 0;
  text-align: center;
  color: #007AFF; /* Apple Blue */
  font-size: 17px;
  font-weight: 600;
  cursor: pointer;
  background: transparent;
  transition: background 0.2s;
}

.alert-action:active {
  background: rgba(0, 0, 0, 0.05);
}
</style>
