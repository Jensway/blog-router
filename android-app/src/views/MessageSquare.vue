<template>
  <div class="page has-bottom-nav">
    <!-- Pull-to-Refresh Indicator (Moved OUTSIDE the scroll container to prevent clipping) -->
    <div class="ptr-indicator" ref="ptrIndicator">
      <div class="ptr-spinner"></div>
      <span class="ptr-text">下拉刷新</span>
    </div>

    <div class="messages-container" ref="msgContainer">

      <div v-if="loading && !ptrRefreshing" class="state-box">
        <div class="loader"></div>
        <p>加载中…</p>
      </div>
      <div v-else-if="error" class="state-box error-box">
        <p>{{ error }}</p>
      </div>
      
      <ul v-else class="list">
        <li v-for="m in messages" :key="m.id" class="msg-swipe-container">
          <div class="msg-swipe-track">
            <!-- Main Card -->
            <div class="msg-card">
              <div class="msg-head">
                <div class="user-info">
                  <div class="avatar">{{ m.username.charAt(0).toUpperCase() }}</div>
                  <span class="user">{{ m.username }}</span>
                </div>
                <div class="head-actions">
                  <span class="time">{{ m.created_at }}</span>
                </div>
              </div>
              <p v-if="m.content" class="msg-content">{{ m.content }}</p>
              <div v-if="m.file_url" class="msg-attachment">
                <img v-if="m.file_type === 'image'" :src="fileURL('/api/file/' + m.file_url)" class="msg-img" loading="lazy" @click="openFullscreen(fileURL('/api/file/' + m.file_url))" />
                <a v-else @click.prevent="openBrowser(fileURL('/api/file/' + m.file_url))" href="#" class="msg-file">
                  <span class="file-icon">📄</span>
                  <span class="file-txt">{{ m.file_name || '附件' }}</span>
                </a>
              </div>
            </div>

            <!-- Swipe Actions -->
            <div class="msg-actions">
              <button class="action-btn action-edit" v-if="m.username === username" @click="startEdit(m)">
                <span>✏️</span>
                <small>编辑</small>
              </button>
              <button class="action-btn action-copy" v-if="m.content" @click="copyText(m.content)">
                <span>📋</span>
                <small>复制</small>
              </button>
              <button class="action-btn action-download" v-if="m.file_url" @click="openBrowser(fileURL('/api/file/' + m.file_url))">
                <span>📥</span>
                <small>下载</small>
              </button>
              <button class="action-btn action-delete" v-if="m.username === username" @click="deleteMsg(m.id)">
                <span>🗑️</span>
                <small>删除</small>
              </button>
            </div>
          </div>
        </li>
      </ul>
      <div v-if="!loading && !error && messages.length === 0" class="state-box empty-box">
        <div class="empty-icon">💬</div>
        <p>暂无消息，来第一个发言吧！</p>
      </div>
    </div>

    <!-- Enhanced Bottom Input Area -->
    <div class="send-area-wrapper">
      <div class="send-area glass-bar">
        <!-- Preview Selected File -->
        <div v-if="selectedFile" class="file-preview-float">
          <div class="file-preview-content">
            <img v-if="isImage(selectedFile)" :src="previewUrl" class="img-mini-preview" />
            <div v-else class="file-mini-icon">📄</div>
            <span class="file-name" :title="selectedFile.name">{{ selectedFile.name }}</span>
            <button class="remove-btn" @click="removeFile" title="移除附件">×</button>
          </div>
        </div>

        <div class="send-bar">
          <input type="file" ref="fileInput" style="display: none" @change="onFileSelected" />
          
          <div class="ai-input-container">
            <div v-if="editingMsg" class="edit-header">
              <span>正在编辑消息...</span>
              <button class="cancel" @click="cancelEdit" title="取消编辑">×</button>
            </div>
            <textarea 
              ref="textInput"
              v-model="newContent" 
              class="chat-input-area"
              placeholder="说点什么…" 
              maxlength="1000" 
              @input="autoResize"
              @keydown.enter.prevent="handleEnter"
              :disabled="sending"
              rows="1"
            ></textarea>
            
            <div class="ai-action-bar">
              <div class="ai-tools-left">
                <button class="icon-action-btn" @click="$refs.fileInput.click()" title="发送图片/文件" :disabled="sending">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-paperclip"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
                  <span v-if="selectedFile" class="file-badge">1</span>
                </button>
                
                <button class="icon-action-btn" @click="pasteFromClipboard" title="一键粘贴" :disabled="sending">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-clipboard"><rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>
                </button>
              </div>
              
              <button class="ai-send-btn" @click="send" :disabled="sending || (!newContent.trim() && !selectedFile)">
                <span v-if="sending" class="spinner-small"></span>
                <svg v-else xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-send"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onActivated, inject, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fileURL } from '../api'
import { Clipboard } from '@capacitor/clipboard'
import { Browser } from '@capacitor/browser'
import { Capacitor } from '@capacitor/core'

const router = useRouter()
const toast = inject('toast')
const messages = ref([])
const loading = ref(true)
const error = ref('')
const newContent = ref('')
const sending = ref(false)
const editingMsg = ref(null)
const username = ref('')

const textInput = ref(null)
const fileInput = ref(null)
const selectedFile = ref(null)
const previewUrl = ref('')

// Create a temporary image to feed Viewer.js programmatically
function openFullscreen(url) {
  const img = new Image();
  img.src = url;
  const viewer = new window.Viewer(img, {
    hidden: function () {
      viewer.destroy();
    },
    toolbar: false,
    navbar: false,
    button: true, // Show close button in top right
    title: false,
    tooltip: false,
    movable: true,
    rotatable: false,
    scalable: false,
    transition: true,
    fullscreen: false,
    keyboard: false
  });
  viewer.show();
}

function autoResize() {
  if (!textInput.value) return;
  textInput.value.style.height = 'auto'; // Reset
  textInput.value.style.height = Math.min(textInput.value.scrollHeight, 120) + 'px'; // Cap at ~5 lines
}

function handleEnter(e) {
  if (e.shiftKey) return; // Allow Shift+Enter for newlines
  send();
}

function isImage(file) {
  return file && file.type.startsWith('image/')
}

async function openBrowser(url) {
  try {
    await Browser.open({ url })
  } catch(e) {
    window.open(url, '_blank')
  }
}

async function copyText(text) {
  try {
    await Clipboard.write({ string: text })
    toast('已复制到剪贴板')
  } catch (err) {
    // Fallback for web if @capacitor/clipboard fails in browser
    try {
      await navigator.clipboard.writeText(text)
      toast('已复制到剪贴板')
    } catch(e) {
      toast('复制失败')
    }
  }
}

async function pasteFromClipboard() {
  try {
    const { type, value } = await Clipboard.read()
    if (value) {
      newContent.value = newContent.value + value
      toast('已读取剪贴板')
    } else {
      toast('剪贴板为空')
    }
  } catch (err) {
    // Fallback for web
    try {
      const text = await navigator.clipboard.readText()
      newContent.value = newContent.value + text
    } catch(e) {
      toast('无法读取剪贴板，请检查权限')
    }
  }
}

function onFileSelected(e) {
  const file = e.target.files[0]
  if (!file) return
  
  if (previewUrl.value) {
    URL.revokeObjectURL(previewUrl.value)
  }
  
  selectedFile.value = file
  if (isImage(file)) {
    previewUrl.value = URL.createObjectURL(file)
  }
  e.target.value = ''
}

function removeFile() {
  selectedFile.value = null
  if (previewUrl.value) {
    URL.revokeObjectURL(previewUrl.value)
    previewUrl.value = ''
  }
  if (fileInput.value) {
    fileInput.value.value = ''
  }
}

onUnmounted(() => {
  if (previewUrl.value) {
    URL.revokeObjectURL(previewUrl.value)
  }
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const sess = await api.session()
    username.value = sess && sess.username ? sess.username : ''
    messages.value = await api.getMessages()
    
    // Check if we arrived here from an Android system Share Intent
    const sharedRaw = localStorage.getItem('shared_intent_payload')
    if (sharedRaw) {
      localStorage.removeItem('shared_intent_payload')
      const shared = JSON.parse(sharedRaw)
      
      if (shared.text && !shared.url) {
        newContent.value = shared.text
      }
      
      if (shared.url) {
        try {
          // Utilize Capacitor's native local server to bypass Android 11+ strict Scoped Storage blocks!
          // This safely transforms 'content://' or 'file://' intents into 'http://localhost/_capacitor_file_/' streams.
          const convertedUrl = Capacitor.convertFileSrc(shared.url);
          
          let ext = shared.url.split('.').pop().toLowerCase()
          if (!ext || ext === shared.url.toLowerCase() || ext.length > 5) {
            ext = 'bin' // generic fallback
          }
          
          // Natively stream the binary data into WebView memory directly
          const fetchRes = await fetch(convertedUrl);
          if (!fetchRes.ok) throw new Error("WebView local proxy denied the read stream");
          const blob = await fetchRes.blob();
          
          let mimeType = blob.type || 'application/octet-stream'
          
          // Fallback manual mime assignment if the proxy couldn't intuit it
          if (mimeType === 'application/octet-stream' || mimeType === '') {
            if (ext === 'apk') mimeType = 'application/vnd.android.package-archive'
            else if (ext === 'zip') mimeType = 'application/zip'
            else if (ext === 'pdf') mimeType = 'application/pdf'
            else if (ext === 'mp4') mimeType = 'video/mp4'
            else if (ext === 'png') mimeType = 'image/png'
            else if (ext === 'jpg' || ext === 'jpeg') mimeType = 'image/jpeg'
          }
          
          let filename = shared.url.split('/').pop() || `shared_file.${ext}`
          // Fallback missing extensions on the filename just in case
          if (!filename.includes('.')) filename += `.${ext}`
          
          const file = new File([blob], filename, { type: mimeType })
          
          selectedFile.value = file
          previewUrl.value = URL.createObjectURL(file)
          if (shared.text) newContent.value = shared.text
        } catch (e) {
          console.error("Failed to read shared file intent:", e)
          toast('文件读取失败，可能是系统权限限制')
        }
      }
    }
  } catch (e) {
    error.value = e.message
    toast(e.message)
  } finally {
    loading.value = false
  }
}

async function deleteMsg(id) {
  if (confirm('是否要删除这条消息？')) {
    try {
      await api.deleteMessage(id)
      toast('已删除')
      await load()
    } catch (e) {
      toast(e.message || '删除失败，可能没有权限')
    }
  }
}

async function send() {
  let content = newContent.value.trim()
  
  if (!content && !selectedFile.value) {
    return
  }
  
  sending.value = true
  try {
    let payload = { content }
    
    if (editingMsg.value) {
      await api.updateMessage(editingMsg.value.id, payload)
      toast('修改成功')
      cancelEdit()
      await load()
      return
    }
    
    if (selectedFile.value) {
      toast('正在上传附件…')
      const uploadRes = await api.uploadFile(selectedFile.value)
      toast('上传成功，发送消息…')
      
      // Share-center's /api/upload endpoint for post_id=0 returns {"filename": "msg_xxx.ext", "url": "/api/file/msg_xxx.ext", "type": "image"}
      if (uploadRes && uploadRes.filename) {
        payload.file_url = uploadRes.filename
        payload.file_name = uploadRes.orig_name || selectedFile.value.name
        payload.file_type = uploadRes.type || (selectedFile.value.type.startsWith('image/') ? 'image' : 'file')
      } else if (uploadRes && uploadRes.urls && uploadRes.urls.length > 0) {
        // Fallback for V5 list format if present
        payload.file_url = uploadRes.urls[0].url.replace('/api/file/', '')
        payload.file_name = uploadRes.urls[0].name || selectedFile.value.name
        payload.file_type = uploadRes.urls[0].type || 'file'
      } else if (uploadRes && uploadRes.url) { 
        payload.file_url = uploadRes.url.replace('/api/file/', '')
        payload.file_name = uploadRes.name || selectedFile.value.name
        payload.file_type = selectedFile.value.type.startsWith('image/') ? 'image' : 'file'
      }
    }
    
    await api.createMessage(payload)
    newContent.value = ''
    removeFile()
    await load()
    
    // Smooth scroll to top after sending
    window.scrollTo({ top: 0, behavior: 'smooth' })
  } catch (e) {
    toast(e.message || '发送失败')
  } finally {
    sending.value = false
  }
}

// Pure Vue Pull-to-Refresh State
const msgContainer = ref(null)
const ptrIndicator = ref(null)
const ptrRefreshing = ref(false)
let ptrStartY = 0, ptrPulling = false, ptrDy = 0

function startEdit(m) {
  editingMsg.value = m
  newContent.value = m.content || ''
  if (textInput.value) {
    textInput.value.focus()
  }
}

function cancelEdit() {
  editingMsg.value = null
  newContent.value = ''
  removeFile()
}

function initPTR() {
  const el = msgContainer.value
  if (!el) return

  el.addEventListener('touchstart', (e) => {
    // Only allow PTR when scrolled to the very top of the list
    if (el.scrollTop <= 0 && !ptrRefreshing.value) {
      ptrStartY = e.touches[0].clientY
      ptrPulling = true
      ptrDy = 0
      el.style.transition = 'none'
    }
  }, { passive: true })

  el.addEventListener('touchmove', (e) => {
    if (!ptrPulling) return
    ptrDy = e.touches[0].clientY - ptrStartY
    if (ptrDy < 0) { ptrPulling = false; return }
    if (e.cancelable) e.preventDefault()

    const pull = Math.min(ptrDy * 0.4, 80)
    el.style.transform = 'translateY(' + pull + 'px)'
    const ind = ptrIndicator.value
    if (ind) {
      ind.style.opacity = Math.min(pull / 40, 1)
      if (pull >= 50) {
        ind.classList.add('ready')
        ind.querySelector('.ptr-text').textContent = '释放刷新'
      } else {
        ind.classList.remove('ready')
        ind.querySelector('.ptr-text').textContent = '下拉刷新'
      }
    }
  }, { passive: false })

  el.addEventListener('touchend', () => {
    if (!ptrPulling) return
    ptrPulling = false
    const pull = Math.min(ptrDy * 0.4, 80)
    el.style.transition = 'transform 0.3s ease'

    if (pull >= 50) {
      el.style.transform = 'translateY(50px)'
      const ind = ptrIndicator.value
      if (ind) ind.querySelector('.ptr-text').textContent = '刷新中...'
      if (navigator.vibrate) navigator.vibrate(10)
      ptrRefreshing.value = true
      Promise.resolve(load()).finally(() => {
        el.style.transform = 'translateY(0)'
        el.scrollTo({ top: 0, behavior: 'smooth' }) // Ensure it jumps to the top list element
        if (ind) {
          ind.style.opacity = '0'
          ind.classList.remove('ready')
          ind.querySelector('.ptr-text').textContent = '下拉刷新'
        }
        ptrRefreshing.value = false
      })
    } else {
      el.style.transform = 'translateY(0)'
      const ind = ptrIndicator.value
      if (ind) {
        ind.style.opacity = '0'
        ind.classList.remove('ready')
      }
    }
  }, { passive: true })
}

onMounted(() => {
  load()
  window.addEventListener('reloadMessagesIntent', load)
  initPTR()
})

onActivated(load)

onUnmounted(() => {
  window.removeEventListener('reloadMessagesIntent', load)
})
</script>

<style scoped>
.page { 
  position: relative;
  height: 100%;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  background-color: var(--light);
}

/* PTR Indicator */
.ptr-indicator {
  position: absolute;
  top: 16px; /* Positioned slightly below header/top edge */
  left: 0;
  right: 0;
  height: 50px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--gray);
  font-size: 13px;
  opacity: 0;
  pointer-events: none;
  z-index: 1; /* Below the container initially */
}
.messages-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  padding: 16px 0 calc(128px + env(safe-area-inset-bottom, 0px));
  overflow-x: hidden;
  overscroll-behavior-y: none;
  position: relative;
  z-index: 2;
  background: var(--light);
}
.ptr-spinner {
  width: 18px;
  height: 18px;
  margin-right: 6px;
  border: 2px solid var(--gray);
  border-top-color: transparent;
  border-radius: 50%;
}
.ptr-indicator.ready .ptr-spinner {
  animation: ptr-spin-msg 0.6s linear infinite;
}
@keyframes ptr-spin-msg { 100% { transform: rotate(360deg); } }

/* Base States */
.state-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 60px 20px;
  color: var(--gray);
}
.loader {
  width: 32px;
  height: 32px;
  border: 3px solid #e2e8f0;
  border-bottom-color: var(--primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}
@keyframes spin { 100% { transform: rotate(360deg); } }
.error-box { color: var(--danger); font-weight: 500; }
.empty-icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }

/* Chat Bubbles Swipe Container */
.list { list-style: none; margin: 0; padding: 0; }
.msg-swipe-container {
  width: 100vw;
  overflow-x: auto;
  scroll-snap-type: x mandatory;
  -webkit-overflow-scrolling: touch;
  scrollbar-width: none; /* Firefox */
  margin-bottom: 16px;
}
.msg-swipe-container::-webkit-scrollbar { display: none; }

.msg-swipe-track {
  display: flex;
  width: max-content;
}

.msg-card {
  width: calc(100vw - 40px); /* Fill screen minus padding */
  scroll-snap-align: center;
  margin: 0 20px;
  background: var(--white);
  border-radius: 20px;
  padding: 16px;
  box-shadow: var(--shadow-sm);
  border: 1px solid rgba(0,0,0,0.02);
}

.msg-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  padding-right: 20px; /* Padding for the trailing edge */
  scroll-snap-align: end;
}

.action-btn {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  width: 60px;
  height: 100%;
  border-radius: 16px;
  border: none;
  color: white;
  font-weight: 600;
  cursor: pointer;
}
.action-btn span { font-size: 20px; margin-bottom: 4px; }
.action-edit { background: var(--secondary); }
.action-copy { background: var(--primary-light); }
.action-download { background: #10b981; } /* Emerald */
.action-delete { background: var(--danger); }

.msg-head { 
  display: flex; 
  justify-content: space-between; 
  align-items: center;
  margin-bottom: 12px; 
}
.user-info { display: flex; align-items: center; gap: 8px; }
.avatar {
  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-light) 100%);
  color: white;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 13px;
}
.user { font-weight: 700; font-size: 15px; color: var(--dark); }

.head-actions { display: flex; align-items: center; gap: 8px; }
.time { font-size: 12px; color: #94a3b8; }

.msg-copy-btn {
  background: none;
  border: none;
  color: var(--gray);
  font-size: 14px;
  cursor: pointer;
  padding: 4px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}
.msg-copy-btn:hover { background: #f1f5f9; color: var(--primary); }
.msg-copy-btn:active { transform: scale(0.9); }

.msg-content { 
  font-size: 15px;
  line-height: 1.6; 
  color: #334155;
  word-break: break-word; 
}

.msg-attachment { margin-top: 12px; }
.msg-img {
  max-width: 100%;
  max-height: 250px;
  border-radius: 12px;
  object-fit: cover;
  box-shadow: var(--shadow-sm);
  border: 1px solid #f1f5f9;
}
.msg-file {
  font-size: 14px;
  font-weight: 500;
  color: var(--primary-dark);
  text-decoration: none;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: #f0f9ff;
  padding: 12px 16px;
  border-radius: 12px;
  border: 1px solid #e0f2fe;
  transition: all 0.2s;
}
.msg-file:hover { background: #e0f2fe; }

/* Bottom Input Area */
.send-area-wrapper {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  background: var(--light);
  z-index: 100;
  padding-bottom: env(safe-area-inset-bottom, 0px);
  box-shadow: 0 -2px 10px rgba(0,0,0,0.03);
  pointer-events: auto;
}

.send-area.glass-bar {
  background: var(--white);
  padding: 12px 16px;
  border-top: 1px solid #e2e8f0;
}

.file-preview-float {
  background: #f8fafc;
  border-radius: 16px;
  padding: 8px 12px;
  margin-bottom: 12px;
  border: 1px solid #e2e8f0;
}
.file-preview-content {
  display: flex;
  align-items: center;
  gap: 12px;
}
.img-mini-preview {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  object-fit: cover;
}
.file-mini-icon {
  width: 36px;
  height: 36px;
  border-radius: 8px;
  background: #e2e8f0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
}
.file-name {
  flex: 1;
  font-size: 13px;
  font-weight: 600;
  color: var(--dark);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.remove-btn {
  background: #fef2f2;
  color: var(--danger);
  border: none;
  width: 28px;
  height: 28px;
  border-radius: 14px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  cursor: pointer;
}

.file-badge {
  position: absolute;
  top: -4px;
  right: -4px;
  background: var(--danger);
  color: white;
  font-size: 10px;
  font-weight: bold;
  height: 16px;
  width: 16px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 2px solid white;
}

.send-bar {
  display: flex;
  gap: 8px;
  align-items: center;
}

.ai-input-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  background: #ffffff;
  border-radius: 16px;
  border: 1px solid #e2e8f0;
  box-shadow: 0 2px 6px rgba(0, 0, 0, 0.02);
  overflow: hidden;
  transition: border-color 0.2s, box-shadow 0.2s;
}

.ai-input-container:focus-within {
  border-color: var(--primary);
  box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
}

.chat-input-area {
  width: 100%;
  min-height: 44px;
  padding: 12px 14px 4px 14px;
  border: none;
  background: transparent;
  font-size: 15px;
  color: var(--dark);
  line-height: 1.4;
  resize: none;
  font-family: inherit;
  box-sizing: border-box;
  overflow-y: hidden;
}

.edit-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 6px 14px;
  background: #f0fdf4;
  color: var(--primary);
  font-size: 12px;
  font-weight: bold;
  border-bottom: 1px solid rgba(16, 185, 129, 0.1);
}
.edit-header .cancel {
  background: none;
  border: none;
  font-size: 18px;
  line-height: 1;
  color: var(--gray);
  cursor: pointer;
}

.chat-input-area:focus {
  outline: none;
}

.ai-action-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 4px 8px 8px 8px;
}

.ai-tools-left {
  display: flex;
  gap: 4px;
}

.icon-action-btn {
  width: 36px;
  height: 36px;
  border-radius: 12px;
  border: none;
  background: transparent;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #64748b;
  cursor: pointer;
  transition: all 0.2s;
  position: relative; /* For file-badge */
}

.icon-action-btn:hover {
  background: #f1f5f9;
  color: var(--primary);
}

.icon-action-btn:active {
  transform: scale(0.95);
}

.ai-send-btn {
  width: 36px;
  height: 36px;
  border-radius: 12px;
  border: none;
  background: var(--primary);
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s;
}

.ai-send-btn:disabled {
  background: var(--bg-hover);
  color: #ccc;
  border-color: var(--border);
  box-shadow: none;
}
.ai-send-btn svg {
  margin-left: -2px; /* Visual balance for paper plane arrow */
}

.ai-send-btn:not(:disabled):active {
  transform: scale(0.95);
}

.spinner-small {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255,255,255,0.3);
  border-radius: 50%;
  border-top-color: white;
  animation: spin 0.8s linear infinite;
}

/* Override existing file-badge positioning to fit the new SVG icon */
.file-badge {
  position: absolute;
  top: -2px;
  right: -2px;
  background: var(--danger);
  color: white;
  font-size: 11px;
  font-weight: bold;
  height: 16px;
  width: 16px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1.5px solid white;
}
</style>
