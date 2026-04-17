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
        <li v-for="m in messages" :key="m.id" class="msg-item">
          <div class="msg-card">
            <div class="msg-head">
              <div class="user-info">
                <div class="avatar">{{ m.username.charAt(0).toUpperCase() }}</div>
                <span class="user">{{ m.username }}</span>
                <span class="time">{{ m.created_at }}</span>
              </div>
              <div class="head-actions">
                <button v-if="m.content" class="inline-action-btn" @click.stop="copyText(m.content)" title="复制">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                </button>
                <button v-if="(m.attachments && m.attachments.length > 0) || m.file_url" class="inline-action-btn" @click.stop="openBrowser(fileURL('/api/file/' + ((m.attachments && m.attachments.length > 0) ? m.attachments[0].url : m.file_url)))" title="下载">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                </button>
                <button v-if="m.username === username" class="inline-action-btn" @click.stop="editingMsg && editingMsg.id === m.id ? send() : startEdit(m)" title="编辑">
                  <svg v-if="editingMsg && editingMsg.id === m.id" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
                </button>
                <button v-if="m.username === username" class="inline-action-btn danger-btn" @click.stop="deleteMsg(m.id)" title="删除">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                </button>
              </div>
            </div>
            <p v-if="m.content" class="msg-content">{{ m.content }}</p>
            <div v-if="(m.attachments && m.attachments.length > 0) || m.file_url" class="msg-attachments-container">
              <div v-if="(m.attachments || [{url: m.file_url, type: m.file_type, name: m.file_name}]).filter(a => a.type === 'image').length > 0" 
                   class="msg-attachments-grid" 
                   :class="'grid-' + (((m.attachments || [{url: m.file_url, type: m.file_type}]).filter(a => a.type === 'image').length >= 3) ? '9' : (((m.attachments || [{url: m.file_url, type: m.file_type}]).filter(a => a.type === 'image').length === 2) ? '4' : '1'))">
                <img v-for="(imgAtt, idx) in (m.attachments || [{url: m.file_url, type: m.file_type, name: m.file_name}]).filter(a => a.type === 'image')" 
                     :key="'img'+idx" 
                     :src="fileURL('/api/file/' + imgAtt.url)" 
                     loading="lazy" 
                     class="msg-img-grid-item" 
                     @click="openFullscreen(fileURL('/api/file/' + imgAtt.url))" />
              </div>
              <div v-for="(fileAtt, idx) in (m.attachments || [{url: m.file_url, type: m.file_type, name: m.file_name}]).filter(a => a.type !== 'image' && a.url)" 
                   :key="'file'+idx" 
                   class="msg-attachment non-image">
                <a @click.prevent="openBrowser(fileURL('/api/file/' + fileAtt.url))" href="#" class="msg-file">
                  <span class="file-icon">📄</span>
                  <span class="file-txt">{{ fileAtt.name || '附件' }}</span>
                </a>
              </div>
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
        <div v-if="selectedFiles.length > 0" class="file-preview-float" style="display:flex; overflow-x:auto; gap:12px; padding-bottom:4px;">
          <div v-for="(f, i) in selectedFiles" :key="i" class="file-preview-content" style="flex-shrink:0;">
            <img v-if="isImage(f.file)" :src="f.previewUrl" class="img-mini-preview" />
            <div v-else class="file-mini-icon">📄</div>
            <span class="file-name" :title="f.file.name" style="max-width:80px;">{{ f.file.name }}</span>
            <button class="remove-btn" @click="removeFile(i)" title="移除附件">×</button>
          </div>
        </div>

        <div class="send-bar">
          <input type="file" ref="fileInput" multiple style="display: none" @change="onFileSelected" />
          
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
              :disabled="sending"
              rows="1"
            ></textarea>
            
            <div class="ai-action-bar">
              <div class="ai-tools-left">
                <button class="icon-action-btn" @click="$refs.fileInput.click()" title="发送图片/文件" :disabled="sending">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-paperclip"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
                  <span v-if="selectedFiles.length > 0" class="file-badge">{{ selectedFiles.length }}</span>
                </button>
                
                <button class="icon-action-btn" @click="pasteFromClipboard" title="一键粘贴" :disabled="sending">
                  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-clipboard"><rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>
                </button>
              </div>
              
              <button class="ai-send-btn" @click="send" :disabled="sending || (!newContent.trim() && selectedFiles.length === 0)">
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
const selectedFiles = ref([])

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
  const files = e.target.files
  if (!files || files.length === 0) return
  
  for (let i = 0; i < files.length; i++) {
    const file = files[i]
    let pUrl = ''
    if (isImage(file)) pUrl = URL.createObjectURL(file)
    selectedFiles.value.push({ file, previewUrl: pUrl })
  }
  e.target.value = ''
}

function removeFile(index) {
  const item = selectedFiles.value[index]
  if (item && item.previewUrl) {
    URL.revokeObjectURL(item.previewUrl)
  }
  selectedFiles.value.splice(index, 1)
  if (fileInput.value && selectedFiles.value.length === 0) {
    fileInput.value.value = ''
  }
}

onUnmounted(() => {
  selectedFiles.value.forEach(item => {
    if (item.previewUrl) URL.revokeObjectURL(item.previewUrl)
  })
})

async function load() {
  // Capture payload SYNCHRONOUSLY to prevent App.vue from overwriting it during async network fetch
  const sharedRaw = localStorage.getItem('shared_intent_payload')
  if (sharedRaw) {
    localStorage.removeItem('shared_intent_payload')
    try {
      const shared = JSON.parse(sharedRaw)
      if (shared.text && !shared.url) {
        newContent.value = newContent.value ? newContent.value + '\n' + shared.text : shared.text
      }
      
      if (shared.url) {
        // Run async file bridge extraction independently
        ;(async () => {
          try {
            const convertedUrl = Capacitor.convertFileSrc(shared.url)
            let ext = shared.url.split('.').pop().toLowerCase()
            if (!ext || ext === shared.url.toLowerCase() || ext.length > 5) ext = 'bin'
            
            const fetchRes = await fetch(convertedUrl)
            if (!fetchRes.ok) throw new Error("WebView local proxy denied the read stream")
            const blob = await fetchRes.blob()
            
            let mimeType = blob.type || 'application/octet-stream'
            if (mimeType === 'application/octet-stream' || mimeType === '') {
              if (ext === 'apk') mimeType = 'application/vnd.android.package-archive'
              else if (ext === 'zip') mimeType = 'application/zip'
              else if (ext === 'pdf') mimeType = 'application/pdf'
              else if (ext === 'mp4') mimeType = 'video/mp4'
              else if (ext === 'png') mimeType = 'image/png'
              else if (ext === 'jpg' || ext === 'jpeg') mimeType = 'image/jpeg'
            }
            
            let filename = shared.url.split('/').pop() || `shared_file.${ext}`
            if (!filename.includes('.')) filename += `.${ext}`
            
            const file = new File([blob], filename, { type: mimeType })
            let pUrl = ''
            if (isImage(file)) pUrl = URL.createObjectURL(file)
            selectedFiles.value.push({ file, previewUrl: pUrl })
            
            if (shared.text && !newContent.value) newContent.value = shared.text
          } catch (e) {
            console.error("Failed to read shared file intent:", e)
            toast('文件读取失败，可能是系统权限限制')
          }
        })()
      }
    } catch (e) {}
  }

  loading.value = true
  error.value = ''
  try {
    const sess = await api.session()
    username.value = sess && sess.username ? sess.username : ''
    messages.value = await api.getMessages()
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
  
  if (!content && selectedFiles.value.length === 0) {
    return
  }
  
  sending.value = true
  try {
    if (editingMsg.value) {
      let payload = { content }
      await api.updateMessage(editingMsg.value.id, payload)
      toast('修改成功')
      cancelEdit()
      await load()
      return
    }
    
    if (selectedFiles.value.length > 0) {
      let uploadedAttachments = [];
      for (let i = 0; i < selectedFiles.value.length; i++) {
        const item = selectedFiles.value[i]
        toast(selectedFiles.value.length > 1 ? `正在上传附件 ${i+1}/${selectedFiles.value.length}…` : '正在上传附件…')
        const uploadRes = await api.uploadFile(item.file)
        
        let pURL = '';
        let pName = item.file.name;
        let pType = item.file.type.startsWith('image/') ? 'image' : 'file';
        
        if (uploadRes && uploadRes.filename) {
          pURL = uploadRes.filename
          pName = uploadRes.orig_name || item.file.name
          pType = uploadRes.type || pType
        } else if (uploadRes && uploadRes.urls && uploadRes.urls.length > 0) {
          pURL = uploadRes.urls[0].url.replace('/api/file/', '')
          pName = uploadRes.urls[0].name || item.file.name
          pType = uploadRes.urls[0].type || pType
        } else if (uploadRes && uploadRes.url) { 
          pURL = uploadRes.url.replace('/api/file/', '')
          pName = uploadRes.name || item.file.name
        }
        
        if (pURL) {
           uploadedAttachments.push({ url: pURL, type: pType, name: pName })
        }
      }
      
      let payload = { 
        content: content,
        attachments: uploadedAttachments
      }
      await api.createMessage(payload)
      
    } else {
      let payload = { content }
      await api.createMessage(payload)
    }
    
    newContent.value = ''
    while (selectedFiles.value.length > 0) removeFile(0)
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
  while (selectedFiles.value.length > 0) removeFile(0)
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

/* Chat Item */
.list { list-style: none; margin: 0; padding: 0; }
.msg-item {
  margin-bottom: 16px;
  width: 100%;
}

.msg-card {
  margin: 0 20px;
  background: var(--white);
  border-radius: 20px;
  padding: 16px;
  box-shadow: var(--shadow-sm);
  border: 1px solid rgba(0,0,0,0.02);
}

.msg-head { 
  display: flex; 
  justify-content: space-between; 
  align-items: center;
  margin-bottom: 12px; 
}
.user-info { display: flex; align-items: center; gap: 8px; flex: 1; min-width: 0; }
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
  flex-shrink: 0;
}
.user { font-weight: 700; font-size: 15px; color: var(--dark); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.time { font-size: 11px; color: #94a3b8; flex-shrink: 0; }

.head-actions { display: flex; align-items: center; gap: 2px; flex-shrink: 0; }

.inline-action-btn {
  background: transparent;
  border: none;
  padding: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  color: #94a3b8;
  cursor: pointer;
  transition: all 0.2s;
}
.inline-action-btn svg {
  width: 15px;
  height: 15px;
}
.inline-action-btn:active {
  background: rgba(0,0,0,0.05);
  color: var(--primary);
}
.danger-btn:active {
  color: var(--danger);
}
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
  line-height: 1.5;
  color: var(--dark);
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.msg-attachments-container {
  margin-top: 10px;
}

.msg-attachments-grid {
  display: grid;
  gap: 6px;
  border-radius: 8px;
  overflow: hidden;
}
.grid-1 { grid-template-columns: 1fr; }
.grid-1 .msg-img-grid-item { max-height: 280px; width: auto; max-width: 100%; border-radius: 8px; }
.grid-4 { grid-template-columns: repeat(2, 1fr); max-width: 250px; border-radius: 8px;}
.grid-9 { grid-template-columns: repeat(3, 1fr); max-width: 320px; border-radius: 8px;}
.msg-img-grid-item {
  width: 100%;
  aspect-ratio: 1;
  object-fit: cover;
  cursor: zoom-in;
  border-radius: 6px;
}

.msg-attachment.non-image {
  margin-top: 8px;
  display: block;
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
