<template>
  <div class="page has-bottom-nav">
    <header class="header blur-header">
      <div style="width: 24px;"></div> <!-- Spacer -->
      <h1>消息广场</h1>
      <div style="width: 24px;"></div> <!-- Spacer -->
    </header>
    
    <div class="messages-container">
      <div v-if="loading" class="state-box">
        <div class="loader"></div>
        <p>加载中…</p>
      </div>
      <div v-else-if="error" class="state-box error-box">
        <p>{{ error }}</p>
      </div>
      
      <ul v-else class="list">
        <li v-for="m in messages" :key="m.id" class="msg-card">
          <div class="msg-head">
            <div class="user-info">
              <div class="avatar">{{ m.username.charAt(0).toUpperCase() }}</div>
              <span class="user">{{ m.username }}</span>
            </div>
            <div class="head-actions">
              <span class="time">{{ m.created_at }}</span>
              <button v-if="m.content" class="msg-copy-btn" @click="copyText(m.content)" title="复制消息">
                <span class="copy-icon">⎘</span>
              </button>
            </div>
          </div>
          <p v-if="m.content" class="msg-content">{{ m.content }}</p>
          <div v-if="m.file_url" class="msg-attachment">
            <img v-if="m.file_type === 'image'" :src="fileURL('/api/file/' + m.file_url)" class="msg-img" loading="lazy" />
            <a v-else @click.prevent="openBrowser(fileURL('/api/file/' + m.file_url))" href="#" class="msg-file">
              <span class="file-icon">📄</span>
              <span class="file-txt">{{ m.file_name || '附件' }}</span>
            </a>
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
          
          <button class="attach-btn" @click="$refs.fileInput.click()" title="发送图片/文件" :disabled="sending">
            <span class="attach-icon">📎</span>
          </button>
          
          <button class="paste-btn" @click="pasteFromClipboard" title="一键粘贴" :disabled="sending">
             📋
          </button>
          
          <input 
            v-model="newContent" 
            class="chat-input"
            placeholder="说点什么…" 
            maxlength="500" 
            @keyup.enter="send" 
            :disabled="sending"
          />
          
          <button class="send-btn" @click="send" :disabled="sending || (!newContent.trim() && !selectedFile)">
            <span v-if="sending" class="spinner-small"></span>
            <span v-else>发送</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, inject, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, fileURL } from '../api'
import { Clipboard } from '@capacitor/clipboard'
import { Browser } from '@capacitor/browser'

const router = useRouter()
const toast = inject('toast')
const messages = ref([])
const loading = ref(true)
const error = ref('')
const newContent = ref('')
const sending = ref(false)

const fileInput = ref(null)
const selectedFile = ref(null)
const previewUrl = ref('')

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
    messages.value = await api.getMessages()
  } catch (e) {
    error.value = e.message
    toast(e.message)
  } finally {
    loading.value = false
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
    
    if (selectedFile.value) {
      toast('正在上传附件…')
      const uploadRes = await api.uploadFile(selectedFile.value)
      
      if (uploadRes && uploadRes.urls && uploadRes.urls.length > 0) {
        toast('上传成功，发送消息…')
        payload.file_url = uploadRes.urls[0].url.replace('/api/file/', '')
        payload.file_name = uploadRes.urls[0].name
        payload.file_type = uploadRes.urls[0].type
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

onMounted(load)
</script>

<style scoped>
.page { 
  position: relative;
  min-height: 100vh;
  background-color: var(--light);
}

.blur-header {
  position: sticky;
  top: 0;
  z-index: 50;
  background: rgba(248, 250, 252, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  padding: 12px 20px;
  border-bottom: 1px solid rgba(0,0,0,0.05);
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.back-btn {
  background: none;
  border: none;
  font-size: 15px;
  font-weight: 600;
  color: var(--primary);
  display: flex;
  align-items: center;
  gap: 4px;
  padding: 8px 0;
  cursor: pointer;
  width: 70px;
}
.back-btn .icon { font-size: 18px; margin-top: -2px; }

.header h1 { 
  font-size: 20px; 
  font-weight: 800; 
  color: var(--dark);
  margin: 0;
  text-align: center;
}

.messages-container {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  padding: 16px 20px 0; /* Removed large bottom padding since send-area is now handled by layout wrapper */
}

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

/* Chat Bubbles */
.list { list-style: none; }
.msg-card {
  background: var(--white);
  border-radius: 20px;
  padding: 16px;
  margin-bottom: 16px;
  box-shadow: var(--shadow-sm);
  border: 1px solid rgba(0,0,0,0.02);
}

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
  padding: 16px 20px calc(16px + var(--safe-bottom));
  background: linear-gradient(to top, rgba(248, 250, 252, 1) 60%, rgba(248, 250, 252, 0) 100%);
  z-index: 100;
  pointer-events: none; /* Let clicks pass through background */
  padding-bottom: 24px; /* Increased bottom padding to clear the bottom nav */
}

.send-area.glass-bar {
  background: rgba(255, 255, 255, 0.95);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-radius: 24px;
  padding: 12px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.08);
  border: 1px solid rgba(255,255,255,0.6);
  pointer-events: auto; /* Re-enable clicks for the bar itself */
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

.send-bar {
  display: flex;
  gap: 10px;
  align-items: center;
}

.attach-btn {
  width: 40px;
  height: 40px;
  border-radius: 20px;
  background: #f1f5f9;
  border: none;
  color: var(--gray);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s;
}
.attach-btn:hover { background: #e2e8f0; color: var(--primary); }
.attach-icon { font-size: 20px; }

.paste-btn {
  width: 40px;
  height: 40px;
  border-radius: 20px;
  background: #f0fdf4;
  border: 1px solid #bbf7d0;
  color: #166534;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s;
}
.paste-btn:hover { background: #dcfce7; }
.paste-btn:active { transform: scale(0.95); }

.chat-input {
  flex: 1;
  padding: 12px 16px;
  border: none;
  background: #f1f5f9;
  border-radius: 20px;
  font-size: 15px;
  color: var(--dark);
  transition: all 0.2s;
}
.chat-input:focus {
  outline: none;
  background: #fff;
  box-shadow: inset 0 0 0 2px var(--primary-light);
}

.send-btn {
  padding: 0 20px;
  height: 40px;
  background: var(--primary);
  color: var(--white);
  border: none;
  border-radius: 20px;
  font-weight: 600;
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}
.send-btn:disabled {
  background: #e2e8f0;
  color: #94a3b8;
  cursor: not-allowed;
}
.spinner-small {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(255,255,255,0.3);
  border-radius: 50%;
  border-top-color: white;
  animation: spin 0.8s linear infinite;
}
</style>
