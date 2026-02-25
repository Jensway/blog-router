<template>
  <div class="page">
    <header class="header blur-header">
      <button class="back-btn" @click="router.back">
        <span class="icon">←</span>
        <span>返回</span>
      </button>
      
      <div class="actions-group">
        <div v-if="post && post.is_deleted" class="trash-actions">
          <button class="action-btn restore-btn" @click="restore" :disabled="processing">恢复</button>
          <button class="action-btn delete-btn" @click="hardDelete" :disabled="processing">彻底删除</button>
        </div>
        
        <div v-if="post && !post.is_deleted" class="edit-actions">
          <button class="action-btn edit-btn" @click="editPost">编辑</button>
        </div>
      </div>
    </header>
    
    <div class="content-wrapper">
      <div v-if="post && post.is_deleted" class="trash-warning">
        <span class="warning-icon">⚠</span>
        这是一个已删除的日志，位于回收站中。
      </div>

      <div v-if="loading" class="state-box">
        <div class="loader"></div>
        <p>加载中…</p>
      </div>
      
      <div v-else-if="error" class="state-box error-box">
        <p>{{ error }}</p>
      </div>
      
      <article v-else class="article">
        <h1 class="title">{{ post.title || '无标题' }}</h1>
        <div class="meta">
          <span class="date">{{ post.updated_at || post.created_at }}</span>
          <span v-if="post.category" class="category">{{ post.category }}</span>
        </div>
        <div class="content markdown-body" v-html="post.safe_content || post.content || ''"></div>
      </article>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed, inject } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, fileURL } from '../api'

const route = useRoute()
const router = useRouter()
const toast = inject('toast', () => {})
const post = ref({})
const loading = ref(true)
const error = ref('')
const processing = ref(false)

onMounted(async () => {
  const id = route.params.id
  if (!id) return
  loading.value = true
  error.value = ''
  try {
    post.value = await api.getPost(id)
    if (post.value.safe_content || post.value.content) {
      // Fix HTML img tags: aggressively extract /api/file/... regardless of quotes or trailing parameters
      post.value.safe_content = (post.value.safe_content || post.value.content || '')
        .replace(
          /src=(['"])[^'"]*?(\/api\/file\/[^'"?]+)[^'"]*\1/gi,
          (match, quote, path) => `src="${fileURL(path)}"`
        )
        // Fix Markdown img tags: match ![alt](.../api/file/...)
        .replace(
          /!\[(.*?)\]\([^)]*?(\/api\/file\/[^)?]+)[^)]*\)/gi,
          (match, alt, path) => `![${alt}](${fileURL(path)})`
        )
    }
    
    // Auto-highlight code blocks if Prism is loaded
    setTimeout(() => {
      if (window.Prism) {
        window.Prism.highlightAll()
      }
      
      // Intercept octet-stream extensionless images for Android WebView
      const images = document.querySelectorAll('.content img')
      images.forEach(async (img) => {
        const src = img.getAttribute('src')
        if (!src || !src.includes('/api/file/')) return
        
        // Check if it lacks a standard image extension before the query parameters
        const pathMatch = src.split('?')[0]
        const hasExtension = /\.(png|jpe?g|gif|webp|svg)$/i.test(pathMatch)
        
        if (!hasExtension) {
          try {
            // Fetch the image natively to bypass WebView's octet-stream MIME rejection
            const res = await fetch(src)
            if (res.ok) {
              const blob = await res.blob()
              // Re-wrap the blob with an explicit image MIME type
              const imageBlob = new Blob([blob], { type: 'image/png' })
              img.src = URL.createObjectURL(imageBlob)
            }
          } catch (err) {
            console.error('Failed to intercept extensionless image:', err)
          }
        }
      })
    }, 150)
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
})

function editPost() {
  router.push(`/posts/${post.value.id}/edit`)
}

async function restore() {
  if (!confirm('确定要恢复这篇日志吗？')) return
  processing.value = true
  try {
    await api.restorePost(post.value.id)
    toast('已恢复')
    router.replace('/posts')
  } catch(e) {
    toast(e.message || '恢复失败')
  } finally {
    processing.value = false
  }
}

async function hardDelete() {
  if (!confirm('彻底删除后无法找回，确定要删除吗？')) return
  processing.value = true
  try {
    await api.hardDeletePost(post.value.id)
    toast('已彻底删除')
    router.replace('/posts')
  } catch(e) {
    toast(e.message || '删除失败')
  } finally {
    processing.value = false
  }
}
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
}
.back-btn .icon { font-size: 18px; margin-top: -2px; }

.actions-group { display: flex; gap: 8px; }
.trash-actions, .edit-actions { display: flex; gap: 8px; }

.action-btn {
  padding: 8px 16px;
  border-radius: 8px;
  border: none;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}
.action-btn:active { transform: scale(0.95); }

.restore-btn { background: var(--primary); color: white; box-shadow: var(--shadow-sm); }
.delete-btn { background: #fee2e2; color: var(--danger); }
.edit-btn { background: #e2e8f0; color: var(--dark); }
.action-btn:disabled { opacity: 0.6; cursor: not-allowed; }

.content-wrapper { padding: 20px; padding-bottom: 60px; }

.trash-warning {
  background: #fffbeb;
  color: #d97706;
  padding: 12px 16px;
  border-radius: 12px;
  margin-bottom: 24px;
  font-size: 14px;
  font-weight: 500;
  border: 1px solid #fde68a;
  display: flex;
  align-items: center;
  gap: 8px;
}
.warning-icon { font-size: 16px; }

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

.article {
  background: var(--white);
  border-radius: 20px;
  padding: 24px 24px 32px;
  box-shadow: var(--shadow-sm);
  border: 1px solid rgba(0,0,0,0.02);
}

.title { 
  font-size: 26px; 
  font-weight: 800; 
  letter-spacing: -0.5px;
  margin-bottom: 12px; 
  line-height: 1.3; 
  color: var(--dark);
}

.meta { 
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 13px; 
  color: var(--gray); 
  margin-bottom: 28px; 
  padding-bottom: 20px;
  border-bottom: 1px solid #f1f5f9;
}
.category {
  background: #f1f5f9;
  padding: 4px 10px;
  border-radius: 12px;
  font-weight: 600;
  color: var(--primary);
}

.content {
  font-size: 16px;
  line-height: 1.8;
  color: #334155;
  word-break: break-word;
}
.content :deep(p) { margin-bottom: 16px; }
.content :deep(img) { 
  max-width: 100%; 
  height: auto; 
  border-radius: 12px;
  margin: 16px 0;
  box-shadow: var(--shadow-sm);
}
.content :deep(ul), .content :deep(ol) { margin-bottom: 16px; padding-left: 24px; }
.content :deep(li) { margin-bottom: 6px; }

.content :deep(pre) { 
  overflow-x: auto; 
  background: #1e293b; 
  color: #f8fafc;
  padding: 16px; 
  border-radius: 12px; 
  margin: 20px 0; 
  font-size: 14px;
  box-shadow: inset 0 2px 4px rgba(0,0,0,0.2);
}
.content :deep(code) { 
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}
/* Inline code */
.content :deep(:not(pre) > code) {
  background: #f1f5f9;
  color: #1e293b;
  padding: 3px 6px;
  border-radius: 6px;
  font-size: 14px;
  border: 1px solid #e2e8f0;
}
.content :deep(blockquote) {
  border-left: 4px solid var(--primary-light);
  padding-left: 16px;
  margin-left: 0;
  margin-right: 0;
  color: var(--gray);
  font-style: italic;
  background: #f8fafc;
  padding: 12px 16px;
  border-radius: 0 12px 12px 0;
}
</style>
