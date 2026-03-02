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
          <button class="icon-action-btn" @click="copyPostContent" title="复制内容">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>
          </button>
          
          <button class="icon-action-btn delete-icon" @click="softDelete" title="移至回收站" :disabled="processing">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/><line x1="10" x2="10" y1="11" y2="17"/><line x1="14" x2="14" y1="11" y2="17"/></svg>
          </button>
          
          <button class="icon-action-btn edit-icon" @click="editPost" title="编辑日志">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/><path d="m15 5 4 4"/></svg>
          </button>
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
import { ref, onMounted, nextTick, inject } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, fileURL, getBaseURL } from '../api'
import { Clipboard } from '@capacitor/clipboard'

const route = useRoute()
const router = useRouter()
const toast = inject('toast', () => {})
const post = ref(null)
const loading = ref(true)
const processing = ref(false)
const error = ref('')
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
    button: true,
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

const currentUser = ref(localStorage.getItem('username') || '')

/**
 * 核心：将服务器返回的 HTML 中所有 img src 注入完整的服务器绝对地址 + token
 * 采用 DOM 解析代替正则，兼容性最好，避免部分老旧浏览器正则引擎报错
 */
function rewriteImageSrcs(html) {
  if (!html) return html
  try {
    const base = getBaseURL()
    const parser = new DOMParser()
    const doc = parser.parseFromString(html, 'text/html')
    const images = doc.querySelectorAll('img')
    images.forEach(img => {
      const src = img.getAttribute('src')
      if (!src) return
      const lower = src.toLowerCase()
      if (lower.startsWith('http') || lower.startsWith('data:') || lower.startsWith('blob:')) return
      
      if (src.includes('/api/file/')) {
        img.setAttribute('src', encodeURI(fileURL(src)))
      } else {
        const cleaned = src.replace(/^\.?\//, '')
        img.setAttribute('src', encodeURI(fileURL('/api/file/' + cleaned)))
      }
    })
    return doc.body.innerHTML
  } catch (err) {
    return html
  }
}


onMounted(async () => {
  const id = route.params.id
  if (!id) return
  loading.value = true
  error.value = ''
  try {
    post.value = await api.getPost(id)
    // Phase 1: 字符串级别重写所有 img src
    const raw = post.value.safe_content || post.value.content || ''
    post.value.safe_content = rewriteImageSrcs(raw)

    // Phase 2: DOM 渲染完成后，高亮代码块，并执行原生 Blob 转换（彻底绕过不同 WebView 的拦截机制）
    await nextTick()
    setTimeout(() => {
      if (window.Prism) window.Prism.highlightAll()
      
      const images = document.querySelectorAll('.content img')
      images.forEach(async (img) => {
        // Enforce clickable cursor natively
        img.style.cursor = 'pointer';
        
        const curSrc = img.getAttribute('src');
        if (!curSrc || curSrc.startsWith('blob:') || curSrc.startsWith('data:')) {
            // Already raw/processed, just bind click
            img.onclick = () => openFullscreen(img.src);
            return;
        }
        
        try {
          // 清洗可能存在的过期 Token 或干扰参数，基于原生 fileURL 重塑无缓存的新地址
          let name = curSrc.split('/').pop().split('?')[0];
          name = decodeURIComponent(name);
          const freshUrl = fileURL('/api/file/' + encodeURIComponent(name)) + '?v=' + Date.now();
          
          // 原生拉取数据为 Blob，100% 躲开 Android WebView 的后缀名和 octet-stream 安全机制拦截
          // 利用 freshUrl 上的时间戳参数绝对穿透缓存机制，保证读取最新图片
          const res = await fetch(freshUrl);
          if (res.ok) {
            const blob = await res.blob();
            const objectUrl = URL.createObjectURL(new Blob([blob], { type: 'image/png' }));
            img.src = objectUrl;
            img.onclick = () => openFullscreen(objectUrl);
          } else {
            // Fallback click binding if fetch fails but image renders somehow
            img.onclick = () => openFullscreen(freshUrl);
          }
        } catch (e) {
          console.error("DOM Img intercept failed", e);
        }
      })
    }, 200)
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
})

function editPost() {
  router.push(`/posts/${post.value.id}/edit`)
}

async function copyPostContent() {
  if (!post.value) return
  const textToCopy = post.value.content || post.value.safe_content || ''
  try {
    await Clipboard.write({ string: textToCopy })
    toast('日志内容已复制')
  } catch(e) {
    try {
        await navigator.clipboard.writeText(textToCopy)
        toast('日志内容已复制')
    } catch (err) { }
  }
}

async function softDelete() {
  if (!confirm('确定要移至回收站吗？')) return
  processing.value = true
  try {
    await api.deletePost(post.value.id)
    toast('已移至回收站')
    router.replace('/posts')
  } catch(e) {
    toast(e.message || '操作失败')
  } finally {
    processing.value = false
  }
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
.action-btn:disabled, .icon-action-btn:disabled { opacity: 0.6; cursor: not-allowed; }

.icon-action-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: rgba(148, 163, 184, 0.1);
  color: var(--gray);
  border: none;
  cursor: pointer;
  transition: all 0.2s;
}
.icon-action-btn:hover { background: rgba(148, 163, 184, 0.2); color: var(--dark); }
.icon-action-btn.delete-icon:hover { background: #fee2e2; color: var(--danger); }
.icon-action-btn.edit-icon:hover { background: #e0f2fe; color: var(--primary); }
.icon-action-btn:active { transform: scale(0.9); }

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
