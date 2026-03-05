<template>
  <div class="page">
    <header class="header">
      <button class="back" @click="goBack" :disabled="saving">← 返回</button>
      <h1>{{ isEdit ? '编辑日志' : '写日志' }}</h1>
      <button class="action-btn save-btn" @click="save" :disabled="saving">
        {{ saving ? '保存中…' : '保存' }}
      </button>
    </header>

    <div v-if="loading" class="loading">加载中…</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else class="editor-area">
      <input 
        v-model="post.title" 
        class="input-title" 
        placeholder="标题 (可选，留空将截取正文片段)" 
        maxlength="120"
      />
      <editor-content :editor="editor" class="input-content tiptap-wrapper" />
    </div>

    <!-- Tiptap Floating Bottom Toolbar -->
    <div class="editor-toolbar" v-if="editor && !loading && !error">
      <button @click="editor.chain().focus().toggleBold().run()" :class="{ 'is-active': editor.isActive('bold') }">
        <b>B</b>
      </button>
      <button @click="editor.chain().focus().toggleItalic().run()" :class="{ 'is-active': editor.isActive('italic') }">
        <i>I</i>
      </button>
      <button @click="editor.chain().focus().toggleBulletList().run()" :class="{ 'is-active': editor.isActive('bulletList') }">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>
      </button>
      <button @click="editor.chain().focus().toggleOrderedList().run()" :class="{ 'is-active': editor.isActive('orderedList') }">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="10" y1="6" x2="21" y2="6"></line><line x1="10" y1="12" x2="21" y2="12"></line><line x1="10" y1="18" x2="21" y2="18"></line><path d="M4 6h1v4"></path><path d="M4 10h2"></path><path d="M6 18H4c0-1 2-2 2-3s-1-1.5-2-1"></path></svg>
      </button>
      <button @click="addImage">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><circle cx="8.5" cy="8.5" r="1.5"></circle><polyline points="21 15 16 10 5 21"></polyline></svg>
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, inject, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, fileURL, getBaseURL } from '../api'

// Tiptap Imports
import { useEditor, EditorContent } from '@tiptap/vue-3'
import StarterKit from '@tiptap/starter-kit'
import Placeholder from '@tiptap/extension-placeholder'
import Image from '@tiptap/extension-image'
import Link from '@tiptap/extension-link'

const route = useRoute()
const router = useRouter()
const toast = inject('toast', () => {})

const postId = route.params.id
const isEdit = computed(() => !!postId)
const loading = ref(false)
const saving = ref(false)
const error = ref('')

const post = ref({
  title: '',
  content: '',
  content_type: 'html',  // Tiptap produces HTML
  is_draft: false,
  source: 'android-app'
})

const editor = useEditor({
  content: '',
  extensions: [
    StarterKit,
    Placeholder.configure({
      placeholder: '在这里写下你的日志正文...',
    }),
    Image,
    Link.configure({ openOnClick: false })
  ],
  onUpdate: ({ editor }) => {
    post.value.content = editor.getHTML()
  }
})

/** 统一重写所有 img src：采用 DOM 解析代替正则，兼容性最好 */
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

// Minimal file upload binding for imagery
async function addImage() {
  const input = document.createElement('input')
  input.type = 'file'
  input.accept = 'image/*'
  input.onchange = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    try {
      const res = await api.uploadFile(file)
      if (res.url) {
        const url = fileURL('/api/file/' + res.url)
        editor.value.chain().focus().setImage({ src: url }).run()
      }
    } catch (err) {
      toast(err.message || '图片上传失败')
    }
  }
  input.click()
}

onMounted(async () => {
  if (isEdit.value) {
    loading.value = true
    try {
      const data = await api.getPost(postId)
      post.value = {
        title: data.title || '',
        content: rewriteImageSrcs(data.content || ''),
        content_type: 'html',
        is_draft: data.is_draft || false,
        source: 'android-app'
      }
      if (editor.value) {
        editor.value.commands.setContent(post.value.content)
      }
    } catch (e) {
      error.value = '加载失败: ' + e.message
    } finally {
      loading.value = false
    }
  }
})

onBeforeUnmount(() => {
  if (editor.value) {
    editor.value.destroy()
  }
})

async function save() {
  const content = post.value.content.trim()
  if (!content) {
    toast('正文不能为空')
    return
  }
  
  saving.value = true
  try {
    if (isEdit.value) {
      await api.updatePost(postId, post.value)
      toast('保存成功')
      router.back()
    } else {
      await api.createPost(post.value)
      toast('发布成功')
      router.replace('/posts')
    }
  } catch (e) {
    toast(e.message || '保存失败')
  } finally {
    saving.value = false
  }
}

function goBack() {
  if (confirm('是否放弃当前的编辑？')) {
    router.back()
  }
}
</script>

<style scoped>
.page { 
  display: flex;
  flex-direction: column;
  height: 100vh;
  padding: 16px; 
  padding-bottom: 0;
  box-sizing: border-box;
}

.header { 
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px; 
  flex-shrink: 0;
}

.back {
  background: none;
  border: none;
  font-size: 16px;
  color: var(--primary);
  padding: 8px 0;
}

.header h1 {
  font-size: 18px;
  font-weight: 600;
  margin: 0;
}

.action-btn {
  padding: 6px 16px;
  border-radius: 6px;
  border: none;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
}

.save-btn {
  background: var(--primary);
  color: white;
}
.save-btn:disabled, .back:disabled { opacity: 0.6; }

.loading, .error {
  text-align: center;
  padding: 40px 20px;
  color: var(--gray);
}
.error { color: var(--danger); }

.editor-area {
  flex: 1;
  display: flex;
  flex-direction: column;
  background: var(--white);
  border-radius: 12px 12px 0 0;
  padding: 16px;
  box-shadow: 0 -2px 10px rgba(0,0,0,0.03);
}

.input-title {
  font-size: 20px;
  font-weight: 600;
  border: none;
  border-bottom: 1px solid #f1f5f9;
  padding: 8px 0 16px 0;
  margin-bottom: 16px;
  color: var(--dark);
}
.input-title:focus { outline: none; border-bottom-color: var(--primary); }

.input-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  padding-bottom: 20px; /* offset for toolbar */
}
/* Tiptap inner editor root */
:deep(.tiptap) {
  flex: 1;
  outline: none;
  line-height: 1.6;
  font-size: 16px;
  color: #334155;
  min-height: 200px;
}
:deep(.tiptap p.is-editor-empty:first-child::before) {
  content: attr(data-placeholder);
  float: left;
  color: #cbd5e1;
  pointer-events: none;
  height: 0;
}
:deep(.tiptap img) {
  max-width: 100%;
  border-radius: 8px;
  margin: 12px 0;
}
:deep(.tiptap ul), :deep(.tiptap ol) {
  padding-left: 20px;
}

/* Beautiful Floating Toolbar */
.editor-toolbar {
  position: sticky;
  bottom: 12px;
  align-self: center;
  display: flex;
  gap: 8px;
  background: rgba(248, 250, 252, 0.9);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid rgba(0,0,0,0.05);
  padding: 8px 12px;
  border-radius: 100px;
  box-shadow: 0 4px 16px rgba(0,0,0,0.08);
  margin-bottom: 16px;
  z-index: 10;
}
.editor-toolbar button {
  width: 36px;
  height: 36px;
  border: none;
  background: transparent;
  border-radius: 50%;
  color: #64748b;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s;
}
.editor-toolbar button:active {
  transform: scale(0.9);
  background: #f1f5f9;
}
.editor-toolbar button.is-active {
  background: var(--primary);
  color: white;
  box-shadow: 0 2px 6px rgba(14,165,233,0.3);
}
</style>
