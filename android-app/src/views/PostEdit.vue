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
      <editor
        v-model="post.content"
        :init="editorConfig"
        class="input-content"
      />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, inject, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, fileURL } from '../api'
import Editor from '@tinymce/tinymce-vue'

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
  content_type: 'html',  // TinyMCE produces HTML
  is_draft: false,
  source: 'android-app'
})

const editorConfig = {
  plugins: 'link image lists table code wordcount',
  toolbar: 'undo redo | blocks | bold italic underline strikethrough | alignleft aligncenter alignright alignjustify | bullist numlist outdent indent | link image table | removeformat code',
  menubar: false,
  statusbar: false,
  height: '100%',
  width: '100%',
  language: 'zh_CN',
  placeholder: '在这里写下你的日志正文...',
  images_upload_handler: async (blobInfo) => {
    try {
      const res = await api.uploadFile(blobInfo.blob())
      if (res.url) {
        return fileURL('/api/file/' + res.url)
      } else {
        throw new Error('上传返回格式错误')
      }
    } catch(e) {
      throw { message: e.message || '图片上传失败', remove: true }
    }
  }
}

onMounted(async () => {
  if (isEdit.value) {
    loading.value = true
    try {
      const data = await api.getPost(postId)
      post.value = {
        title: data.title || '',
        // server returns safe_content and content, we need the raw content for editing
        content: data.content || '',
        content_type: 'html', // ensure we save back as html
        is_draft: data.is_draft || false,
        source: 'android-app'
      }
    } catch (e) {
      error.value = '加载失败: ' + e.message
    } finally {
      loading.value = false
    }
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
}
/* Ensure the TinyMCE editor fills the container height in mobile view */
:deep(.tox-tinymce) {
  flex: 1;
  border: none !important;
  border-radius: 8px !important;
}
</style>
