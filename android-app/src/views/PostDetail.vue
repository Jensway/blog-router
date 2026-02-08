<template>
  <div class="page">
    <header class="header">
      <button class="back" @click="router.back">← 返回</button>
    </header>
    <div v-if="loading" class="loading">加载中…</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <article v-else class="article">
      <h1 class="title">{{ post.title || '无标题' }}</h1>
      <div class="meta">{{ post.updated_at || post.created_at }}</div>
      <div class="content" v-html="post.safe_content || post.content || ''"></div>
    </article>
  </div>
</template>

<script setup>
import { ref, onMounted, computed, inject } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, getBaseURL } from '../api'

const route = useRoute()
const router = useRouter()
const post = ref({})
const loading = ref(true)
const error = ref('')

onMounted(async () => {
  const id = route.params.id
  if (!id) return
  loading.value = true
  error.value = ''
  try {
    post.value = await api.getPost(id)
    const base = getBaseURL()
    if (base && post.value.safe_content) {
      post.value.safe_content = post.value.safe_content.replace(
        /src="\/api\/file\//g,
        'src="' + base + '/api/file/'
      )
    }
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.page { padding: 16px; }
.header { margin-bottom: 16px; }
.back {
  background: none;
  border: none;
  font-size: 16px;
  color: var(--primary);
  padding: 8px 0;
}
.loading, .error {
  text-align: center;
  padding: 40px 20px;
  color: var(--gray);
}
.error { color: var(--danger); }
.article { background: var(--white); border-radius: 12px; padding: 20px; }
.title { font-size: 22px; margin-bottom: 8px; line-height: 1.3; }
.meta { font-size: 13px; color: var(--gray); margin-bottom: 16px; }
.content {
  font-size: 15px;
  line-height: 1.7;
  word-break: break-word;
}
.content :deep(img) { max-width: 100%; height: auto; }
.content :deep(pre) { overflow-x: auto; background: var(--light); padding: 12px; border-radius: 8px; }
.content :deep(code) { font-size: 14px; }
</style>
