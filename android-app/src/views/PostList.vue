<template>
  <div class="page">
    <header class="header">
      <h1>我的日志</h1>
      <button class="icon-btn" @click="goMessages" aria-label="消息">💬</button>
    </header>
    <div v-if="loading" class="loading">加载中…</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <ul v-else class="list">
      <li v-for="p in posts" :key="p.id" class="item" @click="goPost(p.id)">
        <span class="title">{{ p.title || '无标题' }}</span>
        <span class="meta">{{ p.updated_at || p.created_at }}</span>
      </li>
    </ul>
    <p v-if="!loading && !error && posts.length === 0" class="empty">暂无日志</p>
  </div>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '../api'

const router = useRouter()
const toast = inject('toast')
const posts = ref([])
const loading = ref(true)
const error = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    posts.value = await api.getPosts({ draft: '0' })
  } catch (e) {
    error.value = e.message
    toast(e.message)
  } finally {
    loading.value = false
  }
}

function goPost(id) {
  router.push('/posts/' + id)
}

function goMessages() {
  router.push('/messages')
}

onMounted(load)
</script>

<style scoped>
.page { padding: 16px; padding-top: 12px; }
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
}
.header h1 { font-size: 22px; font-weight: 700; }
.icon-btn {
  width: 44px;
  height: 44px;
  border: none;
  background: var(--light);
  border-radius: 12px;
  font-size: 20px;
}
.loading, .error, .empty {
  text-align: center;
  color: var(--gray);
  padding: 40px 20px;
}
.error { color: var(--danger); }
.list { list-style: none; }
.item {
  background: var(--white);
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 10px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}
.item .title {
  display: block;
  font-weight: 600;
  margin-bottom: 6px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.item .meta {
  font-size: 12px;
  color: var(--gray);
}
</style>
