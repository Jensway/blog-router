<template>
  <div class="page">
    <header class="header">
      <button class="back" @click="router.back">← 返回</button>
      <h1>消息广场</h1>
    </header>
    <div class="send-bar">
      <input v-model="newContent" placeholder="说点什么…" maxlength="500" @keyup.enter="send" />
      <button class="send-btn" @click="send" :disabled="sending">发送</button>
    </div>
    <div v-if="loading" class="loading">加载中…</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <ul v-else class="list">
      <li v-for="m in messages" :key="m.id" class="msg">
        <div class="msg-head">
          <span class="user">{{ m.username }}</span>
          <span class="time">{{ m.created_at }}</span>
        </div>
        <p v-if="m.content" class="msg-content">{{ m.content }}</p>
        <a v-if="m.file_url" :href="fileURL('/api/file/' + m.file_url)" target="_blank" class="msg-file">
          {{ m.file_name || '附件' }}
        </a>
      </li>
    </ul>
    <p v-if="!loading && !error && messages.length === 0" class="empty">暂无消息</p>
  </div>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue'
import { useRouter } from 'vue-router'
import { api, fileURL } from '../api'

const router = useRouter()
const toast = inject('toast')
const messages = ref([])
const loading = ref(true)
const error = ref('')
const newContent = ref('')
const sending = ref(false)

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
  const content = newContent.value.trim()
  if (!content) return
  sending.value = true
  try {
    await api.createMessage({ content })
    newContent.value = ''
    await load()
  } catch (e) {
    toast(e.message || '发送失败')
  } finally {
    sending.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.page { padding: 16px; padding-bottom: 80px; }
.header { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; }
.back {
  background: none;
  border: none;
  font-size: 16px;
  color: var(--primary);
  padding: 8px 0;
}
.header h1 { font-size: 20px; font-weight: 700; }
.send-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  padding: 10px 0;
}
.send-bar input {
  flex: 1;
  padding: 12px 14px;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  font-size: 15px;
}
.send-btn {
  padding: 12px 20px;
  background: var(--primary);
  color: var(--white);
  border: none;
  border-radius: 8px;
  font-weight: 600;
}
.send-btn:disabled { opacity: 0.6; }
.loading, .error, .empty {
  text-align: center;
  color: var(--gray);
  padding: 24px;
}
.error { color: var(--danger); }
.list { list-style: none; }
.msg {
  background: var(--white);
  border-radius: 12px;
  padding: 14px;
  margin-bottom: 10px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.06);
}
.msg-head { display: flex; justify-content: space-between; margin-bottom: 8px; }
.user { font-weight: 600; font-size: 14px; }
.time { font-size: 12px; color: var(--gray); }
.msg-content { font-size: 15px; line-height: 1.5; margin-bottom: 8px; }
.msg-file {
  font-size: 13px;
  color: var(--primary);
  text-decoration: none;
}
</style>
