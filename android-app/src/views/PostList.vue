<template>
  <div class="page">
    <header class="header blur-header">
      <div class="tabs">
        <div class="tab-indicator" :style="{ 
          transform: `translateX(${currentTab === 'active' ? '0' : (currentTab === 'draft' ? '100%' : '200%')})`,
          width: 'calc(33.333% - 2.66px)'
        }"></div>
        <button :class="['tab-btn', { active: currentTab === 'active' }]" @click="setTab('active')">已发布</button>
        <button :class="['tab-btn', { active: currentTab === 'draft' }]" @click="setTab('draft')">草稿箱</button>
        <button :class="['tab-btn', { active: currentTab === 'trash' }]" @click="setTab('trash')">回收站</button>
      </div>
    </header>

    <div class="content-area">
      <div v-if="loading" class="state-box">
        <div class="loader"></div>
        <p>加载中…</p>
      </div>
      
      <div v-else-if="error" class="state-box error-box">
        <span>⚠</span>
        <p>{{ error }}</p>
        <button class="retry-btn" @click="load">重试</button>
      </div>
      
      <ul v-else class="list">
        <li v-for="p in posts" :key="p.id" class="item card-hover" @click="goPost(p.id)">
          <div class="item-content">
            <span class="title">{{ postTitle(p) }}</span>
            <div class="meta-row">
              <span class="meta-date">{{ p.updated_at || p.created_at }}</span>
              <span v-if="p.category" class="meta-badge category-badge">{{ p.category }}</span>
              <template v-if="getTags(p).length > 0">
                <span v-for="tag in getTags(p)" :key="tag" class="meta-badge tag-badge">{{ tag }}</span>
              </template>
              <span v-if="currentTab === 'trash'" class="meta-badge trash-badge">已删除</span>
            </div>
          </div>
          <div class="item-arrow">›</div>
        </li>
      </ul>
      
      <div v-if="!loading && !error && posts.length === 0" class="state-box empty-box">
        <div class="empty-icon">📝</div>
        <p>{{ currentTab === 'trash' ? '回收站空空如也' : (currentTab === 'draft' ? '你还没有写过草稿' : '这里还没有任何日志。') }}</p>
      </div>
    </div>

    <!-- Floating Action Button for New Post -->
    <button v-if="currentTab === 'active'" class="fab" @click="goNewPost" aria-label="写日志">
      <span>＋</span>
    </button>
  </div>
</template>

<script setup>
import { ref, onMounted, inject } from 'vue'
import { useRouter } from 'vue-router'
import { api, setConfig } from '../api'

const router = useRouter()
const toast = inject('toast')
const posts = ref([])
const loading = ref(true)
const error = ref('')
const currentTab = ref('active') // 'active' or 'trash'

async function load() {
  loading.value = true
  error.value = ''
  try {
    let params = { draft: '0', trash: '0' }
    if (currentTab.value === 'trash') params = { trash: '1' }
    else if (currentTab.value === 'draft') params = { draft: '1', trash: '0' }
    
    posts.value = await api.getPosts(params)
  } catch (e) {
    error.value = e.message
    toast(e.message)
  } finally {
    loading.value = false
  }
}

function setTab(tab) {
  if (currentTab.value !== tab) {
    currentTab.value = tab
    load()
  }
}

function postTitle(p) {
  const t = (p && (p.title || p.Title || '')).trim()
  if (t) return t
  return '日志 #' + (p && p.id ? p.id : '')
}

function getTags(p) {
  if (!p || !p.tags) return []
  if (Array.isArray(p.tags)) return p.tags
  if (typeof p.tags === 'string') return p.tags.split(',').map(s => s.trim()).filter(Boolean)
  return []
}

function goPost(id) {
  router.push('/posts/' + id)
}

function goNewPost() {
  router.push('/posts/new')
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
  padding: 12px 20px 12px;
  border-bottom: 1px solid rgba(0,0,0,0.05);
}

.icon-btn {
  width: 44px;
  height: 44px;
  border: none;
  background: var(--white);
  border-radius: 14px;
  font-size: 20px;
  box-shadow: var(--shadow-sm);
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}
.icon-btn:active { transform: scale(0.95); }
.chat-icon { transform: translateY(1px); }

.logout-btn {
  background: transparent;
  box-shadow: none;
  border: 1px solid #e2e8f0;
  color: var(--gray);
  font-size: 16px;
}
.logout-btn:hover { background: #fef2f2; border-color: #fecaca; color: var(--danger); }

/* Premium Tabs */
.tabs {
  position: relative;
  display: flex;
  background: #e2e8f0;
  padding: 4px;
  border-radius: 12px;
  box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);
}
.tab-indicator {
  position: absolute;
  top: 4px;
  bottom: 4px;
  left: 4px;
  width: calc(33.333% - 2.66px); /* Modified inline, fallback here */
  background: var(--white);
  border-radius: 8px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  transition: transform 0.3s cubic-bezier(0.25, 1, 0.5, 1);
  z-index: 1;
}
.tab-btn {
  position: relative;
  z-index: 2;
  flex: 1;
  padding: 10px 0;
  border: none;
  background: transparent;
  color: var(--gray);
  font-weight: 600;
  font-size: 14px;
  cursor: pointer;
  transition: color 0.3s;
}
.tab-btn.active {
  color: var(--dark);
}

/* List Content */
.content-area {
  padding: 16px 20px 100px;
}

.list { list-style: none; }
.item {
  background: var(--white);
  border-radius: 16px;
  padding: 18px 20px;
  margin-bottom: 12px;
  box-shadow: var(--shadow-sm);
  border: 1px solid rgba(0,0,0,0.02);
  display: flex;
  align-items: center;
  justify-content: space-between;
  cursor: pointer;
  transition: all 0.2s;
}
.card-hover:active {
  transform: scale(0.98);
  background: var(--light);
}

.item-content { flex: 1; min-width: 0; padding-right: 12px; }
.item .title {
  display: block;
  font-size: 16px;
  font-weight: 600;
  color: var(--dark);
  margin-bottom: 6px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.meta-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.meta-date {
  font-size: 13px;
  color: #94a3b8;
}
.meta-badge {
  font-size: 11px;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 6px;
  letter-spacing: 0.5px;
  white-space: nowrap;
}
.category-badge {
  background: #f0f9ff;
  color: var(--primary-dark);
  border: 1px solid #e0f2fe;
}
.tag-badge {
  background: #f1f5f9;
  color: #64748b;
  border: 1px solid #e2e8f0;
}
.trash-badge {
  background: #fef2f2;
  color: var(--danger);
  border: 1px solid #fee2e2;
}

.item-arrow {
  font-size: 24px;
  color: #cbd5e1;
  font-weight: 300;
}

/* States */
.state-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  color: var(--gray);
  text-align: center;
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

.error-box span { font-size: 32px; color: var(--danger); margin-bottom: 12px; }
.retry-btn {
  margin-top: 16px;
  padding: 8px 20px;
  background: var(--white);
  border: 1px solid #e2e8f0;
  border-radius: 20px;
  font-weight: 600;
  cursor: pointer;
}

.empty-icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }

/* Enhanced FAB */
.fab {
  position: fixed;
  right: 20px;
  bottom: calc(20px + var(--safe-bottom));
  width: 48px;
  height: 48px;
  border-radius: 24px;
  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
  color: white;
  border: none;
  font-size: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 10px 25px rgba(14, 165, 233, 0.4);
  cursor: pointer;
  z-index: 100;
  transition: all 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
.fab span { transform: translateY(-1px); }
.fab:hover { transform: scale(1.05); box-shadow: 0 14px 30px rgba(14, 165, 233, 0.5); }
.fab:active { transform: scale(0.95); box-shadow: 0 5px 15px rgba(14, 165, 233, 0.3); }
</style>
