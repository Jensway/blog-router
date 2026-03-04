<template>
  <div class="page" ref="pageEl">
    <header :class="['header blur-header', { 'header-hidden': isHeaderHidden }]">
      <div class="header-content" v-if="!searchActive">
        <button :class="['chip-btn', { active: currentTab === 'active' }]" @click="setTab('active')">已发布</button>
        <button :class="['chip-btn', { active: currentTab === 'draft' }]" @click="setTab('draft')">草稿箱</button>
        <button :class="['chip-btn', { active: currentTab === 'trash' }]" @click="setTab('trash')">回收站</button>
        <button class="header-text-btn" @click="searchActive = true">搜索</button>
        <button class="header-text-btn" @click="goNewPost">添加</button>
      </div>
      <div class="search-bar" v-else>
        <div class="search-input-wrapper">
          <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
          <input type="search" ref="searchInputRef" v-model="searchQuery" class="search-input" placeholder="搜索主题、分类或标签..." @keyup.esc="closeSearch" />
          <button v-if="searchQuery" class="clear-btn" @click="searchQuery = ''">×</button>
        </div>
        <button class="search-cancel" @click="closeSearch">取消</button>
      </div>
    </header>

    <div class="content-area" ref="contentArea">
      <!-- Pull-to-Refresh Indicator -->
      <div class="ptr-indicator" ref="ptrIndicator">
        <div class="ptr-spinner"></div>
        <span class="ptr-text">下拉刷新</span>
      </div>

      <div v-if="loading && !ptrRefreshing" class="state-box">
        <div class="loader"></div>
        <p>加载中…</p>
      </div>
      
      <div v-else-if="error" class="state-box error-box">
        <span>⚠</span>
        <p>{{ error }}</p>
        <button class="retry-btn" @click="load">重试</button>
      </div>
      
      <ul v-else class="list">
        <li v-for="p in filteredPosts" :key="p.id" class="item card-hover" @click="goPost(p.id)">
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
      
      <div v-if="!loading && !error && filteredPosts.length === 0" class="state-box empty-box">
        <div class="empty-icon">📝</div>
        <p>{{ searchQuery ? '未找到匹配的日志' : (currentTab === 'trash' ? '回收站空空如也' : (currentTab === 'draft' ? '你还没有写过草稿' : '这里还没有任何日志。')) }}</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, inject, watch, nextTick } from 'vue'
import { useRouter } from 'vue-router'
import { api, setConfig } from '../api'

const router = useRouter()
const toast = inject('toast')
const posts = ref([])
const loading = ref(true)
const error = ref('')
const currentTab = ref('active')

// Immersive Scroll & Search State
const isHeaderHidden = ref(false)
const searchActive = ref(false)
const searchQuery = ref('')
const searchInputRef = ref(null)
let lastScrollTop = 0

// Watch searchActive to focus input automatically
watch(searchActive, async (val) => {
  if (val) {
    await nextTick()
    if (searchInputRef.value) searchInputRef.value.focus()
  }
})

function closeSearch() {
  searchActive.value = false
  searchQuery.value = ''
}

// Dynamic Categories Array (extracted from loaded posts)
const dynamicCategories = computed(() => {
  const cats = new Set()
  posts.value.forEach(p => {
    if (p.category) cats.add(p.category)
  })
  return Array.from(cats)
})

const filteredPosts = computed(() => {
  let result = posts.value

  // Post filtering purely by currentTab if it's a dynamic category
  if (currentTab.value !== 'active' && currentTab.value !== 'draft' && currentTab.value !== 'trash') {
    result = result.filter(p => p.category === currentTab.value)
  }

  // Search query filtering
  if (!searchQuery.value) return result
  
  const q = searchQuery.value.toLowerCase()
  return result.filter(p => {
    const t = postTitle(p).toLowerCase()
    const c = (p.category || '').toLowerCase()
    const tags = getTags(p).map(tag => tag.toLowerCase()).join(' ')
    return t.includes(q) || c.includes(q) || tags.includes(q)
  })
})

// Pure Vue Pull-to-Refresh State
const pageEl = ref(null)
const contentArea = ref(null)
const ptrIndicator = ref(null)
const ptrRefreshing = ref(false)
let ptrStartY = 0, ptrPulling = false, ptrDy = 0

function initPTR() {
  const el = contentArea.value
  if (!el) return

  el.addEventListener('touchstart', (e) => {
    // Only allow PTR when scrolled to the very top of the parent container
    const sp = document.querySelector('.tab-content') || window
    const st = sp === window ? window.scrollY : sp.scrollTop
    
    if (st <= 0 && !ptrRefreshing.value) {
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
        window.scrollTo({ top: 0, behavior: 'smooth' }) // Scroll to top exactly as requested
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

let scrollParent = null

function initImmersiveScroll() {
  // Find the actual scrolling parent element (usually .tab-content in MainLayout)
  scrollParent = document.querySelector('.tab-content') || window
  
  scrollParent.addEventListener('scroll', handleScroll, { passive: true })
}

function handleScroll(e) {
  const st = scrollParent === window ? window.scrollY : scrollParent.scrollTop
  
  // If scrolling down and past 50px threshold, hide header
  if (st > lastScrollTop && st > 50) {
    isHeaderHidden.value = true
  } 
  // If scrolling up (at least 5px delta to prevent jitters) or at the top, show header
  else if (st < lastScrollTop - 5 || st <= 0) {
    isHeaderHidden.value = false
  }
  lastScrollTop = st <= 0 ? 0 : st
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    let params = { draft: '0', trash: '0' }
    
    // If not trash or draft, always request standard posts
    if (currentTab.value === 'trash') params = { trash: '1' }
    else if (currentTab.value === 'draft') params = { draft: '1', trash: '0' }
    
    // For custom dynamic categories, we still query standard active posts, and then filter locally above.
    const res = await api.getPosts(params)
    posts.value = res
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

onMounted(() => {
  load()
  initPTR()
  
  // Need to wait for MainLayout.vue to render its .tab-content if this is a sub-route
  setTimeout(() => {
    initImmersiveScroll()
  }, 300)
})

onUnmounted(() => {
  if (scrollParent) {
    scrollParent.removeEventListener('scroll', handleScroll)
  }
})
</script>

<style scoped>
.page { 
  position: relative;
  min-height: 100vh;
  background-color: var(--light);
  overscroll-behavior-y: none;
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
  transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.header-hidden {
  transform: translateY(-100%);
}

.header-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
}

.chip-btn {
  background: transparent;
  border: none;
  font-size: 15px;
  font-weight: 600;
  color: #94a3b8;
  border-radius: 0;
  white-space: nowrap;
  flex-shrink: 0;
  transition: all 0.2s;
  cursor: pointer;
  padding: 6px 0;
}
.chip-btn.active {
  background: transparent;
  color: var(--primary);
  border-color: transparent;
  box-shadow: none;
}

.header-text-btn {
  background: transparent;
  border: none;
  color: #94a3b8;
  font-size: 15px;
  font-weight: 600;
  padding: 6px 0;
  cursor: pointer;
  transition: all 0.2s;
}
.header-text-btn:active {
  opacity: 0.7;
}

/* Internal File Search Bar */
.search-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  animation: slideFadeIn 0.2s ease-out forwards;
}
@keyframes slideFadeIn {
  from { opacity: 0; transform: translateX(10px); }
  to { opacity: 1; transform: translateX(0); }
}

.search-input-wrapper {
  flex: 1;
  display: flex;
  align-items: center;
  background: var(--white);
  border: 1px solid #e2e8f0;
  border-radius: 20px;
  padding: 0 12px;
  height: 40px;
  box-shadow: inset 0 2px 4px rgba(0,0,0,0.02);
}

.search-icon {
  width: 16px;
  height: 16px;
  color: #94a3b8;
  margin-right: 8px;
}

.search-input {
  flex: 1;
  border: none;
  background: transparent;
  font-size: 15px;
  color: var(--dark);
  outline: none;
  width: 100%;
}
.search-input::placeholder { color: #cbd5e1; font-weight: 500; }

.clear-btn {
  background: #cbd5e1;
  color: white;
  border: none;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  cursor: pointer;
  padding: 0;
  margin-left: 8px;
}

.search-cancel {
  background: transparent;
  border: none;
  color: var(--primary);
  font-weight: 600;
  font-size: 15px;
  cursor: pointer;
  padding: 8px 0;
  white-space: nowrap;
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
  position: relative;
}

/* PTR Indicator */
.ptr-indicator {
  position: absolute;
  top: -50px;
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
  animation: ptr-spin 0.6s linear infinite;
}
@keyframes ptr-spin { 100% { transform: rotate(360deg); } }

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
</style>
