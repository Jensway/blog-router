import { createRouter, createWebHashHistory } from 'vue-router'
import { getConfig } from '../api'
import Login from '../views/Login.vue'
import PostList from '../views/PostList.vue'
import PostDetail from '../views/PostDetail.vue'
import MessageSquare from '../views/MessageSquare.vue'

import MainLayout from '../views/MainLayout.vue'
import Settings from '../views/Settings.vue' // Will be created
import PostEdit from '../views/PostEdit.vue'

const routes = [
  { path: '/', redirect: () => { const c = getConfig(); return (c && c.apiToken) ? '/posts' : '/login' } },
  { path: '/login', component: Login },

  // Tab Layout Routes
  {
    path: '/',
    component: MainLayout,
    children: [
      { path: 'posts', component: PostList },
      { path: 'messages', component: MessageSquare },
      { path: 'settings', component: Settings },
    ]
  },

  // Full Screen Routes
  { path: '/posts/new', component: PostEdit },
  { path: '/posts/:id/edit', component: PostEdit },
  { path: '/posts/:id', component: PostDetail },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to, _from, next) => {
  const config = getConfig()
  const hasAuth = config && config.baseURL && config.apiToken
  if (to.path === '/login') {
    if (hasAuth) next('/posts')
    else next()
    return
  }
  if (!hasAuth) {
    next('/login')
    return
  }
  next()
})

export default router
