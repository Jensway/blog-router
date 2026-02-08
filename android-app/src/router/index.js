import { createRouter, createWebHashHistory } from 'vue-router'
import { getConfig } from '../api'
import Login from '../views/Login.vue'
import PostList from '../views/PostList.vue'
import PostDetail from '../views/PostDetail.vue'
import MessageSquare from '../views/MessageSquare.vue'

const routes = [
  { path: '/', redirect: () => (getConfig()?.apiToken ? '/posts' : '/login') },
  { path: '/login', component: Login },
  { path: '/posts', component: PostList },
  { path: '/posts/:id', component: PostDetail },
  { path: '/messages', component: MessageSquare },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to, _from, next) => {
  const config = getConfig()
  const hasAuth = config?.baseURL && config?.apiToken
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
