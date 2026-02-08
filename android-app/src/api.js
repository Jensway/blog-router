const STORAGE_KEY = 'share_center_config'

export function getConfig() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    return JSON.parse(raw)
  } catch {
    return null
  }
}

export function setConfig(baseURL, apiToken) {
  const base = baseURL.replace(/\/+$/, '')
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ baseURL: base, apiToken: apiToken || '' }))
}

export function getAuthHeaders() {
  const c = getConfig()
  if (!c?.baseURL || !c?.apiToken) return {}
  return { 'X-API-Token': c.apiToken }
}

export function getBaseURL() {
  const c = getConfig()
  return c?.baseURL || ''
}

async function request(path, options = {}) {
  const base = getBaseURL()
  if (!base) throw new Error('请先设置服务器地址和 API 令牌')
  const url = path.startsWith('http') ? path : `${base}${path}`
  const headers = {
    'Content-Type': 'application/json',
    ...getAuthHeaders(),
    ...options.headers,
  }
  let res, text
  try {
    res = await fetch(url, { ...options, headers })
    text = await res.text()
  } catch (e) {
    const msg = (e && e.message) || ''
    if (/failed to fetch|network|load failed/i.test(msg)) {
      throw new Error(
        '连接失败，请检查：① 服务器地址不要用 localhost，改用电脑局域网 IP（如 http://192.168.1.x:5000）或公网地址；② 手机与电脑是否在同一 WiFi；③ 电脑防火墙是否放行该端口。'
      )
    }
    throw e
  }
  if (!res.ok) {
    let msg = '请求失败'
    try {
      const j = JSON.parse(text)
      if (j.error) msg = j.error
    } catch (_) {}
    throw new Error(msg)
  }
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

export const api = {
  async session() {
    return request('/api/session')
  },
  async getPosts(params = {}) {
    const q = new URLSearchParams(params).toString()
    return request('/api/posts' + (q ? '?' + q : ''))
  },
  async getPost(id) {
    return request(`/api/posts/${id}`)
  },
  async getMessages() {
    return request('/api/messages')
  },
  async createMessage(body) {
    return request('/api/messages', { method: 'POST', body: JSON.stringify(body) })
  },
  async deleteMessage(id) {
    return request(`/api/messages/${id}`, { method: 'DELETE' })
  },
}

export function fileURL(path) {
  if (!path) return ''
  const base = getBaseURL()
  const c = getConfig()
  const token = c?.apiToken
  let url = path.startsWith('http') ? path : (base ? `${base}${path}` : path)
  if (token && url.indexOf('?') === -1) url += '?token=' + encodeURIComponent(token)
  else if (token) url += '&token=' + encodeURIComponent(token)
  return url
}
