import { CapacitorHttp } from '@capacitor/core'

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
    } catch (_) { }
    throw new Error(msg)
  }
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

function ensureArray(data) {
  if (Array.isArray(data)) return data
  if (data && Array.isArray(data.data)) return data.data
  if (data && Array.isArray(data.posts)) return data.posts
  if (data && Array.isArray(data.list)) return data.list
  return []
}

export const api = {
  async session() {
    return request('/api/session')
  },
  async getLanIps(host) {
    const url = host.startsWith('http') ? `${host}/api/lan-ips` : `http://${host}/api/lan-ips`
    const res = await fetch(url)
    if (!res.ok) throw new Error('无法获取局域网 IP')
    return res.json()
  },
  async getPosts(params = {}) {
    const q = new URLSearchParams(params).toString()
    const data = await request('/api/posts' + (q ? '?' + q : ''))
    return ensureArray(data)
  },
  async getPost(id) {
    return request(`/api/posts/${id}`)
  },
  async createPost(body) {
    return request('/api/posts', { method: 'POST', body: JSON.stringify(body) })
  },
  async updatePost(id, body) {
    return request(`/api/posts/${id}`, { method: 'PUT', body: JSON.stringify(body) })
  },
  async restorePost(id) {
    return request(`/api/posts/${id}/restore`, { method: 'POST' })
  },
  async hardDeletePost(id) {
    return request(`/api/posts/${id}/hard_delete`, { method: 'DELETE' })
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
  async uploadFile(file) {
    const base = getBaseURL()
    if (!base) throw new Error('请先设置服务器地址')
    const url = `${base}/api/upload`
    const headers = getAuthHeaders()

    // When running natively, WebView FormData fails often.
    // Try to convert to Base64 and use CapacitorHttp, OR fallback gracefully.
    try {
      // 1) Get base64 representation of the file
      const buffer = await file.arrayBuffer()
      const bytes = new Uint8Array(buffer)
      let binary = ''
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i])
      }
      const b64Data = btoa(binary)

      // 2) Construct raw multipart-form payload manually since CapacitorHttp 
      // is safer with Raw base64 form-data injections than JS FormData
      const boundary = '----CapacitorFormBoundary' + Math.random().toString(36).substring(2)

      let bodyData = `--${boundary}\r\n`
      bodyData += `Content-Disposition: form-data; name="file"; filename="${file.name}"\r\n`
      bodyData += `Content-Type: ${file.type || 'application/octet-stream'}\r\n\r\n`

      const payload = bodyData + binary + `\r\n--${boundary}--\r\n`
      // For binary concatenation strings safely in fetch:
      // However since CapacitorHttp in v6 natively supports form uploads better:

      const formData = new FormData()
      formData.append('file', file)

      if (window.Capacitor && window.Capacitor.isNative) {
        // Native device: use CapacitorHttp to avoid WebView mangling Boundaries
        const options = {
          url: url,
          headers: headers,
          data: formData, // CapacitorHttp natively handles FormData boundary building
        }
        const response = await CapacitorHttp.post(options)

        if (response.status !== 200 && response.status !== 201) {
          let msg = '上传失败'
          if (response.data && response.data.error) msg = response.data.error
          throw new Error(msg)
        }
        return response.data
      } else {
        // Web execution: standard fetch
        const res = await fetch(url, {
          method: 'POST',
          headers,
          body: formData
        })
        const text = await res.text()
        if (!res.ok) {
          let msg = '上传失败'
          try { const j = JSON.parse(text); if (j.error) msg = j.error } catch (_) { }
          throw new Error(msg)
        }
        return JSON.parse(text)
      }
    } catch (e) {
      throw new Error('上传出错: ' + (e.message || e))
    }
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
