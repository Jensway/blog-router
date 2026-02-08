package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "github.com/glebarez/go-sqlite"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

var (
	chunkDirs   sync.Map
	restartChan = make(chan int, 1)
	app         *App
	portFlag    int
	workDirFlag string
)

type Session struct {
	Username  string
	IsAdmin   bool
	ExpiresAt time.Time
}

type Post struct {
	ID          int64    `json:"id"`
	Title       string   `json:"title"`
	Content     string   `json:"content,omitempty"`
	SafeContent string   `json:"safe_content,omitempty"`
	ContentType string   `json:"content_type"`
	Category    string   `json:"category,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	IsDraft     bool     `json:"is_draft"`
	IsPinned    bool     `json:"is_pinned"`
	IsStarred   bool     `json:"is_starred"`
	IsDeleted   bool     `json:"is_deleted,omitempty"`
	Source      string   `json:"source"`
	Author      string   `json:"author"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	DeletedAt   string   `json:"deleted_at,omitempty"`
	WordCount   int      `json:"word_count,omitempty"`
}

type Attachment struct {
	ID        int64  `json:"id"`
	PostID    int64  `json:"post_id"`
	Filename  string `json:"filename"`
	OrigName  string `json:"orig_name"`
	FileType  string `json:"file_type"`
	FileSize  int64  `json:"file_size"`
	CreatedAt string `json:"created_at"`
}

type APIToken struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Token     string `json:"token,omitempty"`
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
	LastUsed  string `json:"last_used,omitempty"`
}

type Settings struct {
	Port        int `json:"port"`
	MaxUploadMB int `json:"max_upload_mb"`
}

// 消息广场
// Message 结构体
type Message struct {
	ID        int64  `json:"id"`
	Content   string `json:"content"`
	Username  string `json:"username"`
	FileURL   string `json:"file_url,omitempty"`
	FileType  string `json:"file_type,omitempty"`
	FileName  string `json:"file_name,omitempty"`
	CreatedAt string `json:"created_at"`
}

type App struct {
	db        *sql.DB
	sessions  map[string]*Session
	sessionMu sync.RWMutex
	clients   map[*websocket.Conn]string
	clientsMu sync.RWMutex
	workDir   string
	settings  Settings
	upgrader  websocket.Upgrader
	server    *http.Server
}

func NewApp(workDir string) *App {
	os.MkdirAll(filepath.Join(workDir, "data"), 0755)
	os.MkdirAll(filepath.Join(workDir, "uploads"), 0755)

	db, err := sql.Open("sqlite", filepath.Join(workDir, "data", "blog.db"))
	if err != nil {
		log.Fatal(err)
	}

	app := &App{
		db:       db,
		sessions: make(map[string]*Session),
		clients:  make(map[*websocket.Conn]string),
		workDir:  workDir,
		settings: Settings{Port: 5000, MaxUploadMB: 100},
	}
	app.upgrader = websocket.Upgrader{
		CheckOrigin: app.checkWSOrigin,
	}
	app.initDB()
	app.loadSettings()
	return app
}

func (app *App) initDB() {
	app.db.Exec(`CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password TEXT NOT NULL,
		is_admin INTEGER DEFAULT 0
	)`)

	app.db.Exec(`CREATE TABLE IF NOT EXISTS posts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		content TEXT,
		content_type TEXT DEFAULT 'text',
		category TEXT DEFAULT '',
		tags TEXT DEFAULT '',
		is_draft INTEGER DEFAULT 0,
		is_pinned INTEGER DEFAULT 0,
		is_starred INTEGER DEFAULT 0,
		is_deleted INTEGER DEFAULT 0,
		source TEXT DEFAULT 'web',
		author TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		deleted_at TEXT DEFAULT ''
	)`)

	app.db.Exec(`ALTER TABLE posts ADD COLUMN content_type TEXT DEFAULT 'text'`)

	app.db.Exec(`CREATE TABLE IF NOT EXISTS attachments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		post_id INTEGER NOT NULL,
		filename TEXT NOT NULL,
		orig_name TEXT NOT NULL,
		file_type TEXT NOT NULL,
		file_size INTEGER DEFAULT 0,
		created_at TEXT NOT NULL
	)`)

	app.db.Exec(`CREATE TABLE IF NOT EXISTS categories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		username TEXT NOT NULL,
		sort_order INTEGER DEFAULT 0,
		UNIQUE(name, username)
	)`)

	app.db.Exec(`CREATE TABLE IF NOT EXISTS tags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		username TEXT NOT NULL,
		UNIQUE(name, username)
	)`)

	app.db.Exec(`CREATE TABLE IF NOT EXISTS api_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		token TEXT NOT NULL UNIQUE,
		username TEXT NOT NULL,
		created_at TEXT NOT NULL,
		last_used TEXT DEFAULT ''
	)`)

	// 消息广场表
	app.db.Exec(`CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		content TEXT NOT NULL,
		username TEXT NOT NULL,
		created_at TEXT NOT NULL
	)`)
	app.db.Exec(`ALTER TABLE messages ADD COLUMN file_url TEXT DEFAULT ''`)
	app.db.Exec(`ALTER TABLE messages ADD COLUMN file_type TEXT DEFAULT ''`)
	app.db.Exec(`ALTER TABLE messages ADD COLUMN file_name TEXT DEFAULT ''`)
	app.db.Exec(`CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author)`)
	app.db.Exec(`CREATE INDEX IF NOT EXISTS idx_posts_deleted ON posts(is_deleted)`)
	app.db.Exec(`CREATE INDEX IF NOT EXISTS idx_attachments_post ON attachments(post_id)`)
	app.db.Exec(`CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)`)

	var count int
	app.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		app.db.Exec("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", "admin", string(hash))
	}
}

func (app *App) loadSettings() {
	data, err := os.ReadFile(filepath.Join(app.workDir, "data", "settings.json"))
	if err == nil {
		_ = json.Unmarshal(data, &app.settings)
	}
	if app.settings.Port == 0 {
		app.settings.Port = 5000
	}
	if app.settings.MaxUploadMB <= 0 {
		app.settings.MaxUploadMB = 100
	}
}

func (app *App) saveSettings() {
	data, _ := json.MarshalIndent(app.settings, "", "  ")
	_ = os.WriteFile(filepath.Join(app.workDir, "data", "settings.json"), data, 0644)
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func nowStr() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func countWords(s string) int {
	return len([]rune(strings.TrimSpace(s)))
}

func getFileType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg":
		return "image"
	case ".mp4", ".webm", ".mov", ".avi", ".mkv":
		return "video"
	case ".mp3", ".wav", ".ogg", ".flac", ".aac":
		return "audio"
	case ".pdf":
		return "pdf"
	case ".md", ".txt":
		return "text"
	default:
		return "file"
	}
}

func (app *App) maxUploadBytes() int64 {
	mb := app.settings.MaxUploadMB
	if mb <= 0 {
		mb = 100
	}
	return int64(mb) * 1024 * 1024
}

func (app *App) getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	app.sessionMu.RLock()
	defer app.sessionMu.RUnlock()
	sess := app.sessions[cookie.Value]
	if sess != nil && time.Now().Before(sess.ExpiresAt) {
		return sess
	}
	return nil
}

func (app *App) getAPIUser(r *http.Request) string {
	token := r.Header.Get("X-API-Token")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		return ""
	}
	var username string
	err := app.db.QueryRow("SELECT username FROM api_tokens WHERE token = ?", token).Scan(&username)
	if err != nil {
		return ""
	}
	app.db.Exec("UPDATE api_tokens SET last_used = ? WHERE token = ?", nowStr(), token)
	return username
}

func (app *App) requireAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	if sess := app.getSession(r); sess != nil {
		return sess.Username, false
	}
	if user := app.getAPIUser(r); user != "" {
		return user, true
	}
	jsonError(w, "请先登录", http.StatusUnauthorized)
	return "", false
}

func (app *App) requireLogin(w http.ResponseWriter, r *http.Request) *Session {
	if sess := app.getSession(r); sess != nil {
		return sess
	}
	jsonError(w, "请先登录", http.StatusUnauthorized)
	return nil
}

func (app *App) requireAdmin(w http.ResponseWriter, r *http.Request) *Session {
	sess := app.requireLogin(w, r)
	if sess == nil {
		return nil
	}
	if !sess.IsAdmin {
		jsonError(w, "需要管理员权限", http.StatusForbidden)
		return nil
	}
	return sess
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (app *App) broadcastToUser(username string, msg interface{}) {
	data, _ := json.Marshal(msg)
	app.clientsMu.RLock()
	defer app.clientsMu.RUnlock()
	for client, user := range app.clients {
		if user == username {
			_ = client.WriteMessage(websocket.TextMessage, data)
		}
	}
}

// 广播给所有在线用户
func (app *App) broadcastToAll(msg interface{}) {
	data, _ := json.Marshal(msg)
	app.clientsMu.RLock()
	defer app.clientsMu.RUnlock()
	for client := range app.clients {
		_ = client.WriteMessage(websocket.TextMessage, data)
	}
}

func sameOrigin(origin string, r *http.Request) bool {
	if origin == "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	want := scheme + "://" + r.Host
	return origin == want
}

func (app *App) checkWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return sameOrigin(origin, r)
}

func (app *App) handleWS(w http.ResponseWriter, r *http.Request) {
	sess := app.getSession(r)
	if sess == nil {
		http.Error(w, "未登录", http.StatusUnauthorized)
		return
	}
	conn, err := app.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	app.clientsMu.Lock()
	app.clients[conn] = sess.Username
	app.clientsMu.Unlock()

	defer func() {
		app.clientsMu.Lock()
		delete(app.clients, conn)
		app.clientsMu.Unlock()
	}()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (app *App) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "无效请求", http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 2 || len(req.Password) < 4 {
		jsonError(w, "用户名至少2位，密码至少4位", http.StatusBadRequest)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	_, err := app.db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", req.Username, string(hash))
	if err != nil {
		jsonError(w, "用户名已存在", http.StatusConflict)
		return
	}
	jsonResponse(w, map[string]string{"message": "注册成功"})
}

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		jsonError(w, "无效请求", http.StatusBadRequest)
		return
	}
	var password string
	var isAdmin bool
	err := app.db.QueryRow("SELECT password, is_admin FROM users WHERE username = ?", req.Username).Scan(&password, &isAdmin)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(password), []byte(req.Password)) != nil {
		jsonError(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	token := generateToken()
	app.sessionMu.Lock()
	app.sessions[token] = &Session{Username: req.Username, IsAdmin: isAdmin, ExpiresAt: time.Now().Add(7 * 24 * time.Hour)}
	app.sessionMu.Unlock()

	c := &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		MaxAge:   7 * 24 * 3600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	}
	http.SetCookie(w, c)

	jsonResponse(w, map[string]interface{}{"username": req.Username, "is_admin": isAdmin})
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session"); err == nil {
		app.sessionMu.Lock()
		delete(app.sessions, cookie.Value)
		app.sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil})
	jsonResponse(w, map[string]string{"message": "已退出"})
}

func (app *App) handleSession(w http.ResponseWriter, r *http.Request) {
	sess := app.getSession(r)
	if sess == nil {
		jsonResponse(w, map[string]bool{"logged_in": false})
		return
	}
	jsonResponse(w, map[string]interface{}{"logged_in": true, "username": sess.Username, "is_admin": sess.IsAdmin})
}

func clampString(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	if maxRunes <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes])
}

func sanitizeTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := make(map[string]bool)
	for _, t := range tags {
		t = clampString(t, 32)
		t = strings.ReplaceAll(t, ",", "")
		if t == "" {
			continue
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
		if len(out) >= 20 {
			break
		}
	}
	return out
}

func safeSortField(sortBy string) string {
	switch sortBy {
	case "created_at", "updated_at", "title":
		return sortBy
	default:
		return "created_at"
	}
}

func escapeHTML(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sanitizeForRender(input string) string {
	if input == "" {
		return ""
	}
	const maxRunes = 200000
	if len([]rune(input)) > maxRunes {
		input = string([]rune(input)[:maxRunes])
	}

	s := strings.ReplaceAll(input, "\r\n", "\n")

	var out strings.Builder
	i := 0
	for i < len(s) {
		start := strings.Index(s[i:], "```")
		if start < 0 {
			plain := s[i:]
			out.WriteString(strings.ReplaceAll(escapeHTML(plain), "\n", "<br>"))
			break
		}
		start += i
		if start > i {
			plain := s[i:start]
			out.WriteString(strings.ReplaceAll(escapeHTML(plain), "\n", "<br>"))
		}

		langLineEnd := strings.IndexByte(s[start+3:], '\n')
		lang := ""
		codeStart := start + 3
		if langLineEnd >= 0 {
			langLineEnd = start + 3 + langLineEnd
			lang = strings.TrimSpace(s[start+3 : langLineEnd])
			codeStart = langLineEnd + 1
		} else {
			out.WriteString(escapeHTML(s[start:]))
			break
		}

		end := strings.Index(s[codeStart:], "```")
		if end < 0 {
			out.WriteString(escapeHTML(s[start:]))
			break
		}
		end = codeStart + end
		code := s[codeStart:end]

		lang = clampString(lang, 32)
		lang = strings.ToLower(lang)
		langClass := ""
		if lang != "" {
			sb := strings.Builder{}
			for _, r := range lang {
				if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
					sb.WriteRune(r)
				}
			}
			if sb.Len() > 0 {
				langClass = ` class="language-` + sb.String() + `"`
			}
		}

		out.WriteString("<pre><code" + langClass + ">")
		out.WriteString(escapeHTML(code))
		out.WriteString("</code></pre>")

		i = end + 3
	}

	return out.String()
}

func sanitizeFilenameForDownload(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "file"
	}
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "\x00", "")
	if len([]rune(name)) > 120 {
		name = string([]rune(name)[:120])
	}
	return name
}

func validFileID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func (app *App) handleGetPosts(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	query := r.URL.Query()
	category := clampString(query.Get("category"), 64)
	tag := clampString(query.Get("tag"), 32)
	search := clampString(query.Get("search"), 120)
	showDraft := query.Get("draft") == "1"
	showTrash := query.Get("trash") == "1"
	sortBy := safeSortField(query.Get("sort"))

	sqlStr := `SELECT id, title, content, content_type, category, tags, is_draft, is_pinned, is_starred, source, author, created_at, updated_at 
			FROM posts WHERE author = ? AND is_deleted = ?`
	args := []interface{}{username, showTrash}

	if !showTrash {
		if showDraft {
			sqlStr += " AND is_draft = 1"
		} else {
			sqlStr += " AND is_draft = 0"
		}
	}
	if category != "" {
		sqlStr += " AND category = ?"
		args = append(args, category)
	}
	if tag != "" {
		sqlStr += " AND (',' || tags || ',') LIKE ?"
		args = append(args, "%,"+tag+",%")
	}
	if search != "" {
		sqlStr += " AND (title LIKE ? OR content LIKE ?)"
		args = append(args, "%"+search+"%", "%"+search+"%")
	}

	sqlStr += " ORDER BY is_pinned DESC, " + sortBy + " DESC"

	rows, err := app.db.Query(sqlStr, args...)
	if err != nil {
		jsonError(w, "查询失败", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	posts := []Post{}
	for rows.Next() {
		var p Post
		var tags string
		var contentType sql.NullString
		_ = rows.Scan(&p.ID, &p.Title, &p.Content, &contentType, &p.Category, &tags, &p.IsDraft, &p.IsPinned, &p.IsStarred, &p.Source, &p.Author, &p.CreatedAt, &p.UpdatedAt)
		if tags != "" {
			p.Tags = strings.Split(tags, ",")
		}
		if contentType.Valid && contentType.String != "" {
			p.ContentType = contentType.String
		} else {
			p.ContentType = "text"
		}
		p.WordCount = countWords(p.Content)
		p.Content = ""
		p.SafeContent = ""
		posts = append(posts, p)
	}
	jsonResponse(w, posts)
}

func (app *App) handleGetPost(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/posts/")
	var p Post
	var tags string
	var contentType sql.NullString
	err := app.db.QueryRow(`SELECT id, title, content, content_type, category, tags, is_draft, is_pinned, is_starred, source, author, created_at, updated_at 
		FROM posts WHERE id = ? AND author = ? AND is_deleted = 0`, id, username).Scan(
		&p.ID, &p.Title, &p.Content, &contentType, &p.Category, &tags, &p.IsDraft, &p.IsPinned, &p.IsStarred, &p.Source, &p.Author, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		jsonError(w, "日志不存在", http.StatusNotFound)
		return
	}
	if tags != "" {
		p.Tags = strings.Split(tags, ",")
	}
	if contentType.Valid && contentType.String != "" {
		p.ContentType = contentType.String
	} else {
		p.ContentType = "text"
	}
	p.WordCount = countWords(p.Content)

	// 根据内容类型决定如何处理
	if p.ContentType == "html" {
		p.SafeContent = p.Content // HTML 内容直接使用，已在导入时处理过
	} else {
		p.SafeContent = sanitizeForRender(p.Content)
	}

	jsonResponse(w, p)
}

func (app *App) decodeJSONStrict(r *http.Request, v any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func (app *App) handleCreatePost(w http.ResponseWriter, r *http.Request) {
	username, isAPI := app.requireAuth(w, r)
	if username == "" {
		return
	}

	var req struct {
		Title       string   `json:"title"`
		Content     string   `json:"content"`
		ContentType string   `json:"content_type"`
		Category    string   `json:"category"`
		Tags        []string `json:"tags"`
		IsDraft     bool     `json:"is_draft"`
		Source      string   `json:"source"`
	}
	if err := app.decodeJSONLoose(r, &req, 4*1024*1024); err != nil {
		jsonError(w, "无效请求", http.StatusBadRequest)
		return
	}

	if !utf8.ValidString(req.Content) || !utf8.ValidString(req.Title) {
		jsonError(w, "内容包含无效字符", http.StatusBadRequest)
		return
	}

	req.Title = clampString(req.Title, 120)
	req.Category = clampString(req.Category, 64)
	req.Tags = sanitizeTags(req.Tags)

	if req.ContentType == "" {
		req.ContentType = "text"
	}
	req.ContentType = clampString(req.ContentType, 16)

	if strings.HasPrefix(req.Content, "/todo ") {
		req.Content = strings.TrimPrefix(req.Content, "/todo ")
		req.Tags = append(req.Tags, "待办")
		req.Tags = sanitizeTags(req.Tags)
	}

	if req.Title == "" {
		lines := strings.SplitN(req.Content, "\n", 2)
		first := clampString(lines[0], 50)
		if first != "" {
			if len([]rune(lines[0])) > 50 {
				req.Title = first + "..."
			} else {
				req.Title = first
			}
		} else {
			req.Title = "无标题"
		}
	}

	source := req.Source
	if source == "" {
		if isAPI {
			source = "api"
		} else {
			source = "web"
		}
	}
	source = clampString(source, 16)

	now := nowStr()
	tags := strings.Join(req.Tags, ",")
	result, err := app.db.Exec(`INSERT INTO posts (title, content, content_type, category, tags, is_draft, source, author, created_at, updated_at) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Title, req.Content, req.ContentType, req.Category, tags, req.IsDraft, source, username, now, now)
	if err != nil {
		jsonError(w, "保存失败", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()

	safeContent := req.Content
	if req.ContentType != "html" {
		safeContent = sanitizeForRender(req.Content)
	}

	post := Post{
		ID:          id,
		Title:       req.Title,
		Content:     req.Content,
		SafeContent: safeContent,
		ContentType: req.ContentType,
		Category:    req.Category,
		Tags:        req.Tags,
		IsDraft:     req.IsDraft,
		Source:      source,
		Author:      username,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	app.broadcastToUser(username, map[string]interface{}{"type": "post_created", "data": post})
	jsonResponse(w, post)

}

func (app *App) decodeJSONLoose(r *http.Request, v any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = 2 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

func (app *App) handleUpdatePost(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/posts/")
	var req struct {
		Title       *string  `json:"title"`
		Content     *string  `json:"content"`
		ContentType *string  `json:"content_type"`
		Category    *string  `json:"category"`
		Tags        []string `json:"tags"`
		IsDraft     *bool    `json:"is_draft"`
		IsPinned    *bool    `json:"is_pinned"`
		IsStarred   *bool    `json:"is_starred"`
	}
	if err := app.decodeJSONLoose(r, &req, 4*1024*1024); err != nil {
		jsonError(w, "无效请求", http.StatusBadRequest)
		return
	}

	var existing Post
	var tagsStr string
	var contentType sql.NullString
	err := app.db.QueryRow(`SELECT id, title, content, content_type, category, tags, is_draft, is_pinned, is_starred, source, author, created_at, updated_at
		FROM posts WHERE id = ? AND author = ? AND is_deleted = 0`, id, username).
		Scan(&existing.ID, &existing.Title, &existing.Content, &contentType, &existing.Category, &tagsStr, &existing.IsDraft, &existing.IsPinned, &existing.IsStarred, &existing.Source, &existing.Author, &existing.CreatedAt, &existing.UpdatedAt)
	if err != nil {
		jsonError(w, "日志不存在", http.StatusNotFound)
		return
	}
	if contentType.Valid && contentType.String != "" {
		existing.ContentType = contentType.String
	} else {
		existing.ContentType = "text"
	}
	if tagsStr != "" {
		existing.Tags = strings.Split(tagsStr, ",")
	}

	if req.Title != nil {
		existing.Title = clampString(*req.Title, 120)
	}
	if req.Content != nil {
		if !utf8.ValidString(*req.Content) {
			jsonError(w, "内容包含无效字符", http.StatusBadRequest)
			return
		}
		existing.Content = *req.Content
	}
	if req.ContentType != nil {
		ct := clampString(*req.ContentType, 16)
		if ct == "" {
			ct = "text"
		}
		existing.ContentType = ct
	}
	if req.Category != nil {
		existing.Category = clampString(*req.Category, 64)
	}
	if req.Tags != nil {
		existing.Tags = sanitizeTags(req.Tags)
	}
	if req.IsDraft != nil {
		existing.IsDraft = *req.IsDraft
	}
	if req.IsPinned != nil {
		existing.IsPinned = *req.IsPinned
	}
	if req.IsStarred != nil {
		existing.IsStarred = *req.IsStarred
	}

	now := nowStr()
	_, _ = app.db.Exec(`UPDATE posts SET title=?, content=?, content_type=?, category=?, tags=?, is_draft=?, is_pinned=?, is_starred=?, updated_at=? 
		WHERE id=? AND author=? AND is_deleted=0`,
		existing.Title, existing.Content, existing.ContentType, existing.Category, strings.Join(existing.Tags, ","), existing.IsDraft, existing.IsPinned, existing.IsStarred, now, id, username)

	app.broadcastToUser(username, map[string]interface{}{"type": "post_updated", "data": map[string]string{"id": id}})
	jsonResponse(w, map[string]string{"message": "已更新"})
}

func (app *App) handleDeletePost(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/posts/")
	permanent := r.URL.Query().Get("permanent") == "1"

	if permanent {
		var postID int64
		fmt.Sscanf(id, "%d", &postID)

		rows, _ := app.db.Query("SELECT filename FROM attachments WHERE post_id = ?", postID)
		for rows.Next() {
			var filename string
			_ = rows.Scan(&filename)
			_ = os.Remove(filepath.Join(app.workDir, "uploads", filename))
		}
		rows.Close()

		app.db.Exec("DELETE FROM attachments WHERE post_id = ?", postID)
		app.db.Exec("DELETE FROM posts WHERE id = ? AND author = ?", id, username)
	} else {
		app.db.Exec("UPDATE posts SET is_deleted = 1, deleted_at = ? WHERE id = ? AND author = ?", nowStr(), id, username)
	}

	app.broadcastToUser(username, map[string]interface{}{"type": "post_deleted", "data": map[string]string{"id": id}})
	jsonResponse(w, map[string]string{"message": "已删除"})
}

func (app *App) handleRestorePost(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/posts/restore/")
	app.db.Exec("UPDATE posts SET is_deleted = 0, deleted_at = '' WHERE id = ? AND author = ?", id, username)
	jsonResponse(w, map[string]string{"message": "已恢复"})
}

func (app *App) handleBatchOperation(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	var req struct {
		IDs      []int64 `json:"ids"`
		Action   string  `json:"action"`
		Category string  `json:"category,omitempty"`
		Tag      string  `json:"tag,omitempty"`
	}
	if app.decodeJSONLoose(r, &req, 2*1024*1024) != nil || len(req.IDs) == 0 {
		jsonError(w, "无效请求", http.StatusBadRequest)
		return
	}

	placeholders := make([]string, len(req.IDs))
	args := make([]interface{}, len(req.IDs)+1)
	args[0] = username
	for i, id := range req.IDs {
		placeholders[i] = "?"
		args[i+1] = id
	}
	idList := strings.Join(placeholders, ",")

	switch req.Action {
	case "delete":
		app.db.Exec("UPDATE posts SET is_deleted = 1, deleted_at = ? WHERE author = ? AND id IN ("+idList+")", append([]interface{}{nowStr(), username}, args[1:]...)...)
	case "restore":
		app.db.Exec("UPDATE posts SET is_deleted = 0, deleted_at = '' WHERE author = ? AND id IN ("+idList+")", args...)
	case "permanent_delete":
		for _, id := range req.IDs {
			rows, _ := app.db.Query("SELECT filename FROM attachments WHERE post_id = ?", id)
			for rows.Next() {
				var filename string
				_ = rows.Scan(&filename)
				_ = os.Remove(filepath.Join(app.workDir, "uploads", filename))
			}
			rows.Close()
			app.db.Exec("DELETE FROM attachments WHERE post_id = ?", id)
		}
		app.db.Exec("DELETE FROM posts WHERE author = ? AND id IN ("+idList+")", args...)
	case "set_category":
		cat := clampString(req.Category, 64)
		app.db.Exec("UPDATE posts SET category = ?, updated_at = ? WHERE author = ? AND id IN ("+idList+")", append([]interface{}{cat, nowStr(), username}, args[1:]...)...)
	case "add_tag":
		tag := clampString(req.Tag, 32)
		tag = strings.ReplaceAll(tag, ",", "")
		if tag == "" {
			jsonError(w, "标签不能为空", http.StatusBadRequest)
			return
		}
		rows, _ := app.db.Query("SELECT id, tags FROM posts WHERE author = ? AND id IN ("+idList+")", args...)
		for rows.Next() {
			var id int64
			var tags string
			_ = rows.Scan(&id, &tags)
			tagList := []string{}
			if tags != "" {
				tagList = strings.Split(tags, ",")
			}
			found := false
			for _, t := range tagList {
				if t == tag {
					found = true
					break
				}
			}
			if !found {
				tagList = append(tagList, tag)
				app.db.Exec("UPDATE posts SET tags = ?, updated_at = ? WHERE id = ?", strings.Join(tagList, ","), nowStr(), id)
			}
		}
		rows.Close()
	case "remove_tag":
		tag := clampString(req.Tag, 32)
		tag = strings.ReplaceAll(tag, ",", "")
		rows, _ := app.db.Query("SELECT id, tags FROM posts WHERE author = ? AND id IN ("+idList+")", args...)
		for rows.Next() {
			var id int64
			var tags string
			_ = rows.Scan(&id, &tags)
			if tags != "" {
				tagList := strings.Split(tags, ",")
				newTags := []string{}
				for _, t := range tagList {
					if t != tag {
						newTags = append(newTags, t)
					}
				}
				app.db.Exec("UPDATE posts SET tags = ?, updated_at = ? WHERE id = ?", strings.Join(newTags, ","), nowStr(), id)
			}
		}
		rows.Close()
	}

	jsonResponse(w, map[string]string{"message": "操作完成"})
}

func (app *App) readMultipartOneFile(r *http.Request) (postID int64, origName string, data io.Reader, sizeLimit int64, err error) {
	sizeLimit = app.maxUploadBytes()
	r.Body = http.MaxBytesReader(nil, r.Body, sizeLimit+1024)

	mr, err := r.MultipartReader()
	if err != nil {
		return 0, "", nil, sizeLimit, err
	}

	var fileData io.Reader
	var filename string

	for {
		part, err2 := mr.NextPart()
		if err2 == io.EOF {
			break
		}
		if err2 != nil {
			return 0, "", nil, sizeLimit, err2
		}
		switch part.FormName() {
		case "post_id":
			b, _ := io.ReadAll(part)
			fmt.Sscanf(string(b), "%d", &postID)
			part.Close()
		case "file":
			filename = part.FileName()
			fileData = part
			return postID, filename, fileData, sizeLimit, nil
		default:
			part.Close()
		}
	}

	return 0, "", nil, sizeLimit, errors.New("no file")
}

func (app *App) handleUpload(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	postID, filename, fileData, _, err := app.readMultipartOneFile(r)
	if err != nil || fileData == nil || filename == "" {
		jsonError(w, "文件上传失败", http.StatusBadRequest)
		return
	}

	filename = sanitizeFilenameForDownload(filename)

	if postID > 0 {
		var author string
		err := app.db.QueryRow("SELECT author FROM posts WHERE id = ?", postID).Scan(&author)
		if err != nil || author != username {
			jsonError(w, "日志不存在", http.StatusNotFound)
			return
		}
	}

	ext := strings.ToLower(filepath.Ext(filename))
	safeName := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), generateToken()[:8], ext)
	savePath := filepath.Join(app.workDir, "uploads", safeName)

	dst, err := os.Create(savePath)
	if err != nil {
		jsonError(w, "保存失败", http.StatusInternalServerError)
		return
	}
	written, copyErr := io.Copy(dst, fileData)
	_ = dst.Close()
	if copyErr != nil {
		_ = os.Remove(savePath)
		jsonError(w, "保存失败", http.StatusInternalServerError)
		return
	}

	if written > app.maxUploadBytes() {
		_ = os.Remove(savePath)
		jsonError(w, "文件过大", http.StatusRequestEntityTooLarge)
		return
	}

	// 如果是 HTML 文件，处理其中的 base64 图片
	if ext == ".html" || ext == ".htm" {
		htmlContent, err := os.ReadFile(savePath)
		if err == nil {
			content := string(htmlContent)

			imgRegex := regexp.MustCompile(`<img[^>]*src="(data:image/([^;]+);base64,([^"]+))"[^>]*>`)
			content = imgRegex.ReplaceAllStringFunc(content, func(match string) string {
				matches := imgRegex.FindStringSubmatch(match)
				if len(matches) < 4 {
					return match
				}

				imgExt := "." + matches[2]
				if imgExt == ".jpeg" {
					imgExt = ".jpg"
				}

				imgData, err := base64.StdEncoding.DecodeString(matches[3])
				if err != nil || len(imgData) == 0 {
					return match
				}

				imgName := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), generateToken()[:8], imgExt)
				imgPath := filepath.Join(app.workDir, "uploads", imgName)

				if err := os.WriteFile(imgPath, imgData, 0644); err != nil {
					return match
				}

				return regexp.MustCompile(`src="[^"]+"`).ReplaceAllString(match, fmt.Sprintf(`src="/api/file/%s"`, imgName))
			})

			os.WriteFile(savePath, []byte(content), 0644)
		}
	}

	now := nowStr()
	fileType := getFileType(filename)

	// 消息广场（post_id=0）：只保存文件并返回 URL，不创建日志或附件，由前端再 POST /api/messages 写入消息
	if postID == 0 {
		msgSafeName := fmt.Sprintf("msg_%d_%s%s", time.Now().UnixNano(), generateToken()[:8], ext)
		msgPath := filepath.Join(app.workDir, "uploads", msgSafeName)
		if err := os.Rename(savePath, msgPath); err != nil {
			// 跨盘时 Rename 可能失败，改为复制后删除
			src, _ := os.Open(savePath)
			dst, createErr := os.Create(msgPath)
			if createErr != nil {
				src.Close()
				os.Remove(savePath)
				jsonError(w, "保存失败", http.StatusInternalServerError)
				return
			}
			io.Copy(dst, src)
			src.Close()
			dst.Close()
			os.Remove(savePath)
		}
		jsonResponse(w, map[string]interface{}{
			"filename":   msgSafeName,
			"orig_name":  filename,
			"file_type":  fileType,
			"file_size":  written,
			"url":        "/api/file/" + msgSafeName,
		})
		return
	}

	result, _ := app.db.Exec(`INSERT INTO attachments (post_id, filename, orig_name, file_type, file_size, created_at) 
		VALUES (?, ?, ?, ?, ?, ?)`, postID, safeName, filename, fileType, written, now)
	attID, _ := result.LastInsertId()

	att := Attachment{ID: attID, PostID: postID, Filename: safeName, OrigName: filename, FileType: fileType, FileSize: written, CreatedAt: now}
	app.broadcastToUser(username, map[string]interface{}{"type": "attachment_added", "data": att})
	jsonResponse(w, map[string]interface{}{
		"id":         att.ID,
		"post_id":    att.PostID,
		"filename":   att.Filename,
		"orig_name":  att.OrigName,
		"file_type":  att.FileType,
		"file_size":  att.FileSize,
		"created_at": att.CreatedAt,
		"url":        "/api/file/" + safeName,
	})
}

func (app *App) handleUploadChunk(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	r.Body = http.MaxBytesReader(nil, r.Body, app.maxUploadBytes()+1024)

	mr, err := r.MultipartReader()
	if err != nil {
		jsonError(w, "参数错误", http.StatusBadRequest)
		return
	}

	var fileID, indexStr string
	var chunkData io.Reader

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			jsonError(w, "读取失败", http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "file_id":
			b, _ := io.ReadAll(part)
			fileID = strings.TrimSpace(string(b))
			part.Close()
		case "index":
			b, _ := io.ReadAll(part)
			indexStr = strings.TrimSpace(string(b))
			part.Close()
		case "chunk":
			if fileID == "" || indexStr == "" {
				part.Close()
				jsonError(w, "参数顺序错误", http.StatusBadRequest)
				return
			}
			chunkData = part
			goto writeChunk
		default:
			part.Close()
		}
	}

writeChunk:
	if chunkData == nil || !validFileID(fileID) || indexStr == "" {
		jsonError(w, "参数错误", http.StatusBadRequest)
		return
	}

	if _, err := strconv.Atoi(indexStr); err != nil {
		jsonError(w, "参数错误", http.StatusBadRequest)
		return
	}

	chunkDir := filepath.Join(app.workDir, "uploads", "chunks_"+fileID)
	if _, loaded := chunkDirs.LoadOrStore(fileID, true); !loaded {
		_ = os.MkdirAll(chunkDir, 0755)
	}

	dst, err := os.Create(filepath.Join(chunkDir, indexStr))
	if err != nil {
		jsonError(w, "保存分片失败", http.StatusInternalServerError)
		return
	}
	_, _ = io.Copy(dst, chunkData)
	_ = dst.Close()

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (app *App) handleUploadMerge(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	var req struct {
		FileID   string `json:"file_id"`
		Filename string `json:"filename"`
		Chunks   int    `json:"chunks"`
		PostID   int64  `json:"post_id"`
	}
	if app.decodeJSONLoose(r, &req, 1*1024*1024) != nil || req.FileID == "" || req.Chunks < 1 {
		jsonError(w, "参数错误", http.StatusBadRequest)
		return
	}
	if !validFileID(req.FileID) {
		jsonError(w, "参数错误", http.StatusBadRequest)
		return
	}
	if req.Chunks > 5000 {
		jsonError(w, "分片过多", http.StatusBadRequest)
		return
	}

	req.Filename = sanitizeFilenameForDownload(req.Filename)

	if req.PostID > 0 {
		var author string
		err := app.db.QueryRow("SELECT author FROM posts WHERE id = ?", req.PostID).Scan(&author)
		if err != nil || author != username {
			jsonError(w, "日志不存在", http.StatusNotFound)
			return
		}
	}

	chunkDir := filepath.Join(app.workDir, "uploads", "chunks_"+req.FileID)
	chunkDirs.Delete(req.FileID)

	ext := strings.ToLower(filepath.Ext(req.Filename))
	safeName := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), generateToken()[:8], ext)
	savePath := filepath.Join(app.workDir, "uploads", safeName)

	dst, err := os.Create(savePath)
	if err != nil {
		jsonError(w, "创建文件失败", http.StatusInternalServerError)
		return
	}

	var totalSize int64
	maxBytes := app.maxUploadBytes()
	for i := 0; i < req.Chunks; i++ {
		chunkPath := filepath.Join(chunkDir, strconv.Itoa(i))
		chunk, err := os.Open(chunkPath)
		if err != nil {
			_ = dst.Close()
			_ = os.Remove(savePath)
			jsonError(w, "分片不完整", http.StatusBadRequest)
			return
		}
		n, _ := io.Copy(dst, chunk)
		totalSize += n
		_ = chunk.Close()
		_ = os.Remove(chunkPath)

		if totalSize > maxBytes {
			_ = dst.Close()
			_ = os.Remove(savePath)
			jsonError(w, "文件过大", http.StatusRequestEntityTooLarge)
			return
		}
	}
	_ = dst.Close()
	_ = os.Remove(chunkDir)

	now := nowStr()
	fileType := getFileType(req.Filename)
	postID := req.PostID

	if postID == 0 {
		// 消息广场：只合并文件并返回，不创建日志条目，由前端再 POST /api/messages 写入 messages 表
		jsonResponse(w, map[string]interface{}{
			"filename":   safeName,
			"orig_name":  req.Filename,
			"file_type":  fileType,
			"file_size":  totalSize,
			"url":        "/api/file/" + safeName,
		})
		return
	}

	result, _ := app.db.Exec(`INSERT INTO attachments (post_id, filename, orig_name, file_type, file_size, created_at) 
		VALUES (?, ?, ?, ?, ?, ?)`, postID, safeName, req.Filename, fileType, totalSize, now)
	attID, _ := result.LastInsertId()

	att := Attachment{ID: attID, PostID: postID, Filename: safeName, OrigName: req.Filename, FileType: fileType, FileSize: totalSize, CreatedAt: now}
	app.broadcastToUser(username, map[string]interface{}{"type": "attachment_added", "data": att})
	jsonResponse(w, map[string]interface{}{
		"id":         att.ID,
		"post_id":    att.PostID,
		"filename":   att.Filename,
		"orig_name":  att.OrigName,
		"file_type":  att.FileType,
		"file_size":  att.FileSize,
		"created_at": att.CreatedAt,
		"url":        "/api/file/" + safeName,
	})
}

func (app *App) handleGetAttachments(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	postID := strings.TrimPrefix(r.URL.Path, "/api/attachments/")

	var author string
	err := app.db.QueryRow("SELECT author FROM posts WHERE id = ?", postID).Scan(&author)
	if err != nil || author != username {
		jsonError(w, "日志不存在", http.StatusNotFound)
		return
	}

	rows, _ := app.db.Query("SELECT id, post_id, filename, orig_name, file_type, file_size, created_at FROM attachments WHERE post_id = ?", postID)
	defer rows.Close()

	atts := []Attachment{}
	for rows.Next() {
		var a Attachment
		_ = rows.Scan(&a.ID, &a.PostID, &a.Filename, &a.OrigName, &a.FileType, &a.FileSize, &a.CreatedAt)
		atts = append(atts, a)
	}
	jsonResponse(w, atts)
}

func (app *App) handleDeleteAttachment(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/attachments/")

	var filename string
	var postID int64
	err := app.db.QueryRow(`SELECT a.filename, a.post_id FROM attachments a 
		JOIN posts p ON a.post_id = p.id WHERE a.id = ? AND p.author = ?`, id, username).Scan(&filename, &postID)
	if err != nil {
		jsonError(w, "附件不存在", http.StatusNotFound)
		return
	}

	_ = os.Remove(filepath.Join(app.workDir, "uploads", filename))
	app.db.Exec("DELETE FROM attachments WHERE id = ?", id)

	app.broadcastToUser(username, map[string]interface{}{"type": "attachment_deleted", "data": map[string]string{"id": id}})
	jsonResponse(w, map[string]string{"message": "已删除"})
}

func (app *App) handleFile(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/api/file/")
	filename = strings.TrimSpace(filename)
	if filename == "" || strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		http.NotFound(w, r)
		return
	}

	filePath := filepath.Join(app.workDir, "uploads", filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	ext := strings.ToLower(filepath.Ext(filename))
	mtype := mime.TypeByExtension(ext)
	if mtype == "" {
		mtype = "application/octet-stream"
	}

	w.Header().Set("Content-Type", mtype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, filePath)
}

func (app *App) handleGetCategories(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	rows, _ := app.db.Query("SELECT id, name, sort_order FROM categories WHERE username = ? ORDER BY sort_order, id", username)
	defer rows.Close()

	cats := []map[string]interface{}{}
	for rows.Next() {
		var id int64
		var name string
		var sortOrder int
		_ = rows.Scan(&id, &name, &sortOrder)
		cats = append(cats, map[string]interface{}{"id": id, "name": name, "sort_order": sortOrder})
	}
	jsonResponse(w, cats)
}

func (app *App) handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	var req struct {
		Name      string `json:"name"`
		SortOrder int    `json:"sort_order"`
	}
	if app.decodeJSONLoose(r, &req, 128*1024) != nil || req.Name == "" {
		jsonError(w, "分类名不能为空", http.StatusBadRequest)
		return
	}
	req.Name = clampString(req.Name, 64)

	result, err := app.db.Exec("INSERT INTO categories (name, username, sort_order) VALUES (?, ?, ?)", req.Name, username, req.SortOrder)
	if err != nil {
		jsonError(w, "分类已存在", http.StatusConflict)
		return
	}
	id, _ := result.LastInsertId()
	jsonResponse(w, map[string]interface{}{"id": id, "name": req.Name})
}

func (app *App) handleUpdateCategory(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/categories/")
	var req struct {
		Name      string `json:"name"`
		SortOrder int    `json:"sort_order"`
	}
	if app.decodeJSONLoose(r, &req, 128*1024) != nil {
		jsonError(w, "无效请求", http.StatusBadRequest)
		return
	}
	req.Name = clampString(req.Name, 64)

	app.db.Exec("UPDATE categories SET name = ?, sort_order = ? WHERE id = ? AND username = ?", req.Name, req.SortOrder, id, username)
	jsonResponse(w, map[string]string{"message": "已更新"})
}

func (app *App) handleDeleteCategory(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/categories/")

	var name string
	app.db.QueryRow("SELECT name FROM categories WHERE id = ? AND username = ?", id, username).Scan(&name)

	app.db.Exec("UPDATE posts SET category = '' WHERE category = ? AND author = ?", name, username)
	app.db.Exec("DELETE FROM categories WHERE id = ? AND username = ?", id, username)
	jsonResponse(w, map[string]string{"message": "已删除"})
}

func (app *App) handleGetTags(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	rows, _ := app.db.Query("SELECT id, name FROM tags WHERE username = ? ORDER BY name", username)
	defer rows.Close()

	tags := []map[string]interface{}{}
	for rows.Next() {
		var id int64
		var name string
		_ = rows.Scan(&id, &name)
		tags = append(tags, map[string]interface{}{"id": id, "name": name})
	}
	jsonResponse(w, tags)
}

func (app *App) handleCreateTag(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if app.decodeJSONLoose(r, &req, 128*1024) != nil || req.Name == "" {
		jsonError(w, "标签名不能为空", http.StatusBadRequest)
		return
	}
	req.Name = clampString(req.Name, 32)
	req.Name = strings.ReplaceAll(req.Name, ",", "")

	result, err := app.db.Exec("INSERT INTO tags (name, username) VALUES (?, ?)", req.Name, username)
	if err != nil {
		jsonError(w, "标签已存在", http.StatusConflict)
		return
	}
	id, _ := result.LastInsertId()
	jsonResponse(w, map[string]interface{}{"id": id, "name": req.Name})
}

func (app *App) handleDeleteTag(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/tags/")

	var name string
	app.db.QueryRow("SELECT name FROM tags WHERE id = ? AND username = ?", id, username).Scan(&name)

	rows, _ := app.db.Query("SELECT id, tags FROM posts WHERE author = ? AND tags LIKE ?", username, "%"+name+"%")
	for rows.Next() {
		var postID int64
		var tags string
		_ = rows.Scan(&postID, &tags)
		tagList := strings.Split(tags, ",")
		newTags := []string{}
		for _, t := range tagList {
			if t != name {
				newTags = append(newTags, t)
			}
		}
		app.db.Exec("UPDATE posts SET tags = ? WHERE id = ?", strings.Join(newTags, ","), postID)
	}
	rows.Close()

	app.db.Exec("DELETE FROM tags WHERE id = ? AND username = ?", id, username)
	jsonResponse(w, map[string]string{"message": "已删除"})
}

func (app *App) handleGetTokens(w http.ResponseWriter, r *http.Request) {
	sess := app.requireLogin(w, r)
	if sess == nil {
		return
	}

	rows, _ := app.db.Query("SELECT id, name, created_at, last_used FROM api_tokens WHERE username = ?", sess.Username)
	defer rows.Close()

	tokens := []APIToken{}
	for rows.Next() {
		var t APIToken
		var lastUsed sql.NullString
		_ = rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &lastUsed)
		t.Username = sess.Username
		t.LastUsed = lastUsed.String
		tokens = append(tokens, t)
	}
	jsonResponse(w, tokens)
}

func (app *App) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	sess := app.requireLogin(w, r)
	if sess == nil {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if app.decodeJSONLoose(r, &req, 128*1024) != nil || strings.TrimSpace(req.Name) == "" {
		jsonError(w, "名称不能为空", http.StatusBadRequest)
		return
	}

	token := generateToken()
	now := nowStr()
	result, _ := app.db.Exec("INSERT INTO api_tokens (name, token, username, created_at) VALUES (?, ?, ?, ?)",
		clampString(req.Name, 64), token, sess.Username, now)
	id, _ := result.LastInsertId()

	jsonResponse(w, APIToken{ID: id, Name: req.Name, Token: token, Username: sess.Username, CreatedAt: now})
}

func (app *App) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	sess := app.requireLogin(w, r)
	if sess == nil {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/tokens/")
	app.db.Exec("DELETE FROM api_tokens WHERE id = ? AND username = ?", id, sess.Username)
	jsonResponse(w, map[string]string{"message": "已删除"})
}

func (app *App) handleExport(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	postID := r.URL.Query().Get("id")

	var rows *sql.Rows
	if postID != "" {
		rows, _ = app.db.Query(`SELECT id, title, content, content_type, category, tags, is_draft, is_pinned, is_starred, source, created_at, updated_at 
			FROM posts WHERE id = ? AND author = ? AND is_deleted = 0`, postID, username)
	} else {
		rows, _ = app.db.Query(`SELECT id, title, content, content_type, category, tags, is_draft, is_pinned, is_starred, source, created_at, updated_at 
			FROM posts WHERE author = ? AND is_deleted = 0 ORDER BY created_at DESC`, username)
	}
	defer rows.Close()

	posts := []Post{}
	for rows.Next() {
		var p Post
		var tags string
		var contentType sql.NullString
		_ = rows.Scan(&p.ID, &p.Title, &p.Content, &contentType, &p.Category, &tags, &p.IsDraft, &p.IsPinned, &p.IsStarred, &p.Source, &p.CreatedAt, &p.UpdatedAt)
		if tags != "" {
			p.Tags = strings.Split(tags, ",")
		}
		if contentType.Valid && contentType.String != "" {
			p.ContentType = contentType.String
		} else {
			p.ContentType = "text"
		}
		p.Author = username
		posts = append(posts, p)
	}

	if format == "markdown" {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=export.zip")

		zw := zip.NewWriter(w)
		for _, p := range posts {
			header := fmt.Sprintf("---\ntitle: %s\ncategory: %s\ntags: %s\ncontent_type: %s\ncreated: %s\n---\n\n",
				p.Title, p.Category, strings.Join(p.Tags, ", "), p.ContentType, p.CreatedAt)
			filename := fmt.Sprintf("%d_%s.md", p.ID, strings.ReplaceAll(p.Title, "/", "_"))
			f, _ := zw.Create(filename)
			_, _ = f.Write([]byte(header + p.Content))
		}
		_ = zw.Close()
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=export.json")
		_ = json.NewEncoder(w).Encode(posts)
	}
}

func (app *App) handleImport(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	r.Body = http.MaxBytesReader(nil, r.Body, 20*1024*1024)

	mr, err := r.MultipartReader()
	if err != nil {
		jsonError(w, "上传失败", http.StatusBadRequest)
		return
	}

	imported := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		filename := sanitizeFilenameForDownload(part.FileName())
		data, _ := io.ReadAll(part)
		part.Close()

		if strings.HasSuffix(filename, ".json") {
			var posts []Post
			if json.Unmarshal(data, &posts) == nil {
				for _, p := range posts {
					now := nowStr()
					tags := strings.Join(sanitizeTags(p.Tags), ",")
					contentType := p.ContentType
					if contentType == "" {
						contentType = "text"
					}
					app.db.Exec(`INSERT INTO posts (title, content, content_type, category, tags, is_draft, is_pinned, is_starred, source, author, created_at, updated_at) 
						VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'import', ?, ?, ?)`,
						clampString(p.Title, 120), p.Content, clampString(contentType, 16), clampString(p.Category, 64), tags, p.IsDraft, p.IsPinned, p.IsStarred, username, now, now)
					imported++
				}
			}
		} else if strings.HasSuffix(filename, ".md") {
			content := string(data)
			title := strings.TrimSuffix(filename, ".md")
			category := ""
			tags := ""
			contentType := "text"

			if strings.HasPrefix(content, "---") {
				parts := strings.SplitN(content, "---", 3)
				if len(parts) >= 3 {
					meta := parts[1]
					content = strings.TrimSpace(parts[2])
					for _, line := range strings.Split(meta, "\n") {
						if strings.HasPrefix(line, "title:") {
							title = strings.TrimSpace(strings.TrimPrefix(line, "title:"))
						} else if strings.HasPrefix(line, "category:") {
							category = strings.TrimSpace(strings.TrimPrefix(line, "category:"))
						} else if strings.HasPrefix(line, "tags:") {
							tags = strings.TrimSpace(strings.TrimPrefix(line, "tags:"))
							tags = strings.ReplaceAll(tags, ", ", ",")
						} else if strings.HasPrefix(line, "content_type:") {
							contentType = strings.TrimSpace(strings.TrimPrefix(line, "content_type:"))
						}
					}
				}
			}

			now := nowStr()
			app.db.Exec(`INSERT INTO posts (title, content, content_type, category, tags, is_draft, source, author, created_at, updated_at) 
				VALUES (?, ?, ?, ?, ?, 0, 'import', ?, ?, ?)`, clampString(title, 120), content, clampString(contentType, 16), clampString(category, 64), tags, username, now, now)
			imported++
		}
	}

	jsonResponse(w, map[string]int{"imported": imported})
}

// ==================== 消息广场 ====================

func (app *App) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	rows, _ := app.db.Query("SELECT id, content, username, file_url, file_type, file_name, created_at FROM messages ORDER BY created_at DESC LIMIT 100")
	defer rows.Close()

	messages := []Message{}
	for rows.Next() {
		var m Message
		var fileURL, fileType, fileName sql.NullString
		rows.Scan(&m.ID, &m.Content, &m.Username, &fileURL, &fileType, &fileName, &m.CreatedAt)
		m.FileURL = fileURL.String
		m.FileType = fileType.String
		m.FileName = fileName.String
		messages = append(messages, m)
	}
	jsonResponse(w, messages)
}

func (app *App) handleCreateMessage(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	var content, fileURL, fileType, fileName string

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		// 单次请求体上限：与 settings 一致，且至少 150MB（避免错误工作目录导致 settings 未加载仍能传大文件）
		bodyLimit := app.maxUploadBytes() + 1024
		if bodyLimit < 150*1024*1024 {
			bodyLimit = 150 * 1024 * 1024
		}
		r.Body = http.MaxBytesReader(nil, r.Body, bodyLimit)
		r.ParseMultipartForm(32 << 20) // 32MB 内存，其余落盘，总大小由 MaxBytesReader 限制
		content = strings.TrimSpace(r.FormValue("content"))

		file, header, err := r.FormFile("file")
		if err == nil {
			defer file.Close()
			fileName = sanitizeFilenameForDownload(header.Filename)
			fileType = getFileType(fileName)
			ext := strings.ToLower(filepath.Ext(fileName))
			safeName := fmt.Sprintf("msg_%d_%s%s", time.Now().UnixNano(), generateToken()[:8], ext)
			dst, err := os.Create(filepath.Join(app.workDir, "uploads", safeName))
			if err == nil {
				io.Copy(dst, file)
				dst.Close()
				fileURL = safeName
			}
		}
	} else {
		var req struct {
			Content  string `json:"content"`
			FileURL  string `json:"file_url"`
			FileType string `json:"file_type"`
			FileName string `json:"file_name"`
		}
		app.decodeJSONLoose(r, &req, 64*1024)
		content = strings.TrimSpace(req.Content)
		// 支持分块上传后传入文件信息
		if req.FileURL != "" && validFileID(strings.TrimSuffix(filepath.Base(req.FileURL), filepath.Ext(req.FileURL))) {
			fileURL = filepath.Base(req.FileURL) // 只取文件名，防止路径遍历
			fileType = req.FileType
			fileName = sanitizeFilenameForDownload(req.FileName)
			if fileType == "" {
				fileType = getFileType(fileName)
			}
		}
	}

	if content == "" && fileURL == "" {
		jsonError(w, "内容不能为空", http.StatusBadRequest)
		return
	}
	if len([]rune(content)) > 500 {
		content = string([]rune(content)[:500])
	}

	now := nowStr()
	result, err := app.db.Exec("INSERT INTO messages (content, username, file_url, file_type, file_name, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		content, username, fileURL, fileType, fileName, now)
	if err != nil {
		jsonError(w, "发送失败", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	msg := Message{ID: id, Content: content, Username: username, FileURL: fileURL, FileType: fileType, FileName: fileName, CreatedAt: now}

	app.broadcastToAll(map[string]interface{}{"type": "new_message", "data": msg})
	jsonResponse(w, msg)
}

func (app *App) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/messages/")

	var msgUsername string
	err := app.db.QueryRow("SELECT username FROM messages WHERE id = ?", id).Scan(&msgUsername)
	if err != nil {
		jsonError(w, "消息不存在", http.StatusNotFound)
		return
	}

	// 仅允许删除自己的消息；管理员（通过 session）可删任意消息
	sess := app.getSession(r)
	if sess != nil && sess.IsAdmin {
		// 网页端管理员
	} else if msgUsername != username {
		jsonError(w, "无权限", http.StatusForbidden)
		return
	}

	app.db.Exec("DELETE FROM messages WHERE id = ?", id)
	app.broadcastToAll(map[string]interface{}{"type": "message_deleted", "data": map[string]string{"id": id}})
	jsonResponse(w, map[string]string{"message": "已删除"})
}

// ==================== SingleFile HTML 导入 ====================

var base64ImgRegex = regexp.MustCompile(`src="data:image/([^;]+);base64,([^"]+)"`)

func (app *App) handleImportHTML(w http.ResponseWriter, r *http.Request) {
	username, _ := app.requireAuth(w, r)
	if username == "" {
		return
	}

	r.Body = http.MaxBytesReader(nil, r.Body, 50*1024*1024)

	mr, err := r.MultipartReader()
	if err != nil {
		jsonError(w, "上传失败", http.StatusBadRequest)
		return
	}

	var htmlData []byte
	var category string
	var tagsStr string

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		switch part.FormName() {
		case "file":
			htmlData, _ = io.ReadAll(part)
		case "category":
			b, _ := io.ReadAll(part)
			category = clampString(string(b), 64)
		case "tags":
			b, _ := io.ReadAll(part)
			tagsStr = string(b)
		}
		part.Close()
	}

	if len(htmlData) == 0 {
		jsonError(w, "未上传文件", http.StatusBadRequest)
		return
	}

	html := string(htmlData)

	// 提取 title
	title := "导入的网页"
	if idx := strings.Index(html, "<title>"); idx >= 0 {
		end := strings.Index(html[idx:], "</title>")
		if end > 7 {
			title = clampString(html[idx+7:idx+end], 120)
		}
	}

	// 提取 body 内容
	content := html
	if idx := strings.Index(strings.ToLower(html), "<body"); idx >= 0 {
		bodyStart := strings.Index(html[idx:], ">")
		if bodyStart >= 0 {
			bodyStart = idx + bodyStart + 1
			bodyEnd := strings.Index(strings.ToLower(html[bodyStart:]), "</body>")
			if bodyEnd >= 0 {
				content = html[bodyStart : bodyStart+bodyEnd]
			} else {
				content = html[bodyStart:]
			}
		}
	}

	// 处理 base64 图片
	content = base64ImgRegex.ReplaceAllStringFunc(content, func(match string) string {
		matches := base64ImgRegex.FindStringSubmatch(match)
		if len(matches) < 3 {
			return match
		}
		imgType := matches[1]
		b64Data := matches[2]

		imgData, err := base64.StdEncoding.DecodeString(b64Data)
		if err != nil || len(imgData) > 10*1024*1024 {
			return match
		}

		ext := "." + imgType
		if imgType == "jpeg" {
			ext = ".jpg"
		}
		safeName := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), generateToken()[:8], ext)
		savePath := filepath.Join(app.workDir, "uploads", safeName)

		if err := os.WriteFile(savePath, imgData, 0644); err != nil {
			return match
		}
		return fmt.Sprintf(`src="/api/file/%s"`, safeName)
	})

	// 处理外部URL图片 (src 和 data-src)
	extImgRegex := regexp.MustCompile(`<img[^>]+(data-src|src)=["'](https?://[^"']+)["']`)
	content = extImgRegex.ReplaceAllStringFunc(content, func(match string) string {
		matches := extImgRegex.FindStringSubmatch(match)
		if len(matches) < 3 {
			return match
		}
		imgURL := matches[2]

		req, _ := http.NewRequest("GET", imgURL, nil)
		req.Header.Set("Referer", "https://mp.weixin.qq.com/")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			return match
		}
		defer resp.Body.Close()

		imgData, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
		if err != nil || len(imgData) == 0 {
			return match
		}

		ext := ".jpg"
		ct := resp.Header.Get("Content-Type")
		if strings.Contains(ct, "png") {
			ext = ".png"
		} else if strings.Contains(ct, "gif") {
			ext = ".gif"
		} else if strings.Contains(ct, "webp") {
			ext = ".webp"
		}

		safeName := fmt.Sprintf("%d_%s%s", time.Now().UnixNano(), generateToken()[:8], ext)
		if err := os.WriteFile(filepath.Join(app.workDir, "uploads", safeName), imgData, 0644); err != nil {
			return match
		}

		newSrc := fmt.Sprintf(`src="/api/file/%s"`, safeName)
		result := regexp.MustCompile(`(data-src|src)=["'][^"']+["']`).ReplaceAllString(match, newSrc)
		return result
	})

	// 处理标签
	tags := []string{}
	if tagsStr != "" {
		for _, t := range strings.Split(tagsStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}
	}
	tags = sanitizeTags(tags)

	now := nowStr()
	result, err := app.db.Exec(`INSERT INTO posts (title, content, content_type, category, tags, is_draft, source, author, created_at, updated_at) 
		VALUES (?, ?, 'html', ?, ?, 0, 'import', ?, ?, ?)`,
		title, content, category, strings.Join(tags, ","), username, now, now)
	if err != nil {
		jsonError(w, "保存失败", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()

	// 不再创建附件记录，删除了那段代码

	post := Post{
		ID:          id,
		Title:       title,
		ContentType: "html",
		Category:    category,
		Tags:        tags,
		Source:      "import",
		Author:      username,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	app.broadcastToUser(username, map[string]interface{}{"type": "post_created", "data": post})
	jsonResponse(w, post)
}

// ==================== 管理接口 ====================

func (app *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if app.requireAdmin(w, r) == nil {
		return
	}
	jsonResponse(w, app.settings)
}

func (app *App) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if app.requireAdmin(w, r) == nil {
		return
	}

	var req Settings
	if app.decodeJSONLoose(r, &req, 128*1024) != nil {
		jsonError(w, "无效请求", http.StatusBadRequest)
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		req.Port = 5000
	}
	if req.MaxUploadMB < 1 {
		req.MaxUploadMB = 100
	}
	if req.MaxUploadMB > 2048 {
		req.MaxUploadMB = 2048
	}

	oldPort := app.settings.Port
	app.settings = req
	app.saveSettings()

	if req.Port != oldPort {
		jsonResponse(w, map[string]interface{}{"message": "设置已保存，正在重启...", "restarting": true, "new_port": req.Port})
		go func() {
			time.Sleep(500 * time.Millisecond)
			restartChan <- req.Port
		}()
		return
	}

	jsonResponse(w, map[string]interface{}{"message": "设置已保存", "restarting": false})
}

func (app *App) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	if app.requireAdmin(w, r) == nil {
		return
	}

	rows, _ := app.db.Query("SELECT username, is_admin FROM users")
	defer rows.Close()

	users := []map[string]interface{}{}
	for rows.Next() {
		var username string
		var isAdmin bool
		_ = rows.Scan(&username, &isAdmin)
		users = append(users, map[string]interface{}{"username": username, "is_admin": isAdmin})
	}
	jsonResponse(w, users)
}

func (app *App) handleAddUser(w http.ResponseWriter, r *http.Request) {
	if app.requireAdmin(w, r) == nil {
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if app.decodeJSONLoose(r, &req, 128*1024) != nil {
		jsonError(w, "无效请求", http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 2 || len(req.Password) < 4 {
		jsonError(w, "用户名至少2位，密码至少4位", http.StatusBadRequest)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	_, err := app.db.Exec("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", req.Username, string(hash), req.IsAdmin)
	if err != nil {
		jsonError(w, "用户名已存在", http.StatusConflict)
		return
	}
	jsonResponse(w, map[string]string{"message": "用户已添加"})
}

func (app *App) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	sess := app.requireAdmin(w, r)
	if sess == nil {
		return
	}

	username := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	username = strings.TrimSpace(username)
	if username == sess.Username {
		jsonError(w, "不能删除自己", http.StatusBadRequest)
		return
	}

	result, _ := app.db.Exec("DELETE FROM users WHERE username = ?", username)
	affected, _ := result.RowsAffected()
	if affected == 0 {
		jsonError(w, "用户不存在", http.StatusNotFound)
		return
	}

	rows, _ := app.db.Query("SELECT filename FROM attachments WHERE post_id IN (SELECT id FROM posts WHERE author = ?)", username)
	for rows.Next() {
		var filename string
		_ = rows.Scan(&filename)
		_ = os.Remove(filepath.Join(app.workDir, "uploads", filename))
	}
	rows.Close()

	app.db.Exec("DELETE FROM attachments WHERE post_id IN (SELECT id FROM posts WHERE author = ?)", username)
	app.db.Exec("DELETE FROM posts WHERE author = ?", username)
	app.db.Exec("DELETE FROM categories WHERE username = ?", username)
	app.db.Exec("DELETE FROM tags WHERE username = ?", username)
	app.db.Exec("DELETE FROM api_tokens WHERE username = ?", username)
	app.db.Exec("DELETE FROM messages WHERE username = ?", username)

	jsonResponse(w, map[string]string{"message": "用户已删除"})
}

func (app *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")

	// 允许 APP（Capacitor/跨域）调用 API
	if strings.HasPrefix(path, "/api/") {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Token")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	if path == "/ws" {
		app.handleWS(w, r)
		return
	}

	if strings.HasPrefix(path, "/api/") {
		switch {
		case path == "/api/register" && r.Method == "POST":
			app.handleRegister(w, r)
		case path == "/api/login" && r.Method == "POST":
			app.handleLogin(w, r)
		case path == "/api/logout" && r.Method == "POST":
			app.handleLogout(w, r)
		case path == "/api/session" && r.Method == "GET":
			app.handleSession(w, r)
		case path == "/api/posts" && r.Method == "GET":
			app.handleGetPosts(w, r)
		case path == "/api/posts" && r.Method == "POST":
			app.handleCreatePost(w, r)
		case strings.HasPrefix(path, "/api/posts/restore/") && r.Method == "POST":
			app.handleRestorePost(w, r)
		case strings.HasPrefix(path, "/api/posts/") && r.Method == "GET":
			app.handleGetPost(w, r)
		case strings.HasPrefix(path, "/api/posts/") && r.Method == "PUT":
			app.handleUpdatePost(w, r)
		case strings.HasPrefix(path, "/api/posts/") && r.Method == "DELETE":
			app.handleDeletePost(w, r)
		case path == "/api/posts/batch" && r.Method == "POST":
			app.handleBatchOperation(w, r)
		case path == "/api/upload" && r.Method == "POST":
			app.handleUpload(w, r)
		case path == "/api/upload/chunk" && r.Method == "POST":
			app.handleUploadChunk(w, r)
		case path == "/api/upload/merge" && r.Method == "POST":
			app.handleUploadMerge(w, r)
		case strings.HasPrefix(path, "/api/attachments/") && r.Method == "GET":
			app.handleGetAttachments(w, r)
		case strings.HasPrefix(path, "/api/attachments/") && r.Method == "DELETE":
			app.handleDeleteAttachment(w, r)
		case strings.HasPrefix(path, "/api/file/"):
			app.handleFile(w, r)
		case path == "/api/categories" && r.Method == "GET":
			app.handleGetCategories(w, r)
		case path == "/api/categories" && r.Method == "POST":
			app.handleCreateCategory(w, r)
		case strings.HasPrefix(path, "/api/categories/") && r.Method == "PUT":
			app.handleUpdateCategory(w, r)
		case strings.HasPrefix(path, "/api/categories/") && r.Method == "DELETE":
			app.handleDeleteCategory(w, r)
		case path == "/api/tags" && r.Method == "GET":
			app.handleGetTags(w, r)
		case path == "/api/tags" && r.Method == "POST":
			app.handleCreateTag(w, r)
		case strings.HasPrefix(path, "/api/tags/") && r.Method == "DELETE":
			app.handleDeleteTag(w, r)
		case path == "/api/tokens" && r.Method == "GET":
			app.handleGetTokens(w, r)
		case path == "/api/tokens" && r.Method == "POST":
			app.handleCreateToken(w, r)
		case strings.HasPrefix(path, "/api/tokens/") && r.Method == "DELETE":
			app.handleDeleteToken(w, r)
		case path == "/api/export" && r.Method == "GET":
			app.handleExport(w, r)
		case path == "/api/import" && r.Method == "POST":
			app.handleImport(w, r)
		case path == "/api/import/html" && r.Method == "POST":
			app.handleImportHTML(w, r)
		case path == "/api/messages" && r.Method == "GET":
			app.handleGetMessages(w, r)
		case path == "/api/messages" && r.Method == "POST":
			app.handleCreateMessage(w, r)
		case strings.HasPrefix(path, "/api/messages/") && r.Method == "DELETE":
			app.handleDeleteMessage(w, r)
		case path == "/api/admin/settings" && r.Method == "GET":
			app.handleGetSettings(w, r)
		case path == "/api/admin/settings" && r.Method == "POST":
			app.handleSaveSettings(w, r)
		case path == "/api/admin/users" && r.Method == "GET":
			app.handleGetUsers(w, r)
		case path == "/api/admin/users" && r.Method == "POST":
			app.handleAddUser(w, r)
		case strings.HasPrefix(path, "/api/admin/users/") && r.Method == "DELETE":
			app.handleDeleteUser(w, r)
		default:
			jsonError(w, "接口不存在", http.StatusNotFound)
		}
		return
	}

	if path == "/" {
		path = "/index.html"
	}
	filePath := filepath.Join(app.workDir, path)
	if _, err := os.Stat(filePath); err == nil {
		http.ServeFile(w, r, filePath)
		return
	}
	http.ServeFile(w, r, filepath.Join(app.workDir, "index.html"))
}

func main() {
	flag.StringVar(&workDirFlag, "dir", "", "工作目录")
	flag.IntVar(&portFlag, "port", 0, "端口号")
	flag.Parse()

	if workDirFlag == "" {
		execPath, _ := os.Executable()
		workDirFlag = filepath.Dir(execPath)
	}
	_ = os.Chdir(workDirFlag)

	app = NewApp(workDirFlag)

	port := portFlag
	if port == 0 {
		port = app.settings.Port
	}
	if port == 0 {
		port = 5000
	}

	execPath, _ := os.Executable()

	for {
		app.server = &http.Server{
			Addr:    ":" + strconv.Itoa(port),
			Handler: app,
		}

		log.Printf("服务器启动: http://localhost:%d", port)

		go func() {
			if err := app.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("服务器错误: %v", err)
			}
		}()

		newPort := <-restartChan
		log.Printf("收到重启信号，新端口: %d", newPort)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = app.server.Shutdown(ctx)
		cancel()

		if runtime.GOOS == "windows" {
			cmd := exec.Command(execPath, "-dir", workDirFlag, "-port", strconv.Itoa(newPort))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			_ = cmd.Start()
			os.Exit(0)
		} else {
			port = newPort
		}
	}
}
