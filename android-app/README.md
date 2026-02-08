# 共享中心 手机端

基于后端 API 的移动端前端（Vue 3），**不装 Android Studio 也能用**。

---

## 推荐：直接用网页，不打包 APK

不用学 GitHub Actions，也不用装 Android Studio，手机当 App 用：

1. **在电脑上**把前端构建出来并让后端能访问到：
   ```bash
   cd android-app
   npm install
   npm run build
   ```
   然后把 `android-app/dist` 里的**全部文件**复制到**后端工作目录**（和后端的 `index.html` 同级的那个目录）。  
   若你希望手机用「单独的手机版入口」，可以把 `dist` 里的内容放到例如 `mobile` 子目录，然后让后端能访问 `/mobile/`（具体看你后端怎么配静态文件）。

2. **在手机上**用浏览器打开你的后端地址，例如：  
   `http://你的电脑IP:5000` 或 `http://你的域名:5000`  
   若你做了上面的 `mobile`，就打开 `http://.../mobile/`。

3. 在浏览器里点 **「添加到主屏幕」**（Chrome 菜单里就有），桌面会多一个图标，点开就像 App 一样用。

这样就不需要 APK、不需要 GitHub Actions、也不需要 Android Studio。

---

## 用 GitHub Actions 自动打 APK（不用装 Android Studio）

仓库里已配置好 **GitHub Actions**，推送到 GitHub 后会自动构建 APK。

1. **触发构建**  
   - 推送到 `main` 或 `master` 分支会自动跑一次；或  
   - 打开仓库 → 顶部 **Actions** → 左侧选「构建 APK」→ 右侧 **Run workflow** → 再点绿色的 **Run workflow**。

2. **下载 APK**  
   构建完成后：同页点进刚跑完的那次 **run** → 页面底部 **Artifacts** 里会有 **共享中心-debug.apk**，点一下即可下载。

3. **装到手机**  
   把下载的 APK 传到手机安装即可（需允许「未知来源」安装）。

---

## 可选：本机用 Android Studio 打 APK

本机已装 **Android Studio** 时，可以本地打包：

```bash
cd android-app
npm install
npx cap add android
npm run build
npx cap sync android
npx cap open android
```

在 Android Studio 里：**Build → Build APK(s)**，APK 在  
`android-app/android/app/build/outputs/apk/debug/app-debug.apk`。

---

## 功能说明

- **连接**：填服务器地址 + API 令牌（在网页版「设置 → API 令牌」里创建）。
- **我的日志**：列表、点进详情。
- **消息广场**：看消息、发文字。

后端需能被手机访问（同一 WiFi 用电脑 IP，或部署到公网后填对应地址）。
