# 把当前项目推送到 GitHub

按下面顺序做即可。

---

## 一、在 GitHub 上新建仓库

1. 打开 https://github.com ，登录你的账号。
2. 右上角点 **+** → **New repository**。
3. **Repository name** 随便起一个，例如：`blog-router` 或 `share-center`。
4. 选 **Public**，下面的 **Add a README** 等都不用勾选（本地已有代码）。
5. 点 **Create repository**。
6. 创建好后会看到一个地址，例如：`https://github.com/你的用户名/blog-router.git`，先记着。

---

## 二、在电脑上打开终端（在项目目录里）

在 VS Code / Cursor 里：**终端 → 新建终端**，或按 `` Ctrl+` ``。

确保当前目录是项目根目录（能看到 `go.mod`、`android-app` 等），如果不是，先执行：

```bash
cd y:\共享中心APP\blog-router
```

（路径按你实际的项目路径改。）

---

## 三、初始化 Git 并推送

在终端里**一条一条**执行（把 `https://github.com/你的用户名/仓库名.git` 换成你刚创建的仓库地址）：

```bash
git init
git add .
git commit -m "首次提交"
git branch -M main
git remote add origin https://github.com/你的用户名/仓库名.git
git push -u origin main
```

- 第一次 `git push` 可能会让你登录 GitHub：  
  - 浏览器弹出登录就按提示登录；  
  - 或使用 **Personal Access Token** 当密码（在 GitHub → Settings → Developer settings → Personal access tokens 里生成）。
- 如果 GitHub 上创建仓库时勾选了 “Add a README”，可能要先执行一次：  
  `git pull origin main --rebase`  
  再执行：  
  `git push -u origin main`

---

## 四、推送成功后

- 打开你的 GitHub 仓库页面，代码已经在了。
- 等一会儿或去 **Actions** 里看「构建 APK」是否在跑；跑完后在 **Artifacts** 里下载 **共享中心-debug.apk**。

以后改完代码想再推送、再打 APK，执行：

```bash
git add .
git commit -m "改了什么简单写一句"
git push
```

即可。
