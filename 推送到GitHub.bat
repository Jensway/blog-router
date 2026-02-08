@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo 正在设置 Git 安全目录...
git config --global --add safe.directory "*"

echo.
echo 设置本仓库 Git 用户（用于首次提交，可之后在 GitHub 里改）...
git config user.email "Jensway@users.noreply.github.com"
git config user.name "Jensway"

echo.
echo 正在添加文件...
git add .

echo.
echo 正在提交（首次提交）...
git commit -m "首次提交"
if errorlevel 1 (
    echo.
    echo [提示] 提交未成功。若上面显示 "nothing to commit"，说明之前已提交过，直接推送即可。
    echo        若显示 "Author identity unknown"，请重新运行本脚本（已自动配置用户信息）。
    echo.
    git status
    echo.
)

echo.
echo 设置主分支为 main...
git branch -M main

echo.
echo 设置远程仓库...
git remote remove origin 2>nul
git remote add origin https://github.com/Jensway/blog-router.git

echo.
echo 正在推送到 GitHub...
git push -u origin main
if errorlevel 1 (
    echo.
    echo [失败] 若上面是 "main does not match any"，说明还没有任何提交。
    echo        请查看上方是否有 "提交成功" 或 "nothing to commit"。
    echo        若本次运行里 commit 成功了，请再双击运行本脚本一次（第二次会直接推送）。
)

echo.
pause
