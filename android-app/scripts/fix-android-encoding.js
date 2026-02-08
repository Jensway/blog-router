/**
 * 修复 Android 构建在 CI（如 GitHub Actions）下中文乱码：
 * 强制 Gradle/Java 使用 UTF-8 编码
 */
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = path.resolve(__dirname, '..')
const androidDir = path.join(root, 'android')
const gradlePropsPath = path.join(androidDir, 'gradle.properties')
const appBuildPath = path.join(androidDir, 'app', 'build.gradle')

if (!fs.existsSync(androidDir)) {
  console.log('android 目录不存在，跳过编码修复（请先执行 npx cap add android）')
  process.exit(0)
}

// 1. gradle.properties：强制 JVM 与 Gradle 使用 UTF-8
if (fs.existsSync(gradlePropsPath)) {
  let content = fs.readFileSync(gradlePropsPath, 'utf8')
  const need = [
    'systemProp.file.encoding=UTF-8',
    'org.gradle.jvmargs=-Dfile.encoding=UTF-8'
  ]
  for (const line of need) {
    if (!content.includes(line)) {
      content = content.trimEnd() + '\n' + line + '\n'
    }
  }
  fs.writeFileSync(gradlePropsPath, content)
  console.log('已写入 gradle.properties UTF-8 配置')
}

// 2. app/build.gradle 或 build.gradle.kts：Java 编译使用 UTF-8
const appBuildKts = path.join(androidDir, 'app', 'build.gradle.kts')
for (const buildFile of [appBuildPath, appBuildKts]) {
  if (!fs.existsSync(buildFile)) continue
  let content = fs.readFileSync(buildFile, 'utf8')
  if (content.includes('encoding') && content.includes('UTF-8')) continue
  const isKts = buildFile.endsWith('.kts')
  if (content.includes('compileOptions')) {
    if (isKts) {
      content = content.replace(
        /(compileOptions\s*\{)/,
        '$1\n        encoding = "UTF-8"'
      )
    } else {
      content = content.replace(
        /(compileOptions\s*\{)/,
        '$1\n        encoding "UTF-8"'
      )
    }
  } else {
    if (isKts) {
      content = content.replace(
        /(android\s*\{)/,
        '$1\n    compileOptions {\n        encoding = "UTF-8"\n    }'
      )
    } else {
      content = content.replace(
        /(android\s*\{)/,
        '$1\n    compileOptions {\n        encoding "UTF-8"\n    }'
      )
    }
  }
  fs.writeFileSync(buildFile, content)
  console.log('已写入 ' + path.basename(buildFile) + ' UTF-8 配置')
  break
}

// 3. 允许 HTTP 连接（Android 9+ 默认禁止明文，会导致 failed to fetch）
const manifestPath = path.join(androidDir, 'app', 'src', 'main', 'AndroidManifest.xml')
if (fs.existsSync(manifestPath)) {
  let manifest = fs.readFileSync(manifestPath, 'utf8')
  if (!manifest.includes('usesCleartextTraffic')) {
    manifest = manifest.replace(
      /<application\s/,
      '<application\n        android:usesCleartextTraffic="true"\n        '
    )
    fs.writeFileSync(manifestPath, manifest)
    console.log('已允许 Android 明文流量 (usesCleartextTraffic)')
  }
}

console.log('Android 编码修复完成')
