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
const resXmlDir = path.join(androidDir, 'app', 'src', 'main', 'res', 'xml')
const networkSecurityConfigPath = path.join(resXmlDir, 'network_security_config.xml')

if (fs.existsSync(manifestPath)) {
  // 3a. 添加 network_security_config.xml（Android 官方推荐方式）
  const networkSecurityConfig = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
`
  if (!fs.existsSync(resXmlDir)) fs.mkdirSync(resXmlDir, { recursive: true })
  fs.writeFileSync(networkSecurityConfigPath, networkSecurityConfig)
  console.log('已创建 network_security_config.xml（允许 HTTP）')

  // 3b. 在 AndroidManifest 的 application 上启用明文 + 引用上述配置
  let manifest = fs.readFileSync(manifestPath, 'utf8')
  const needCleartext = !manifest.includes('usesCleartextTraffic')
  const needNetworkConfig = !manifest.includes('networkSecurityConfig')
  if (needCleartext || needNetworkConfig) {
    const parts = []
    if (needCleartext) parts.push('android:usesCleartextTraffic="true"')
    if (needNetworkConfig) parts.push('android:networkSecurityConfig="@xml/network_security_config"')
    const toInsert = '\n        ' + parts.join('\n        ') + '\n        '
    manifest = manifest.replace(/<application\s/, '<application' + toInsert)
    fs.writeFileSync(manifestPath, manifest)
    console.log('已修改 AndroidManifest 允许明文流量')
  }
}

console.log('Android 编码修复完成')
