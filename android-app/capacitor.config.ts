import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.sharecenter.app',
  appName: '共享中心',
  webDir: 'dist',
  server: {
    // 用 http 避免 WebView 把页面当「安全来源」从而拦截对 http:// 服务器的请求（混合内容）
    androidScheme: 'http',
  },
};

export default config;
