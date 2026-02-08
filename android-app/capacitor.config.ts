import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.sharecenter.app',
  appName: '共享中心',
  webDir: 'dist',
  server: {
    androidScheme: 'https',
  },
};

export default config;
