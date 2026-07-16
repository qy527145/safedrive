import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // 开发模式下将 API 代理到 Rust 后端（cargo run 默认端口）
      '/api': 'http://127.0.0.1:5266',
    },
  },
  build: {
    outDir: 'dist',
    // WebCrypto / Web Streams / SW 都需要现代浏览器
    target: 'es2022',
  },
  test: {
    environment: 'node',
    // src/ 下为单测；e2e/ 为集成 E2E（默认自跳过，bun run test:e2e 触发）
    include: ['src/**/*.test.ts', 'e2e/**/*.test.ts'],
  },
});
