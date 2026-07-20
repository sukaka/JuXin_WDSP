import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:18081',
        // 保持原始 Host（localhost:5173），使 CSRF Origin 校验通过（与生产同域部署一致）
        changeOrigin: false,
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/setupTests.ts',
    globals: true,
    // 排除 Playwright E2E 用例（由 npx playwright test 单独运行）
    exclude: ['**/node_modules/**', '**/dist/**', 'e2e/**'],
  },
})
