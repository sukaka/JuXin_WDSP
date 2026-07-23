import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { loadEnv } from 'vite'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        // 仅代理 /api/v1（不能写 '/api'：会与阶段8 页面路由 /api-endpoints 等冲突，
        // 导致整页刷新被代理到后端返回 404）
        '/api/v1': {
          target: env.VITE_API_PROXY || 'http://localhost:18081',
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
  }
})
