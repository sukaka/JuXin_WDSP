import { defineConfig, devices } from '@playwright/test'

/**
 * P1-04 R4a 安全回归管理界面 E2E（真实 stage5 栈 + vite dev 控制台，由 run.sh 准备）。
 * 目标是管理前端真实页面：baseURL 为 vite dev（/api/v1 代理到本轮栈 api），
 * 登录走真实登录页（验证码答案从 Valkey 读取，与 web/e2e 既有惯例一致）。
 */
const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5173'

export default defineConfig({
  testDir: './specs',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [['list']],
  timeout: 180000,
  use: {
    baseURL: BASE_URL,
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
