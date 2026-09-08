import { defineConfig, devices } from '@playwright/test'

/**
 * P1-02 B4 Bot 挑战浏览器/自动化基准 Playwright 配置（BOT-004 / BOT-021）。
 * 目标不是管理前端，而是真实网关上的 HTTPS 测试应用（stage5 栈，由 run.sh 准备）：
 *   - baseURL 为 https://bot-bench.local（自签证书，ignoreHTTPSErrors）；
 *   - --host-resolver-rules 把测试域名固定解析到本机栈，不改 /etc/hosts；
 *   - 三组用例用 @browser / @automation-js tag 分组，run.sh 分组运行并分别如实报告。
 */
const SITE_URL = process.env.BOT_BENCH_SITE_URL || 'https://bot-bench.local'
const SITE_HOST = process.env.BOT_BENCH_SITE_HOST || 'bot-bench.local'

export default defineConfig({
  testDir: './specs',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [['list']],
  timeout: 120000,
  use: {
    baseURL: SITE_URL,
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    launchOptions: {
      args: [`--host-resolver-rules=MAP ${SITE_HOST} 127.0.0.1`],
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
