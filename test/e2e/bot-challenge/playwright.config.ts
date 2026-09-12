import { defineConfig, devices } from '@playwright/test'

/**
 * P1-02 B4 Bot 挑战浏览器/自动化基准 Playwright 配置（BOT-004 / BOT-006 / BOT-021）。
 * 目标不是管理前端，而是真实网关上的 HTTPS 测试应用（stage5 栈，由 run.sh /
 * run-browsers.sh 准备）：
 *   - baseURL 为 https://bot-bench.local（自签证书，ignoreHTTPSErrors）；
 *   - Chromium 通道用 --host-resolver-rules 把测试域名固定解析到本机栈（该参数为
 *     Chromium 专有，Firefox/WebKit 不支持），不改 /etc/hosts；
 *   - 非 Chromium 通道走第二域名 bot-bench.localhost（RFC 6761 localhost 域，macOS
 *     系统解析器实测原生解析 127.0.0.1，无需任何浏览器专有参数）；挑战/通行按
 *     Host 绑定，各通道 Host 自洽，链路真实不经改写；
 *   - 三组用例用 @browser / @automation-js / @a11y tag 分组，由驱动脚本分组运行
 *     并分别如实报告。
 */
const SITE_URL = process.env.BOT_BENCH_SITE_URL || 'https://bot-bench.local'
const SITE_HOST = process.env.BOT_BENCH_SITE_HOST || 'bot-bench.local'
// 默认可解析域名（非 Chromium 通道）：基准应用登记的第二域名
const SITE_URL_NATIVE = process.env.BOT_BENCH_SITE_URL_NATIVE || 'https://bot-bench.localhost'

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
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: [`--host-resolver-rules=MAP ${SITE_HOST} 127.0.0.1`],
        },
      },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'], baseURL: SITE_URL_NATIVE },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'], baseURL: SITE_URL_NATIVE },
    },
    {
      name: 'mobile-safari',
      use: { ...devices['iPhone 14'], baseURL: SITE_URL_NATIVE },
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 7'], baseURL: SITE_URL_NATIVE },
    },
  ],
})
