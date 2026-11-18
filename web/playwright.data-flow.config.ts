import { defineConfig, devices } from '@playwright/test'

const port = Number(process.env.WDSP_DATA_FLOW_FRONTEND_PORT || 5185)
const baseURL = `http://127.0.0.1:${port}`

export default defineConfig({
  testDir: './e2e',
  testMatch: ['api-data-flow.spec.ts', 'request-audit.spec.ts', 'request-pcap.spec.ts'],
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  workers: 1,
  reporter: 'list',
  timeout: 90000,
  expect: { timeout: 30000 },
  outputDir: process.env.WDSP_DATA_FLOW_TEST_OUTPUT || 'test-results/api-data-flow',
  use: {
    baseURL,
    ...devices['Desktop Chrome'],
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: `npm run dev -- --host 127.0.0.1 --port ${port}`,
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120000,
  },
})
