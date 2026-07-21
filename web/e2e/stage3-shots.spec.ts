import { test } from '@playwright/test'
import { loginViaAPI } from './helpers'

const SECADMIN = process.env.E2E_SECADMIN_USER || 'sec_admin_s3'
const SECADMIN_PWD = process.env.E2E_SECADMIN_PWD || 'SecAdmin@S3!2026'

test('阶段3页面截图', async ({ page }) => {
  await loginViaAPI(page, SECADMIN, SECADMIN_PWD)

  await page.goto('/applications')
  await page.getByText('waf-test').waitFor({ timeout: 10000 })
  await page.screenshot({ path: 'test-results/shots/01-applications.png', fullPage: true })

  await page.getByText('WAF测试应用').click()
  await page.getByText('waf-test.local').waitFor({ timeout: 10000 })
  await page.screenshot({ path: 'test-results/shots/02-app-detail-domains.png', fullPage: true })

  await page.getByRole('tab', { name: /源站管理/ }).click()
  await page.getByText('http://testorigin:8081').waitFor()
  await page.screenshot({ path: 'test-results/shots/03-app-detail-upstreams.png', fullPage: true })

  await page.goto('/config-publish')
  await page.getByText('当前生效版本').waitFor()
  await page.getByRole('button', { name: '预览配置' }).click()
  await page.getByText('业务摘要').waitFor({ timeout: 10000 })
  await page.screenshot({ path: 'test-results/shots/04-config-publish-preview.png', fullPage: true })
  await page.keyboard.press('Escape')

  await page.goto('/config-versions')
  await page.getByText(/^V\d{8}\./).first().waitFor({ timeout: 10000 })
  await page.screenshot({ path: 'test-results/shots/05-config-versions.png', fullPage: true })

  await page.goto('/gateway-status')
  await page.getByText('在线', { exact: true }).waitFor({ timeout: 10000 })
  await page.screenshot({ path: 'test-results/shots/06-gateway-status.png', fullPage: true })
})
