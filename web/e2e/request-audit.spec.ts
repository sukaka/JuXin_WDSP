import { test, expect } from '@playwright/test'
import { loginViaAPI, API_URL } from './helpers'

const username = process.env.E2E_SEC_USER || ''
const password = process.env.E2E_SEC_PWD || ''
const traceID = '0123456789abcdef0123456789abcdef'

test('真实请求审计筛选、趋势和Trace详情', async ({ page }) => {
  test.skip(
    process.env.WDSP_REQUEST_AUDIT_E2E !== 'true' || !username || !password,
    '由 TestRequestAuditAccessLogsEndToEnd 提供真实环境和测试身份',
  )
  const pageErrors: string[] = []
  page.on('pageerror', (error) => pageErrors.push(error.message))

  await loginViaAPI(page, username, password)
  const response = await page.request.get(
    `${API_URL}/access-logs?request_id=req-audit-1`,
  )
  expect(response.status()).toBe(200)
  const result = await response.json()
  expect(result.data.total).toBe(1)
  expect(result.data.items[0].request_id).toBe('req-audit-1')

  await page.goto('/access-logs')
  await expect(page.locator('.ant-card-head')).toContainText('访问日志')
  const trend = page.getByRole('region', { name: '访问日志趋势' })
  await expect(trend).toBeVisible()
  await expect(trend.locator('div[role="img"][aria-label="当前筛选范围共2次请求，1次阻断，1次5xx。"]')).toBeVisible()
  await expect(trend.locator('canvas').first()).toBeVisible()

  const requestFilter = page.getByPlaceholder('请求 ID')
  await requestFilter.fill('req-audit-1')
  await requestFilter.press('Enter')
  await expect(page.getByText('/v1/login')).toBeVisible()
  await page.getByRole('button', { name: /详\s*情/ }).click()
  const drawer = page.getByRole('dialog')
  await expect(drawer.getByText(traceID)).toBeVisible()
  await expect(drawer.getByText('42 ms')).toBeVisible()
  await expect(drawer.getByText('POST /v1/login')).toBeVisible()
  await expect(drawer.getByText('pwd=masked')).toBeVisible()
  await expect(drawer).not.toContainText('body_base64')
  expect(pageErrors).toEqual([])
})
