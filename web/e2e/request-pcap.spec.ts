import { test, expect } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { loginViaAPI, API_URL } from './helpers'

const username = process.env.E2E_SEC_USER || ''
const password = process.env.E2E_SEC_PWD || ''
const requestID = 'req-pcap-e2e'

test('真实PCAP核验下载与审计流向下钻', async ({ page }) => {
  test.skip(process.env.WDSP_REQUEST_AUDIT_E2E !== 'true' || !username || !password, '由真实完整栈提供签名证据和测试身份')
  const pageErrors: string[] = []
  page.on('pageerror', (error) => pageErrors.push(error.message))
  await page.setExtraHTTPHeaders({ 'X-Forwarded-For': '192.0.2.50' })
  await loginViaAPI(page, username, password)
  const lookup = await page.request.get(`${API_URL}/request-pcap/lookup?request_id=${requestID}`)
  expect(lookup.status()).toBe(200)
  const lookupBody = await lookup.json()
  expect(lookupBody.data.items).toHaveLength(1)
  const artifactID = lookupBody.data.items[0].artifact_id as string

  await page.goto('/access-logs')
  const requestFilter = page.getByPlaceholder('请求 ID')
  await requestFilter.fill(requestID)
  await requestFilter.press('Enter')
  await page.getByRole('button', { name: /详\s*情/ }).click()
  const drawer = page.getByRole('dialog')
  const evidence = drawer.getByRole('region', { name: 'PCAP 证据' })
  await expect(evidence.getByText('GATEWAY_EGRESS')).toBeVisible()
  await expect(evidence.getByText('连接级证据')).toBeVisible()
  await evidence.getByRole('button', { name: '完整性核验' }).click()
  const verifyDialog = page.getByRole('dialog', { name: '核验 PCAP 证据' })
  await verifyDialog.getByLabel('核验理由').fill('真实浏览器完整性核验')
  await verifyDialog.getByRole('button', { name: '开始核验' }).click()
  await expect(evidence.getByText('完整性通过')).toBeVisible()

  await evidence.getByRole('button', { name: '申请派生下载' }).click()
  const grantDialog = page.getByRole('dialog', { name: '确认派生下载' })
  await grantDialog.getByLabel('下载理由').fill('真实浏览器取证下载')
  await grantDialog.getByLabel('当前账号密码').fill(password)
  const grantResponsePromise = page.waitForResponse((response) => response.url().includes('/download-grants') && response.status() === 201)
  const downloadPromise = page.waitForEvent('download')
  await grantDialog.getByRole('button', { name: '授权并下载' }).click()
  const grantResponse = await grantResponsePromise
  const grantBody = await grantResponse.json()
  const download = await downloadPromise
  expect(download.suggestedFilename()).toBe(`request-${artifactID}.pcap`)
  const downloadPath = await download.path()
  expect(downloadPath).not.toBeNull()
  const content = await readFile(downloadPath as string)
  expect(content).toHaveLength(104)
  expect(content[0]).toBe(0xd4)
  expect(content[1]).toBe(0xc3)
  const replay = await page.request.get(`${API_URL}/request-pcap/artifacts/${artifactID}/download?request_id=${requestID}&grant_id=${grantBody.data.grant_id}`)
  expect(replay.status()).toBe(403)

  await drawer.locator('.ant-drawer-close').click()
  await page.getByText('审计流向', { exact: true }).click()
  const flow = page.getByRole('region', { name: '审计流向图' })
  await expect(flow.locator('canvas').first()).toBeVisible()
  await expect(flow.getByText('去重请求 1')).toBeVisible()
  await flow.locator('summary').click()
  const drillResponse = page.waitForResponse((response) => response.url().includes('/access-logs?') && response.url().includes('request_ids=req-pcap-e2e'))
  await flow.getByRole('button', { name: '请求敏感字段 / form.pwd · credential' }).click()
  expect((await drillResponse).status()).toBe(200)
  await expect(page.getByText('/v1/pcap')).toBeVisible()
  expect(pageErrors).toEqual([])
})
