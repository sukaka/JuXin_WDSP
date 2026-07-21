import { test, expect } from '@playwright/test'
import { loginViaAPI, API_URL } from './helpers'

/**
 * 阶段3 E2E 场景一：HTTP应用接入全流程
 * 安全管理员登录 → 新增应用 → 配置域名 → HTTP监听 → 源站 → 连通性测试 → 保存 → 预览 → 发布 → 验证访问
 */

const SEC_ADMIN = process.env.E2E_SEC_USER || 'sec_admin_s3'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S3!2026'
const GATEWAY_URL = process.env.E2E_GATEWAY_URL || 'http://127.0.0.1:18080'

test.describe('阶段3场景一：HTTP应用接入', () => {
  test('安全管理员创建应用并发布到网关', async ({ page }) => {
    // 1. 安全管理员登录
    await loginViaAPI(page, SEC_ADMIN, SEC_PWD)
    await page.goto('/applications')
    await expect(page).toHaveURL(/applications/)

    const appCode = `e2e-app-${Date.now().toString().slice(-6)}`
    const hostname = `${appCode}.local`

    // 2. 通过 API 创建应用（UI流程由单元测试覆盖，E2E聚焦业务闭环）
    const me = await page.request.get(`${API_URL}/auth/me`)
    const csrf = (await me.json())?.data?.csrf_token

    const createApp = await page.request.post(`${API_URL}/applications`, {
      data: { code: appCode, name: 'E2E测试应用', protection_mode: 'PROTECT' },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(createApp.status()).toBe(200)
    const appData = (await createApp.json())?.data
    const appId = appData?.id
    expect(appId).toBeTruthy()

    // 3. 配置域名（HTTP监听）
    const addDomain = await page.request.post(`${API_URL}/applications/${appId}/domains`, {
      data: { hostname, is_primary: true, http_enabled: true, http_port: 8080 },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(addDomain.status()).toBe(200)

    // 4. 配置源站（指向testorigin）
    const addUpstream = await page.request.post(`${API_URL}/applications/${appId}/upstreams`, {
      data: { name: 'backend', scheme: 'http', host: 'testorigin', port: 8081, weight: 10 },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(addUpstream.status()).toBe(200)

    // 5. 源站连通性测试
    const testUpstream = await page.request.post(`${API_URL}/upstreams/test`, {
      data: { scheme: 'http', host: 'testorigin', port: 8081, health_check_path: '/health', allow_private: true },
      headers: { 'X-CSRF-Token': csrf },
    })
    const testResult = (await testUpstream.json())?.data
    expect(testResult?.tcp_connected).toBe(true)
    expect(testResult?.http_status).toBe(200)

    // 6. 启用应用
    const enable = await page.request.post(`${API_URL}/applications/${appId}/enable`, {
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(enable.status()).toBe(200)

    // 7. 配置预览
    const preview = await page.request.post(`${API_URL}/gateway-config/preview`, {
      headers: { 'X-CSRF-Token': csrf },
    })
    const previewData = (await preview.json())?.data
    expect(previewData?.server_count).toBeGreaterThan(0)
    expect(previewData?.configuration_hash).toBeTruthy()

    // 8. 发布配置
    const publish = await page.request.post(`${API_URL}/gateway-config/publish`, {
      data: { idempotency_key: `e2e-${appCode}` },
      headers: { 'X-CSRF-Token': csrf },
    })
    const publishData = (await publish.json())?.data
    expect(publishData?.status).toBe('SUCCESS')

    // 9. 验证应用通过网关真实可访问
    const gatewayResp = await page.request.get(`${GATEWAY_URL}/echo`, {
      headers: { Host: hostname },
    })
    expect(gatewayResp.status()).toBe(200)
    const originData = await gatewayResp.json()
    expect(originData?.upstream_mark).toBe('REACHED_ORIGIN')

    // 10. 验证WAF防护（PROTECT模式阻断SQLi）
    const sqliResp = await page.request.get(`${GATEWAY_URL}/echo?q=1'%20OR%20'1'='1`, {
      headers: { Host: hostname },
    })
    expect(sqliResp.status()).toBe(403)
  })
})
