import { test, expect, type Page } from '@playwright/test'
import { loginViaAPI, API_URL } from './helpers'

/**
 * 阶段3 冒烟：Web应用 / 域名 / 源站 / 证书 / 配置发布 / 配置版本 / 网关状态
 * 使用安全管理员真实登录，验证页面渲染真实后端数据，并走通
 * 新建应用 → 新增域名 → 新增源站 → 连通性测试 → 删除应用 的完整 UI 流程。
 */

const SECADMIN = process.env.E2E_SECADMIN_USER || 'sec_admin_s3'
const SECADMIN_PWD = process.env.E2E_SECADMIN_PWD || 'SecAdmin@S3!2026'

const APP_CODE = `e2e-app-${Date.now().toString(36)}`

test.describe('阶段3：应用接入与配置发布', () => {
  test.beforeEach(async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text())
    })
    await loginViaAPI(page, SECADMIN, SECADMIN_PWD)
    ;(page as Page & { __errors?: string[] }).__errors = errors
  })

  test.afterEach(async ({ page }) => {
    const errors = (page as Page & { __errors?: string[] }).__errors || []
    // 过滤第三方库告警（antd 弃用提示、React DevTools），页面级 JS 错误应清零
    const fatal = errors.filter(
      (e) => !e.includes('Download the React DevTools') && !e.includes('[antd:'),
    )
    expect(fatal, `页面存在 JS 错误：${fatal.join(' | ')}`).toEqual([])
    // 兜底清理：删除本用例创建的 e2e-app-* 应用（避免失败时残留）
    const me = await page.request.get(`${API_URL}/auth/me`)
    const meJson = (await me.json()) as { data?: { csrf_token?: string } }
    const csrf = meJson?.data?.csrf_token || ''
    const list = await page.request.get(`${API_URL}/applications?page_size=100`)
    const listJson = (await list.json()) as {
      data?: { items?: { id: string; code: string }[] }
    }
    for (const app of listJson?.data?.items ?? []) {
      if (app.code.startsWith('e2e-app-')) {
        await page.request.delete(`${API_URL}/applications/${app.id}`, {
          headers: { 'X-CSRF-Token': csrf },
        })
      }
    }
  })

  test('Web应用列表渲染真实数据', async ({ page }) => {
    await page.goto('/applications')
    await expect(page.locator('.ant-card-head-title', { hasText: '网站应用' })).toBeVisible()
    await expect(page.getByText('WAF测试应用')).toBeVisible({ timeout: 10000 })
    await expect(page.getByText('waf-test.local')).toBeVisible()
    await expect(page.getByText(/关闭|观察|防护/).first()).toBeVisible()
  })

  test('新建应用 → 域名 → 源站 → 连通性测试 → 删除应用', async ({ page }) => {
    // 1. 新建应用（通过高级选项自定义应用标识，同时验证列表按名称与域名展示）
    await page.goto('/applications')
    await page.getByRole('button', { name: '新建应用' }).click()
    await page.getByLabel('应用名称').fill('E2E冒烟应用')
    await page.getByText('高级选项（自定义应用标识）').click()
    await page.getByLabel('应用标识').fill(APP_CODE)
    await page.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('E2E冒烟应用')).toBeVisible({ timeout: 10000 })

    // 非法标识前端校验
    await page.getByRole('button', { name: '新建应用' }).click()
    await page.getByText('高级选项（自定义应用标识）').click()
    await page.getByLabel('应用标识').fill('BAD--CODE')
    await page.getByLabel('应用名称').click()
    await expect(page.getByText('3-64 位小写字母、数字或短横线')).toBeVisible()
    await page.getByRole('button', { name: /取 ?消/ }).click()

    // 2. 进入详情，新增域名
    await page
      .getByRole('row', { name: /E2E冒烟应用/ })
      .getByText('E2E冒烟应用')
      .click()
    await expect(page.getByText('应用标识')).toBeVisible()
    await expect(page.getByText(APP_CODE)).toBeVisible()
    await page.getByRole('button', { name: '新增域名' }).click()
    await page.getByPlaceholder('example.com 或 *.example.com').fill(`${APP_CODE}.example.com`)
    await page.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText(`${APP_CODE}.example.com`)).toBeVisible({ timeout: 10000 })

    // 非法域名前端校验
    await page.getByRole('button', { name: '新增域名' }).click()
    await page.getByPlaceholder('example.com 或 *.example.com').fill('https://bad.host/x')
    await page.getByText('设为主域名').click()
    await expect(page.getByText('域名不得包含协议')).toBeVisible()
    await page.getByRole('button', { name: /取 ?消/ }).click()

    // 3. 新增源站
    await page.getByRole('tab', { name: /源站管理/ }).click()
    await page.getByRole('button', { name: '新增源站' }).click()
    await page.getByPlaceholder('源站名称（可选）').fill('e2e-origin')
    await page.getByPlaceholder('IP 或域名，如 10.0.0.1 / origin.internal').fill('testorigin')
    await page.getByLabel('端口').fill('8081')
    await page.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('http://testorigin:8081')).toBeVisible({ timeout: 10000 })

    // 4. 连通性测试（testorigin 为 docker 网络内地址，需允许私网）
    await page.getByRole('button', { name: /测 ?试/ }).first().click()
    await page.getByText('允许私网地址').click()
    await page.getByRole('button', { name: '开始测试' }).click()
    await expect(page.getByText(/连通性测试通过|测试失败/)).toBeVisible({ timeout: 15000 })
    await page.keyboard.press('Escape')

    // 5. 返回列表验证主域名展示并删除应用（二次确认）
    await page.goto('/applications')
    const row = page.getByRole('row', { name: new RegExp(`${APP_CODE}\\.example\\.com`) })
    await expect(row).toBeVisible({ timeout: 10000 })
    await row.getByText('更多').hover()
    await page.getByRole('menuitem', { name: '删除' }).click()
    await page.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByRole('row', { name: new RegExp(`${APP_CODE}\\.example\\.com`) })).toHaveCount(0, {
      timeout: 10000,
    })
  })

  test('应用详情展示域名与源站 Tab', async ({ page }) => {
    await page.goto('/applications')
    await page.getByText('WAF测试应用').click()
    await expect(page.getByText('waf-test.local')).toBeVisible({ timeout: 10000 })
    await page.getByRole('tab', { name: /源站管理/ }).click()
    await expect(page.getByText('http://testorigin:8081')).toBeVisible()
    await page.getByRole('tab', { name: '证书绑定' }).click()
    await expect(page.getByText(/未启用 HTTPS 域名|证书绑定关系/)).toBeVisible()
  })

  test('HTTPS证书页渲染', async ({ page }) => {
    await page.goto('/certificates')
    await expect(page.locator('.ant-card-head-title', { hasText: 'HTTPS证书' })).toBeVisible()
    await expect(page.getByRole('button', { name: '上传证书' })).toBeVisible()
  })

  test('配置发布：预览与校验真实通过', async ({ page }) => {
    await page.goto('/config-publish')
    await expect(page.getByText('当前生效版本')).toBeVisible()
    await page.getByRole('button', { name: '预览配置' }).click()
    await expect(page.getByText('业务摘要')).toBeVisible({ timeout: 10000 })
    await expect(page.getByText('waf-test').first()).toBeVisible()
    await page.keyboard.press('Escape')
    await page.getByRole('button', { name: '校验配置' }).click()
    await expect(page.getByText('配置校验通过，可以发布')).toBeVisible({ timeout: 10000 })
  })

  test('配置版本列表与差异对比', async ({ page }) => {
    await page.goto('/config-versions')
    await expect(page.locator('.ant-card-head-title', { hasText: '配置版本' })).toBeVisible()
    await expect(page.getByText(/^V\d{8}\./).first()).toBeVisible({ timeout: 10000 })
    await page.getByRole('button', { name: /差 ?异/ }).first().click()
    await expect(page.getByText('与当前版本差异对比')).toBeVisible()
    await expect(page.getByText(/配置一致|配置不同/)).toBeVisible()
  })

  test('网关状态页展示真实运行数据', async ({ page }) => {
    await page.goto('/gateway-status')
    await expect(page.locator('.ant-card-head-title', { hasText: '网关状态' })).toBeVisible()
    await expect(page.getByText('在线', { exact: true })).toBeVisible({ timeout: 10000 })
    await expect(page.getByText('防护应用数')).toBeVisible()
    await expect(page.getByText('接入域名数')).toBeVisible()
    await expect(page.getByText('在线源站数')).toBeVisible()
  })

  test('菜单按角色展示应用防护分组', async ({ page }) => {
    await page.goto('/dashboard')
    await expect(page.getByRole('menuitem', { name: '网站应用' })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: 'HTTPS证书' })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: '配置发布' })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: '配置版本' })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: '网关状态' })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: '用户管理' })).toHaveCount(0)
  })
})
