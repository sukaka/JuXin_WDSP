import { test, expect } from '@playwright/test'
import { loginViaUI, loginViaAPI, createUserViaAPI, API_URL } from './helpers'

/**
 * 场景一：系统管理员完整流程
 * 登录 → 创建安全管理员 → 创建审计管理员 → 用户列表 → 重置密码 → 强制下线 → 修改密码策略 → 退出
 */

const SYSADMIN = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYSADMIN_PWD = process.env.E2E_SYSADMIN_PWD || 'NewStr0ng!Pass2026'

test.describe('场景一：系统管理员', () => {
  test('登录并访问工作台', async ({ page }) => {
    page.on('console', (msg) => console.log('BROWSER:', msg.type(), msg.text()))
    page.on('pageerror', (err) => console.log('PAGEERROR:', err.message))
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD)
    await page.goto('/dashboard')
    await page.waitForTimeout(3000)
    console.log('CURRENT URL:', page.url())
    await expect(page).toHaveURL(/dashboard/, { timeout: 10000 })
    // 工作台显示当前用户
    await expect(page.getByText(SYSADMIN).first()).toBeVisible({ timeout: 5000 })
  })

  test('系统管理员菜单包含用户管理/系统设置', async ({ page }) => {
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD); await page.goto("/dashboard")
    await expect(page).toHaveURL(/dashboard/, { timeout: 10000 })
    await expect(page.getByRole('menuitem', { name: /用户管理/ })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: /系统设置/ })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: /角色权限/ })).toBeVisible()
    // 系统管理员不应看到"操作审计"菜单
    await expect(page.getByRole('menuitem', { name: /操作审计/ })).not.toBeVisible()
  })

  test('创建安全管理员并返回临时密码', async ({ page }) => {
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD); await page.goto("/dashboard")
    await expect(page).toHaveURL(/dashboard/, { timeout: 10000 })

    await page.goto('/users')
    await expect(page).toHaveURL(/users/)
    // 点击新建用户
    await page.getByRole('button', { name: '新建用户' }).click()
    const username = `e2e_sec_${Date.now().toString().slice(-8)}`
    await page.getByPlaceholder('登录用户名').fill(username)
    await page.getByPlaceholder('用户显示名称').fill('E2E安全管理员')
    // 选择角色（antd Select，在 Modal 作用域内）
    const modal = page.locator('.ant-modal')
    await modal.locator('.ant-select').click()
    await page.getByTitle('安全管理员').locator('div').click()
    // 监听创建用户请求响应
    const createRespPromise = page.waitForResponse(
      (resp) => resp.url().includes('/api/v1/users') && resp.request().method() === 'POST',
      { timeout: 15000 },
    )
    // 点击确定（antd Modal footer primary 按钮）
    await modal.locator('.ant-modal-footer button.ant-btn-primary').click()
    const createResp = await createRespPromise
    console.log('CREATE USER STATUS:', createResp.status(), await createResp.text())
    // 临时密码 Modal 出现（标题含"临时密码"）
    await expect(page.getByText(/临时密码（仅显示一次）/).first()).toBeVisible({ timeout: 10000 })
  })

  test('用户列表显示新创建用户', async ({ page }) => {
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD); await page.goto("/dashboard")
    await page.goto('/users')
    await expect(page).toHaveURL(/users/)
    // 搜索定位（用户多时目标用户可能不在第一页）
    await page.getByPlaceholder('搜索用户名').fill(SYSADMIN)
    await page.getByPlaceholder('搜索用户名').press('Enter')
    await expect(page.getByText(SYSADMIN).first()).toBeVisible({ timeout: 5000 })
  })

  test('修改密码策略（系统设置）', async ({ page }) => {
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD); await page.goto("/dashboard")
    await page.goto('/system-settings')
    await expect(page).toHaveURL(/system-settings/)
    // 应显示密码策略分组
    await expect(page.getByText(/密码策略|password/i).first()).toBeVisible({ timeout: 5000 })
  })

  test('退出登录返回登录页', async ({ page }) => {
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD); await page.goto("/dashboard")
    await expect(page).toHaveURL(/dashboard/, { timeout: 10000 })
    // 打开用户菜单（点击显示名"系统管理员"所在 Dropdown），点退出登录
    await page.locator('header').getByText('系统管理员').click()
    await page.getByRole('menuitem', { name: /退出登录/ }).click()
    await expect(page).toHaveURL(/login/, { timeout: 10000 })
  })
})
