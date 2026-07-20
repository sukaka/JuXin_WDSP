import { test, expect } from '@playwright/test'
import { loginViaAPI, createUserViaAPI, changePasswordViaAPI } from './helpers'

/**
 * 场景三：审计管理员
 * 登录 → 查看登录日志 → 查看操作审计 → 导出 → 尝试修改用户被拒
 */

const SYSADMIN = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYSADMIN_PWD = process.env.E2E_SYSADMIN_PWD || 'NewStr0ng!Pass2026'

async function setupAuditAdmin(page: any) {
  await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD)
  const username = `e2e_audit_${Date.now().toString().slice(-8)}`
  const { password: tempPwd } = await createUserViaAPI(page, username, 'AUDIT_ADMIN')
  const newPwd = 'AuditAdmin@E2E2026!'
  await loginViaAPI(page, username, tempPwd)
  await changePasswordViaAPI(page, tempPwd, newPwd)
  await page.context().clearCookies()
  await loginViaAPI(page, username, newPwd)
  return username
}

test.describe('场景三：审计管理员', () => {
  test('审计管理员菜单包含登录日志/操作审计', async ({ page }) => {
    await setupAuditAdmin(page)
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/dashboard/, { timeout: 10000 })
    await expect(page.getByRole('menuitem', { name: /登录日志/ })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: /操作审计/ })).toBeVisible()
    // 审计管理员不应看到用户管理/系统设置
    await expect(page.getByRole('menuitem', { name: /用户管理/ })).not.toBeVisible()
    await expect(page.getByRole('menuitem', { name: /系统设置/ })).not.toBeVisible()
  })

  test('查看登录日志', async ({ page }) => {
    await setupAuditAdmin(page)
    await page.goto('/login-logs')
    await expect(page).toHaveURL(/login-logs/)
    // 表格应有数据（之前的登录操作）
    await expect(page.locator('.ant-table').first()).toBeVisible({ timeout: 5000 })
    await expect(page.getByText(SYSADMIN).first()).toBeVisible({ timeout: 5000 })
  })

  test('查看操作审计', async ({ page }) => {
    await setupAuditAdmin(page)
    await page.goto('/audits')
    await expect(page).toHaveURL(/audits/)
    await expect(page.locator('.ant-table').first()).toBeVisible({ timeout: 5000 })
    // 应有用户创建等审计记录
    await expect(page.getByText(/users|用户/).first()).toBeVisible({ timeout: 5000 })
  })

  test('审计管理员访问登录日志接口成功，访问用户管理被拒', async ({ page }) => {
    await setupAuditAdmin(page)
    // API 层：可读审计/登录日志
    const base = process.env.E2E_BASE_URL || 'http://localhost:5173'
    const auditsResp = await page.request.get(`${base}/api/v1/audits`)
    expect(auditsResp.status()).toBe(200)
    const logsResp = await page.request.get(`${base}/api/v1/login-logs`)
    expect(logsResp.status()).toBe(200)
    // 不可管理用户
    const usersResp = await page.request.get(`${base}/api/v1/users`)
    expect(usersResp.status()).toBe(403)
  })

  test('审计管理员尝试修改用户被拒绝', async ({ page }) => {
    const username = await setupAuditAdmin(page)
    const base = process.env.E2E_BASE_URL || 'http://localhost:5173'
    // 获取 CSRF
    const me = await page.request.get(`${base}/api/v1/auth/me`)
    const meJson = await me.json()
    const csrf = meJson?.data?.csrf_token
    // 尝试创建用户
    const resp = await page.request.post(`${base}/api/v1/users`, {
      data: { username: 'hacker_e2e', display_name: 'x', role_code: 'SYSTEM_ADMIN' },
      headers: { 'X-CSRF-Token': csrf || '' },
    })
    expect(resp.status()).toBe(403)
  })
})
