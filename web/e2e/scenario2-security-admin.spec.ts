import { test, expect } from '@playwright/test'
import { loginViaAPI, createUserViaAPI, changePasswordViaAPI } from './helpers'

/**
 * 场景二：安全管理员
 * 临时密码登录 → 强制改密 → 工作台 → 访问用户管理被拒 → 查看个人会话 → 退出
 */

const SYSADMIN = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYSADMIN_PWD = process.env.E2E_SYSADMIN_PWD || 'NewStr0ng!Pass2026'

test.describe('场景二：安全管理员', () => {
  test('临时密码登录被强制改密，改密后进入工作台', async ({ page }) => {
    // 先用系统管理员创建一个安全管理员
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD)
    const secUsername = `e2e_seca_${Date.now().toString().slice(-8)}`
    const { password: tempPwd } = await createUserViaAPI(page, secUsername, 'SECURITY_ADMIN')

    // 新会话：用临时密码登录（应强制改密）
    await page.context().clearCookies()
    await loginViaAPI(page, secUsername, tempPwd)
    await page.goto('/dashboard')
    // must_change_password=true → 强制跳转改密页
    await expect(page).toHaveURL(/change-password/, { timeout: 10000 })

    // 通过 API 改密（新密码）
    const newPwd = 'SecAdmin@E2E2026!'
    await changePasswordViaAPI(page, tempPwd, newPwd)

    // 改密后需重新登录
    await page.context().clearCookies()
    await loginViaAPI(page, secUsername, newPwd)
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/dashboard/, { timeout: 10000 })
  })

  test('安全管理员菜单极简（无用户管理/系统设置）', async ({ page }) => {
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD)
    const secUsername = `e2e_secm_${Date.now().toString().slice(-8)}`
    const { password: tempPwd } = await createUserViaAPI(page, secUsername, 'SECURITY_ADMIN')
    const newPwd = 'SecAdmin@E2E2026!'
    await loginViaAPI(page, secUsername, tempPwd)
    await changePasswordViaAPI(page, tempPwd, newPwd)

    await page.context().clearCookies()
    await loginViaAPI(page, secUsername, newPwd)
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/dashboard/, { timeout: 10000 })

    // 安全管理员不应看到用户管理、系统设置、审计菜单
    await expect(page.getByRole('menuitem', { name: /用户管理/ })).not.toBeVisible()
    await expect(page.getByRole('menuitem', { name: /系统设置/ })).not.toBeVisible()
    await expect(page.getByRole('menuitem', { name: /操作审计/ })).not.toBeVisible()
    // 应有工作台和个人中心
    await expect(page.getByRole('menuitem', { name: /工作台/ })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: /个人中心/ })).toBeVisible()
  })

  test('安全管理员直接访问用户管理返回无权限', async ({ page }) => {
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD)
    const secUsername = `e2e_secn_${Date.now().toString().slice(-8)}`
    const { password: tempPwd } = await createUserViaAPI(page, secUsername, 'SECURITY_ADMIN')
    const newPwd = 'SecAdmin@E2E2026!'
    await loginViaAPI(page, secUsername, tempPwd)
    await changePasswordViaAPI(page, tempPwd, newPwd)

    await page.context().clearCookies()
    await loginViaAPI(page, secUsername, newPwd)
    // 直接访问 /users 应跳 403 或显示无权限
    await page.goto('/users')
    await page.waitForTimeout(2000)
    const url = page.url()
    const has403 = url.includes('/403') || (await page.getByText(/无权|403|无权限/).count()) > 0
    expect(has403).toBeTruthy()

    // 后端接口层验证：直接调 API 应 403
    const resp = await page.request.get(`${process.env.E2E_BASE_URL || 'http://localhost:5173'}/api/v1/users`)
    expect(resp.status()).toBe(403)
  })

  test('安全管理员查看个人会话', async ({ page }) => {
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD)
    const secUsername = `e2e_secp_${Date.now().toString().slice(-8)}`
    const { password: tempPwd } = await createUserViaAPI(page, secUsername, 'SECURITY_ADMIN')
    const newPwd = 'SecAdmin@E2E2026!'
    await loginViaAPI(page, secUsername, tempPwd)
    await changePasswordViaAPI(page, tempPwd, newPwd)

    await page.context().clearCookies()
    await loginViaAPI(page, secUsername, newPwd)
    await page.goto('/profile')
    await expect(page).toHaveURL(/profile/)
    // 个人中心应显示用户名
    await expect(page.getByText(secUsername).first()).toBeVisible({ timeout: 5000 })
  })
})
