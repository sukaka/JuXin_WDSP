import { test, expect } from '@playwright/test'
import { loginViaAPI, createUserViaAPI, changePasswordViaAPI, getCaptcha, API_URL } from './helpers'

/**
 * 场景四：账号锁定与解锁
 * 连续错误密码 → 锁定 → 正确密码仍不能登录 → 管理员解锁 → 重新登录成功
 */

const SYSADMIN = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYSADMIN_PWD = process.env.E2E_SYSADMIN_PWD || 'NewStr0ng!Pass2026'

async function tryLogin(page: any, username: string, password: string) {
  const { id, code } = await getCaptcha()
  const resp = await page.request.post(`${API_URL}/auth/login`, {
    data: { username, password, captcha_id: id, captcha_code: code },
  })
  return resp
}

test.describe('场景四：账号锁定与解锁', () => {
  test('连续失败锁定，管理员解锁后可重新登录', async ({ page }) => {
    // 准备：系统管理员创建一个安全管理员账号
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD)
    const username = `e2e_lock_${Date.now().toString().slice(-8)}`
    const { password: tempPwd } = await createUserViaAPI(page, username, 'SECURITY_ADMIN')
    const realPwd = 'LockTarget@2026!'
    await loginViaAPI(page, username, tempPwd)
    await changePasswordViaAPI(page, tempPwd, realPwd)

    // 步骤1：连续 5 次错误密码
    for (let i = 0; i < 5; i++) {
      const resp = await tryLogin(page, username, `wrong-pass-${i}`)
      // 前几次返回 401（统一提示）
    }

    // 步骤2：正确密码仍不能登录（账号已锁定）
    const lockedResp = await tryLogin(page, username, realPwd)
    const lockedBody = await lockedResp.json()
    // 锁定应返回 ACCOUNT_LOCKED（403）或统一 UNAUTHENTICATED（401）
    expect([403, 401]).toContain(lockedResp.status())

    // 步骤3：系统管理员解锁
    await loginViaAPI(page, SYSADMIN, SYSADMIN_PWD)
    const base = process.env.E2E_BASE_URL || 'http://localhost:5173'
    // 查询用户ID
    const listResp = await page.request.get(`${base}/api/v1/users?username=${username}`)
    const listJson = await listResp.json()
    const userId = listJson?.data?.items?.[0]?.id
    expect(userId).toBeTruthy()
    // 获取 CSRF
    const me = await page.request.get(`${base}/api/v1/auth/me`)
    const csrf = (await me.json())?.data?.csrf_token
    // 解锁
    const unlockResp = await page.request.post(`${base}/api/v1/users/${userId}/unlock`, {
      headers: { 'X-CSRF-Token': csrf || '' },
    })
    expect(unlockResp.status()).toBe(200)

    // 步骤4：解锁后正确密码可登录
    const reloginResp = await tryLogin(page, username, realPwd)
    expect(reloginResp.status()).toBe(200)
    const reloginBody = await reloginResp.json()
    expect(reloginBody?.data?.user?.username).toBe(username)
  })
})
