import type { Page } from '@playwright/test'
import Redis from 'ioredis'

/**
 * E2E 测试辅助：登录、验证码读取、用户准备。
 * 通过 HTTP API 获取验证码 ID，从 Valkey 读取验证码答案完成真实登录。
 */

// 前端入口（vite dev server 或容器），通过其 /api 代理访问后端，
// 确保登录 Cookie 与页面同域
const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5173'
const API_URL = `${BASE_URL}/api/v1`

function valkey() {
  return new Redis({
    host: process.env.VALKEY_HOST || '127.0.0.1',
    port: Number(process.env.VALKEY_PORT || 6379),
    password: process.env.VALKEY_PASSWORD || 'CHANGE_ME_STRONG_PASSWORD',
    db: Number(process.env.VALKEY_DB || 0),
    lazyConnect: false,
  })
}

/** 从后端 API 获取验证码，并从 Valkey 读取答案 */
export async function getCaptcha(): Promise<{ id: string; code: string }> {
  const resp = await fetch(`${API_URL}/auth/captcha`)
  const json = (await resp.json()) as { data?: { captcha_id?: string } }
  const id = json?.data?.captcha_id
  if (!id) throw new Error('captcha_id not returned')
  const r = valkey()
  try {
    const code = await r.get(`jiuzhang:captcha:${id}`)
    if (!code) throw new Error('captcha code not found in valkey')
    if (process.env.E2E_DEBUG) console.log(`[e2e] captcha id=${id} code=${code}`)
    return { id, code }
  } finally {
    r.disconnect()
  }
}

/** 通过 UI 登录（真实流程：拦截页面验证码请求获取 captcha_id，读 Valkey 答案填入） */
export async function loginViaUI(page: Page, username: string, password: string) {
  // 拦截页面加载时的验证码响应，获取页面实际使用的 captcha_id
  const captchaRespPromise = page.waitForResponse(
    (resp) => resp.url().includes('/api/v1/auth/captcha') && resp.status() === 200,
    { timeout: 10000 },
  )
  await page.goto('/login')
  const captchaResp = await captchaRespPromise
  const captchaJson = (await captchaResp.json()) as { data?: { captcha_id?: string } }
  const captchaId = captchaJson?.data?.captcha_id
  if (!captchaId) throw new Error('page captcha_id not captured')

  const r = valkey()
  let code: string | null
  try {
    code = await r.get(`jiuzhang:captcha:${captchaId}`)
  } finally {
    r.disconnect()
  }
  if (!code) throw new Error('captcha code not found in valkey')

  await page.getByPlaceholder('用户名').fill(username)
  await page.getByPlaceholder('密码').fill(password)
  await page.getByPlaceholder('图形验证码').fill(code)
  await page.getByRole('button', { name: /登 ?录/ }).click()
}

/** 通过 API 直接登录获取会话（跳过 UI，用于快速准备认证态） */
export async function loginViaAPI(
  page: Page,
  username: string,
  password: string,
): Promise<void> {
  const { id, code } = await getCaptcha()
  const resp = await page.request.post(`${API_URL}/auth/login`, {
    data: { username, password, captcha_id: id, captcha_code: code },
  })
  if (!resp.ok()) {
    throw new Error(`login api failed: ${resp.status()} ${await resp.text()}`)
  }
  // page.request 会自动管理 cookie（共享 context 的 cookie jar）
}

/** 通过 API 创建用户（系统管理员态），返回 {username, password} */
export async function createUserViaAPI(
  page: Page,
  username: string,
  roleCode: string,
): Promise<{ username: string; password: string }> {
  // 先确保有 CSRF token（通过 /auth/me 获取）
  const me = await page.request.get(`${API_URL}/auth/me`)
  const meJson = (await me.json()) as { data?: { csrf_token?: string } }
  const csrf = meJson?.data?.csrf_token
  const resp = await page.request.post(`${API_URL}/users`, {
    data: { username, display_name: username, role_code: roleCode },
    headers: { 'X-CSRF-Token': csrf || '' },
  })
  if (!resp.ok()) {
    throw new Error(`create user failed: ${resp.status()} ${await resp.text()}`)
  }
  const json = (await resp.json()) as { data?: { temporary_password?: string } }
  const password = json?.data?.temporary_password
  if (!password) throw new Error('temporary_password not returned')
  return { username, password }
}

/** 通过 API 修改密码（处理 must_change_password 用户） */
export async function changePasswordViaAPI(
  page: Page,
  oldPassword: string,
  newPassword: string,
): Promise<void> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  const meJson = (await me.json()) as { data?: { csrf_token?: string } }
  const csrf = meJson?.data?.csrf_token
  const resp = await page.request.post(`${API_URL}/auth/change-password`, {
    data: { old_password: oldPassword, new_password: newPassword },
    headers: { 'X-CSRF-Token': csrf || '' },
  })
  if (!resp.ok()) {
    throw new Error(`change password failed: ${resp.status()} ${await resp.text()}`)
  }
}

export { API_URL, BASE_URL }
