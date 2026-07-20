import { request, type FullConfig } from '@playwright/test'
import Redis from 'ioredis'

/**
 * E2E 全局 setup：临时调高登录接口限速（E2E 会大量登录），
 * 避免触发 RATE_LIMITED 影响功能验证。全局 teardown 恢复默认值。
 */

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5173'
const API = `${BASE_URL}/api/v1`
const SYSADMIN = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYSADMIN_PWD = process.env.E2E_SYSADMIN_PWD || 'NewStr0ng!Pass2026'
const ORIGINAL_RATE = 10

async function captcha(): Promise<{ id: string; code: string }> {
  const resp = await fetch(`${API}/auth/captcha`)
  const json = (await resp.json()) as { data?: { captcha_id?: string } }
  const id = json?.data?.captcha_id
  const r = new Redis({
    host: process.env.VALKEY_HOST || '127.0.0.1',
    port: Number(process.env.VALKEY_PORT || 6379),
    password: process.env.VALKEY_PASSWORD || 'CHANGE_ME_STRONG_PASSWORD',
    db: Number(process.env.VALKEY_DB || 0),
  })
  try {
    const code = await r.get(`jiuzhang:captcha:${id}`)
    return { id: id!, code: code! }
  } finally {
    r.disconnect()
  }
}

async function setLoginRate(ctx: any, rate: number) {
  const { id, code } = await captcha()
  const loginResp = await ctx.post(`${API}/auth/login`, {
    data: { username: SYSADMIN, password: SYSADMIN_PWD, captcha_id: id, captcha_code: code },
  })
  const loginJson = await loginResp.json()
  const csrf = loginJson?.data?.csrf_token
  const cookies = loginResp.headers()['set-cookie'] || ''

  // 读当前版本
  const listResp = await ctx.get(`${API}/system-settings?group=login`, {
    headers: { cookie: cookies },
  })
  const listJson = await listResp.json()
  const item = (listJson?.data?.items || []).find((s: any) => s.setting_key === 'rate_limit_per_minute')
  if (!item) return
  const putResp = await ctx.put(`${API}/system-settings`, {
    headers: { cookie: cookies, 'X-CSRF-Token': csrf },
    data: {
      setting_group: 'login',
      setting_key: 'rate_limit_per_minute',
      setting_value: rate,
      version: item.version,
    },
  })
  return putResp.status()
}

async function clearRateLimitKeys() {
  const r = new Redis({
    host: process.env.VALKEY_HOST || '127.0.0.1',
    port: Number(process.env.VALKEY_PORT || 6379),
    password: process.env.VALKEY_PASSWORD || 'CHANGE_ME_STRONG_PASSWORD',
    db: Number(process.env.VALKEY_DB || 0),
  })
  try {
    const keys = await r.keys('jiuzhang:ratelimit:*')
    if (keys.length > 0) {
      await r.del(...keys)
      console.log(`[e2e setup] cleared ${keys.length} rate limit keys`)
    }
  } finally {
    r.disconnect()
  }
}

export default async function globalSetup(config: FullConfig) {
  // 1. 先清空限速计数（避免改设置时登录被限）
  await clearRateLimitKeys()
  // 2. 调高登录限速（支持动态读取的后端会即时生效）
  const ctx = await request.newContext({ ignoreHTTPSErrors: true })
  try {
    const status = await setLoginRate(ctx, 100000)
    console.log(`[e2e setup] login rate limit set to 100000 (status=${status})`)
  } catch (e) {
    console.log(`[e2e setup] failed to adjust rate limit: ${e}`)
  } finally {
    await ctx.dispose()
  }
}
