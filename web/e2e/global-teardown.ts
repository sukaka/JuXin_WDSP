import type { FullConfig } from '@playwright/test'

/**
 * E2E 全局 teardown：恢复登录接口限速为默认值（10次/分钟）。
 */
export default async function globalTeardown(config: FullConfig) {
  // 与 global-setup 对称：恢复 login rate_limit_per_minute 为 10
  const { default: Redis } = await import('ioredis')
  const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5173'
  const API = `${BASE_URL}/api/v1`
  const SYSADMIN = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
  const SYSADMIN_PWD = process.env.E2E_SYSADMIN_PWD || 'NewStr0ng!Pass2026'

  async function captcha() {
    const resp = await fetch(`${API}/auth/captcha`)
    const json = (await resp.json()) as { data?: { captcha_id?: string } }
    const r = new Redis({
      host: process.env.VALKEY_HOST || '127.0.0.1',
      port: Number(process.env.VALKEY_PORT || 6379),
      password: process.env.VALKEY_PASSWORD || 'CHANGE_ME_STRONG_PASSWORD',
      db: Number(process.env.VALKEY_DB || 0),
    })
    try {
      const code = await r.get(`jiuzhang:captcha:${json?.data?.captcha_id}`)
      return { id: json?.data?.captcha_id!, code: code! }
    } finally {
      r.disconnect()
    }
  }

  const { request } = await import('@playwright/test')
  const ctx = await request.newContext({ ignoreHTTPSErrors: true })
  try {
    const { id, code } = await captcha()
    const loginResp = await ctx.post(`${API}/auth/login`, {
      data: { username: SYSADMIN, password: SYSADMIN_PWD, captcha_id: id, captcha_code: code },
    })
    const loginJson = await loginResp.json()
    const csrf = loginJson?.data?.csrf_token
    const cookies = loginResp.headers()['set-cookie'] || ''
    const listResp = await ctx.get(`${API}/system-settings?group=login`, { headers: { cookie: cookies } })
    const listJson = await listResp.json()
    const item = (listJson?.data?.items || []).find((s: any) => s.setting_key === 'rate_limit_per_minute')
    if (item) {
      await ctx.put(`${API}/system-settings`, {
        headers: { cookie: cookies, 'X-CSRF-Token': csrf },
        data: { setting_group: 'login', setting_key: 'rate_limit_per_minute', setting_value: 10, version: item.version },
      })
      console.log('[e2e teardown] login rate limit restored to 10')
    }
  } catch (e) {
    console.log(`[e2e teardown] failed to restore rate limit: ${e}`)
  } finally {
    await ctx.dispose()
  }
}
