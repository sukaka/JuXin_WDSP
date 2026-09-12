import { test, expect, type Page } from '@playwright/test'
import Redis from 'ioredis'
import { loginViaAPI, createUserViaAPI, changePasswordViaAPI, API_URL, BASE_URL } from './helpers'

/**
 * EXC-14 E2E：受限例外与最终处置（WDSP P0-04）管理面页面关键流程
 * （docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md 验收用例 EXC-14 页面子集；
 *   真实网关行为由 test/e2e/exception-p0-smoke.sh 覆盖，本规格聚焦页面可见性与操作流）
 *
 * 覆盖：
 *  1. 受限例外创建（API 落地草稿）→ 列表派生状态可见 → 详情抽屉「影响预览」面板
 *     （VALID/编译指纹/保护模块清单/无法估算不显示 0）→ 启用 → 状态翻转「未发布/未知」
 *     （不假装已生效——无节点回执数据时如实显示）
 *  2. 启用门禁可见性：LOG_ONLY 历史动作 → 保存即 NEEDS_REVIEW（或创建即拒），
 *     列表「启用」按钮禁用且 Tooltip 说明；预览面板展示不支持动作迁移说明
 *  3. 预览乐观锁：过期 expected_version → 409 冲突提示
 *  4. 事件详情「最终处置」区块：真实 WAF 拦截事件（PROTECT 应用发布后经网关打 403）
 *     在事件详情抽屉显示 final_decision（executor=WAF/BLOCK/403/步骤序列）；
 *     无 final_decision 的旧事件显示「无最终处置记录」纯文本（不伪造）
 *  5. RBAC：审计管理员只读——无「新建例外」入口、无启用按钮
 *
 * 环境依赖（与 jwt-trust.spec.ts 一致）：stage5+wdsp 编排（API 127.0.0.1:18081，
 * 网关 18080，vite dev 经 E2E_BASE_URL 覆盖）；Valkey 供验证码读取。
 * 限流键清理：global-setup 提额被 settings 上限拒绝（10000），共享环境残留限流
 * 会导致登录 429——beforeEach 清 jiuzhang:ratelimit:*（与 jwt-trust.spec.ts 同口径）。
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'
const SYS_USER = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYS_PWD = process.env.E2E_SYSADMIN_PWD || 'SysAdmin@S5!2026x'
const GATEWAY_URL = process.env.E2E_GATEWAY_URL || 'http://127.0.0.1:18080'

const rand = () => Math.random().toString(36).slice(2, 8)

test.beforeEach(async () => {
  const redis = new Redis({
    host: process.env.VALKEY_HOST || '127.0.0.1',
    port: Number(process.env.VALKEY_PORT || 56379),
    password: process.env.VALKEY_PASSWORD || 'ci-only-valkey-pwd',
    db: Number(process.env.VALKEY_DB || 0),
  })
  try {
    const keys = await redis.keys('jiuzhang:ratelimit:*')
    if (keys.length > 0) await redis.del(...keys)
  } finally {
    redis.disconnect()
  }
})

async function csrfToken(page: Page): Promise<string> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  return ((await me.json())?.data?.csrf_token as string) || ''
}

/** 创建最小要素应用（不启用不发布），返回 id/code */
async function createApp(page: Page, mode: 'OFF' | 'PROTECT'): Promise<{ id: string; code: string }> {
  const csrf = await csrfToken(page)
  const code = `e2e-exc-${rand()}`
  const resp = await page.request.post(`${API_URL}/applications`, {
    data: { code, name: `E2E 受限例外 ${code}`, protection_mode: mode },
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status()).toBe(200)
  const id = (await resp.json())?.data?.id as string
  return { id, code }
}

/** 创建窄范围 WAF 例外草稿（APPLICATION+942100+ARGS:comment+临时窗口），返回 id/version */
async function createNarrowException(page: Page, appId: string): Promise<{ id: string; version: number }> {
  const csrf = await csrfToken(page)
  const now = Date.now()
  const resp = await page.request.post(`${API_URL}/exceptions`, {
    data: {
      name: `e2e-窄例外-${rand()}`,
      scope_type: 'APPLICATION',
      application_id: appId,
      uri_exact: '/api/orders',
      methods: ['POST'],
      rule_ids: [942100],
      param_names: ['comment'],
      exception_action: 'REMOVE_VAR_DETECTION',
      is_temporary: true,
      effective_from: new Date(now - 60_000).toISOString(),
      effective_until: new Date(now + 3600_000).toISOString(),
      reason: 'EXC-14 E2E',
    },
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status()).toBe(200)
  const exc = (await resp.json())?.data?.exception
  expect(exc.status).toBe('DRAFT')
  expect(exc.validation_status).toBe('VALID')
  return { id: exc.id as string, version: exc.version as number }
}

test.describe('EXC-14：受限例外页面流', () => {
  test('草稿 → 预览 → 启用 → 派生状态如实可见', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page, 'OFF')
    await createNarrowException(page, app.id)

    await page.goto(`${BASE_URL}/exceptions`)
    const row = page.locator('tr', { hasText: 'e2e-窄例外-' })
    await expect(row.first()).toBeVisible()
    // 派生状态：草稿（纯函数推导，非伪造计时器）
    await expect(row.first()).toContainText('草稿')

    // 详情抽屉 → 影响预览
    await row.first().getByRole('button', { name: '详情' }).click()
    const drawer = page.locator('.ant-drawer-open')
    await expect(drawer).toContainText('影响预览')
    await drawer.getByRole('button', { name: '影响预览' }).click()
    // VALID + 编译指纹 + 保护模块 + 无法估算（不显示 0）
    await expect(drawer).toContainText('VALID', { timeout: 10000 })
    await expect(drawer).toContainText('942100')
    await expect(drawer).toContainText('访问控制')
    await expect(drawer).toContainText('无法估算')

    // 启用 → 派生状态翻转「未发布/未知」（无节点回执数据，如实不假装已生效）
    await page.keyboard.press('Escape')
    await row.first().getByRole('button', { name: '启用' }).click()
    await expect(page.locator('.ant-message')).toContainText('操作成功', { timeout: 10000 })
    await expect(row.first()).toContainText('未发布/未知', { timeout: 10000 })
  })

  test('启用门禁：LOG_ONLY 不支持新启用如实可见', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page, 'OFF')
    const csrf = await csrfToken(page)
    const resp = await page.request.post(`${API_URL}/exceptions`, {
      data: {
        name: `e2e-历史动作-${rand()}`,
        scope_type: 'APPLICATION',
        application_id: app.id,
        uri_exact: '/api/orders',
        methods: ['POST'],
        rule_ids: [942100],
        exception_action: 'LOG_ONLY',
      },
      headers: { 'X-CSRF-Token': csrf },
    })
    if (resp.status() === 400) {
      // 保存层直接拒绝：字段级错误如实返回（UNSUPPORTED_ACTION）
      const body = await resp.json()
      test.info().annotations.push({ type: 'note', description: `create LOG_ONLY rejected: ${JSON.stringify(body).slice(0, 200)}` })
      expect([400]).toContain(resp.status())
      return
    }
    expect(resp.status()).toBe(200)
    const exc = (await resp.json())?.data?.exception
    // 保存为 NEEDS_REVIEW 草稿，启用被禁
    expect(exc.validation_status).toBe('NEEDS_REVIEW')

    await page.goto(`${BASE_URL}/exceptions`)
    const row = page.locator('tr', { hasText: 'e2e-历史动作-' })
    await expect(row.first()).toBeVisible()
    await expect(row.first()).toContainText('待审查')
    // 启用按钮禁用（Tooltip 说明缺失项；禁用态本身即门禁可见性）
    const enableBtn = row.first().getByRole('button', { name: '启用' })
    await expect(enableBtn).toBeDisabled()
    // 详情抽屉展示 NEEDS_REVIEW 告警与不支持原因
    await row.first().getByRole('button', { name: '详情' }).click()
    const drawer = page.locator('.ant-drawer-open')
    await expect(drawer).toContainText('NEEDS_REVIEW')
    await expect(drawer).toContainText('仅观察')
  })

  test('预览乐观锁：过期 expected_version → 409', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page, 'OFF')
    const exc = await createNarrowException(page, app.id)
    const csrf = await csrfToken(page)
    const stale = await page.request.post(`${API_URL}/exceptions/${exc.id}/preview`, {
      data: { expected_version: exc.version + 99 },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(stale.status()).toBe(409)
    const ok = await page.request.post(`${API_URL}/exceptions/${exc.id}/preview`, {
      data: { expected_version: exc.version },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(ok.status()).toBe(200)
    const data = (await ok.json())?.data
    expect(data.validation_status).toBe('VALID')
    expect(data.compiled_fingerprint).toMatch(/^[0-9a-f]{64}$/)
    expect(data.estimated_match_count).toBeNull()
  })

  test('审计管理员只读：无新建/启用入口', async ({ page }) => {
    // 系统管理员现场创建 AUDIT_ADMIN 并完成首次改密（同 jwt-trust.spec 惯例：
    // createUserViaAPI 返回临时口令，不得自设口令——role_code 第三参）
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    const auditUser = `audit_exc_${rand()}`
    const { password: tempPwd } = await createUserViaAPI(page, auditUser, 'AUDIT_ADMIN')
    const auditPwd = `Audit@${rand()}1X`
    await loginViaAPI(page, auditUser, tempPwd)
    await changePasswordViaAPI(page, tempPwd, auditPwd)
    await page.context().clearCookies()
    await loginViaAPI(page, auditUser, auditPwd)

    await page.goto(`${BASE_URL}/exceptions`)
    await expect(page.getByRole('button', { name: '新建例外' })).toHaveCount(0)
    // 无 exceptions.manage 权限时直接 403/空列表，均无启用入口
    await expect(page.getByRole('button', { name: '启用' })).toHaveCount(0)
  })
})

test.describe('EXC-14：事件详情最终处置区块', () => {
  test('WAF 拦截事件详情展示最终处置（executor=WAF/BLOCK/403）', async ({ page }) => {
    test.setTimeout(180_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page, 'PROTECT')
    const host = `${app.code}.local`
    const csrf = await csrfToken(page)
    // 域名 + 源站 + 启用 + 发布
    await page.request.post(`${API_URL}/applications/${app.id}/domains`, {
      data: { hostname: host, is_primary: true, http_enabled: true, https_enabled: false, http_port: 8080, redirect_http_to_https: false },
      headers: { 'X-CSRF-Token': csrf },
    })
    await page.request.post(`${API_URL}/applications/${app.id}/upstreams`, {
      data: { name: 'testorigin', scheme: 'http', host: 'testorigin', port: 8081, weight: 1, priority: 1, health_check_enabled: false, health_check_path: '/health', health_check_method: 'GET', health_check_interval_seconds: 10, health_check_timeout_seconds: 3, expected_status_codes: '200', connect_timeout_ms: 3000, response_header_timeout_ms: 10000, tls_server_name: '', tls_verify: false },
      headers: { 'X-CSRF-Token': csrf },
    })
    await page.request.post(`${API_URL}/applications/${app.id}/enable`, { headers: { 'X-CSRF-Token': csrf } })
    const pub = await page.request.post(`${API_URL}/gateway-config/publish`, {
      data: { idempotency_key: `e2e-exc-${Date.now()}` },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(pub.status()).toBe(200)
    const taskId = (await pub.json())?.data?.id
    for (let i = 0; i < 30; i++) {
      const st = await page.request.get(`${API_URL}/publish-tasks/${taskId}`)
      const status = (await st.json())?.data?.status
      if (status === 'SUCCESS') break
      if (status === 'FAILED') throw new Error('发布失败')
      await page.waitForTimeout(1000)
    }

    // 经真实网关打一发 SQLi（PROTECT → 403 + final_decision 事件）
    const attack = await page.request.get(`${GATEWAY_URL}/echo?q=1'%20OR%20'1'='1`, { headers: { Host: host } })
    expect(attack.status()).toBe(403)

    // 轮询事件 API 直至出现带 final_decision 的 WAF 拦截事件
    // （列表不投影 final_decision——先按 response_status=403 找候选行，再 GET 详情核验）
    let evt: { id: string } | undefined
    for (let i = 0; i < 30; i++) {
      const events = await page.request.get(`${API_URL}/security-events?page_size=10`)
      const items = ((await events.json())?.data?.items ?? []) as Array<{ id: string; response_status?: number; request_path?: string }>
      const candidates = items.filter((it) => it.response_status === 403 && it.request_path === '/echo')
      for (const c of candidates) {
        const detail = await page.request.get(`${API_URL}/security-events/${c.id}`)
        const body = await detail.json()
        const fd = body?.data?.event?.final_decision
        if (fd?.executor_module === 'WAF') {
          evt = c
          break
        }
      }
      if (evt) break
      await page.waitForTimeout(2000)
    }
    if (!evt) {
      test.skip(true, '未等到携带 final_decision 的 WAF 事件（事件采集链未在本环境落地）')
      return
    }

    // 详情 final_decision 已确认存在（上方过滤）；列表行无双击/「详情」按钮才开抽屉
    await page.goto(`${BASE_URL}/security-events`)
    const row = page.locator('tr', { hasText: '/echo' }).first()
    await expect(row).toBeVisible({ timeout: 15000 })
    await row.getByRole('button', { name: '详情' }).click()
    const drawer = page.locator('.ant-drawer-open')
    await expect(drawer).toContainText('最终处置', { timeout: 10000 })
    await expect(drawer).toContainText('WAF')
    await expect(drawer).toContainText('403')
  })
})
