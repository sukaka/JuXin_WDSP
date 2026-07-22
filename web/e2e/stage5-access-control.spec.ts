import { test, expect, type Page } from '@playwright/test'
import { loginViaAPI, createUserViaAPI, changePasswordViaAPI, API_URL } from './helpers'

/**
 * 阶段5 E2E：可信代理 / IP黑白名单发布 / CC策略发布 / 临时封禁解封 / 审计管理员只读
 *
 * 环境：stage5 编排（API 18081，网关 18080，应用 s5app / waf-s5.local）。
 * 说明：环境预置种子数据已包含全局黑 198.51.100.0/24、全局白 198.51.100.60、
 * 可信代理 docker-bridge(172.20.0.0/16)。用例2 的封禁 IP 选用 203.0.113.199
 * （任务书示例 198.51.100.199 已被种子全局黑 198.51.100.0/24 覆盖，
 * 无法归因于新建规则），流程与断言不变：基线放行 → 建规则 → 发布 → 403。
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'
const SYS_USER = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYS_PWD = process.env.E2E_SYSADMIN_PWD || 'SysAdmin@S5!2026'
const GATEWAY_URL = process.env.E2E_GATEWAY_URL || 'http://127.0.0.1:18080'
const HOST = process.env.E2E_HOST || 'waf-s5.local'
/** 网关连接源所在 docker 网段（须存在覆盖它的可信代理，XFF 才被信任） */
const DOCKER_CIDR = '172.20.0.0/16'

const rand = () => Math.random().toString(36).slice(2, 8)

async function csrfToken(page: Page): Promise<string> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  return ((await me.json())?.data?.csrf_token as string) || ''
}

/** 发布访问控制/CC配置到网关，轮询任务直至 SUCCESS（≤30s）。
 *  注意：配置版本号为 秒级时间戳+配置哈希，同一秒内发布相同配置（如清理后回到基线）
 *  会撞 version_number 唯一约束（SAVE_VERSION_FAILED duplicate key），跨秒重试即可。 */
async function publishAndWait(page: Page, kind: 'access-rules' | 'rate-limit-policies') {
  for (let attempt = 1; ; attempt++) {
    const csrf = await csrfToken(page)
    const resp = await page.request.post(`${API_URL}/${kind}/publish`, {
      data: { idempotency_key: `e2e-s5-${Date.now()}-${rand()}` },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(resp.status(), `publish ${kind}`).toBe(200)
    let task = (await resp.json())?.data
    expect(task?.id).toBeTruthy()
    const deadline = Date.now() + 30000
    while (task.status !== 'SUCCESS' && task.status !== 'FAILED' && Date.now() < deadline) {
      await page.waitForTimeout(500)
      const t = await page.request.get(`${API_URL}/publish-tasks/${task.id}`)
      task = (await t.json())?.data
    }
    const failure = `${task?.failure_code || ''} ${task?.failure_message || ''}`
    if (
      task?.status === 'FAILED' &&
      failure.includes('gateway_config_versions_version_number_key') &&
      attempt < 3
    ) {
      await page.waitForTimeout(1100) // 跨过版本号秒边界后重试
      continue
    }
    expect(task?.status, `publish task result: ${failure}`).toBe('SUCCESS')
    return
  }
}

/** 经网关发起请求（Host + 可选 X-Forwarded-For） */
function gwGet(page: Page, path: string, xff?: string) {
  const headers: Record<string, string> = { Host: HOST }
  if (xff) headers['X-Forwarded-For'] = xff
  return page.request.get(`${GATEWAY_URL}${path}`, { headers })
}

/** 确保存在覆盖 docker 网段的已启用可信代理（有则复用，无则 API 创建） */
async function ensureTrustedProxy(page: Page) {
  const list = await page.request.get(`${API_URL}/trusted-proxies?page=1&page_size=100`)
  expect(list.status()).toBe(200)
  const items = ((await list.json())?.data?.items || []) as Array<{
    id: string
    cidr: string
    status: string
  }>
  if (items.some((p) => p.cidr === DOCKER_CIDR && p.status === 'ENABLED')) return
  const csrf = await csrfToken(page)
  const resp = await page.request.post(`${API_URL}/trusted-proxies`, {
    data: {
      name: `e2e-tp-auto-${rand()}`,
      cidr: DOCKER_CIDR,
      header_type: 'X_FORWARDED_FOR',
      custom_header_name: '',
      priority: 50,
      scope: 'GLOBAL',
      node_name: '',
      description: 'E2E 自动确保 docker 网段可信代理',
    },
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status(), 'ensure trusted proxy').toBe(200)
}

interface CreatedRule {
  id: string
}

/** 创建 IP 访问控制规则（GLOBAL） */
async function createAccessRule(
  page: Page,
  input: { name: string; ruleType: 'ALLOW' | 'DENY'; address: string; reason: string },
): Promise<CreatedRule> {
  const csrf = await csrfToken(page)
  const resp = await page.request.post(`${API_URL}/access-rules`, {
    data: {
      name: input.name,
      rule_type: input.ruleType,
      scope_type: 'GLOBAL',
      address: input.address,
      validity_type: 'PERMANENT',
      reason: input.reason,
    },
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status(), `create access rule ${input.name}: ${await resp.text()}`).toBe(200)
  const rule = (await resp.json())?.data?.rule
  expect(rule?.id).toBeTruthy()
  return { id: rule.id as string }
}

async function deleteAccessRule(page: Page, id: string) {
  const csrf = await csrfToken(page)
  const resp = await page.request.delete(`${API_URL}/access-rules/${id}`, {
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status(), `delete access rule ${id}`).toBe(200)
}

/** 创建 CC 防护策略（GLOBAL + URI 前缀） */
async function createRateLimitPolicy(
  page: Page,
  input: {
    name: string
    uriPrefix: string
    requestsLimit: number
    burst: number
    action: 'REJECT' | 'TEMP_BLOCK'
    blockDurationSeconds?: number
  },
): Promise<string> {
  const csrf = await csrfToken(page)
  const resp = await page.request.post(`${API_URL}/rate-limit-policies`, {
    data: {
      name: input.name,
      description: 'E2E 阶段5',
      scope_type: 'GLOBAL',
      uri_match_type: 'PREFIX',
      uri_pattern: input.uriPrefix,
      dimension: 'CLIENT_IP',
      algorithm: 'TOKEN_BUCKET',
      requests_limit: input.requestsLimit,
      window_seconds: 60,
      burst_capacity: input.burst,
      action: input.action,
      block_duration_seconds: input.blockDurationSeconds ?? 0,
      observe_only: false,
      priority: 10,
    },
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status(), `create rate limit policy ${input.name}: ${await resp.text()}`).toBe(200)
  const policy = (await resp.json())?.data
  expect(policy?.id).toBeTruthy()
  return policy.id as string
}

async function deleteRateLimitPolicy(page: Page, id: string) {
  const csrf = await csrfToken(page)
  const resp = await page.request.delete(`${API_URL}/rate-limit-policies/${id}`, {
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status(), `delete rate limit policy ${id}`).toBe(200)
}

test.describe('阶段5：访问控制与CC防护', () => {
  test('可信代理：UI 新增、停用、启用', async ({ page }) => {
    const name = `e2e-tp-${rand()}`
    // 预置种子 docker-bridge 已占用 172.20.0.0/16（CIDR 唯一约束），使用随机 10.x 段
    const cidr = `10.${Math.floor(Math.random() * 200) + 10}.0.0/16`
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    try {
      await page.goto('/trusted-proxies')
      await expect(page).toHaveURL(/trusted-proxies/)
      await page.getByRole('button', { name: '新建可信代理' }).click()
      const drawer = page.locator('.ant-drawer')
      await expect(drawer).toBeVisible()
      await drawer.getByPlaceholder('如：办公网出口代理').fill(name)
      await drawer.getByPlaceholder('如 10.0.0.0/8 或 203.0.113.10').fill(cidr)
      // 真实IP提取头默认 X_FORWARDED_FOR，优先级默认 100 → 调整为 88
      await drawer.locator('#priority').fill('88')
      await drawer.getByRole('button', { name: /创 ?建/ }).click()
      // 列表出现新代理
      const row = page.locator('tr', { hasText: name })
      await expect(row).toBeVisible({ timeout: 10000 })
      await expect(row).toContainText(cidr)
      await expect(row).toContainText('88')
      // 停用 → 按钮变为 启用
      await row.getByRole('button', { name: /停 ?用/ }).click()
      await expect(row.getByRole('button', { name: /启 ?用/ })).toBeVisible({ timeout: 10000 })
      // 启用 → 按钮变回 停用
      await row.getByRole('button', { name: /启 ?用/ }).click()
      await expect(row.getByRole('button', { name: /停 ?用/ })).toBeVisible({ timeout: 10000 })
    } finally {
      // 清理：删除 UI 创建的代理
      const csrf = await csrfToken(page)
      const list = await page.request.get(
        `${API_URL}/trusted-proxies?keyword=${name}&page=1&page_size=10`,
      )
      const items = ((await list.json())?.data?.items || []) as Array<{ id: string }>
      for (const item of items) {
        await page.request.delete(`${API_URL}/trusted-proxies/${item.id}`, {
          headers: { 'X-CSRF-Token': csrf },
        })
      }
    }
  })

  test('黑名单：安全事件来源规则发布后网关 403', async ({ page }) => {
    const ip = '203.0.113.199'
    const name = `e2e-deny-${rand()}`
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureTrustedProxy(page)
    let ruleId = ''
    try {
      // 基线：该 IP 当前可正常通行（非 403）
      const before = await gwGet(page, '/', ip)
      expect(before.status(), 'baseline should not be blocked').not.toBe(403)
      // 创建 DENY 规则（reason 标注来源安全事件，对应“从事件创建黑名单”链路）
      const rule = await createAccessRule(page, {
        name,
        ruleType: 'DENY',
        address: ip,
        reason: `E2E 来源安全事件自动封禁（模拟事件 SEC-EVT-${rand()}）`,
      })
      ruleId = rule.id
      await publishAndWait(page, 'access-rules')
      // 网关验证：命中黑名单 403；无关 IP 不受影响
      const blocked = await gwGet(page, '/', ip)
      expect(blocked.status()).toBe(403)
      const other = await gwGet(page, '/', '203.0.113.111')
      expect(other.status()).not.toBe(403)
    } finally {
      if (ruleId) {
        await deleteAccessRule(page, ruleId)
        await publishAndWait(page, 'access-rules')
      }
    }
    // 清理后恢复放行
    const after = await gwGet(page, '/', ip)
    expect(after.status()).not.toBe(403)
  })

  test('白名单优先级：全局白覆盖全局黑', async ({ page }) => {
    const tag = rand()
    // 任务书示例网段 198.51.100.0/24 已被种子规则占用（同地址 DENY 冲突 409），
    // 改用未被种子覆盖的 203.0.113.0/24，断言完全归因于本用例创建的规则
    const denyCidr = '203.0.113.0/24'
    const allowIp = '203.0.113.60'
    const deniedIp = '203.0.113.51'
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureTrustedProxy(page)
    // 基线：两个 IP 当前均可通行
    expect((await gwGet(page, '/', allowIp)).status()).not.toBe(403)
    expect((await gwGet(page, '/', deniedIp)).status()).not.toBe(403)
    const ids: string[] = []
    try {
      ids.push(
        (
          await createAccessRule(page, {
            name: `e2e-gd-${tag}`,
            ruleType: 'DENY',
            address: denyCidr,
            reason: 'E2E 全局黑网段',
          })
        ).id,
        (
          await createAccessRule(page, {
            name: `e2e-ga-${tag}`,
            ruleType: 'ALLOW',
            address: allowIp,
            reason: 'E2E 全局白名单（优先于黑名单）',
          })
        ).id,
      )
      await publishAndWait(page, 'access-rules')
      // 白名单内 IP 放行（非 403），网段内其他 IP 403
      const allowed = await gwGet(page, '/', allowIp)
      expect(allowed.status()).not.toBe(403)
      const denied = await gwGet(page, '/', deniedIp)
      expect(denied.status()).toBe(403)
    } finally {
      for (const id of ids) await deleteAccessRule(page, id)
      if (ids.length > 0) await publishAndWait(page, 'access-rules')
    }
    // 清理后网段恢复放行
    expect((await gwGet(page, '/', deniedIp)).status()).not.toBe(403)
  })

  test('CC策略：REJECT 超限返回 429', async ({ page }) => {
    const name = `e2e-cc-${rand()}`
    const ip = '203.0.113.111'
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureTrustedProxy(page)
    let policyId = ''
    try {
      policyId = await createRateLimitPolicy(page, {
        name,
        uriPrefix: '/e2e-cc/',
        requestsLimit: 3,
        burst: 3,
        action: 'REJECT',
      })
      await publishAndWait(page, 'rate-limit-policies')
      // 同 IP 连续 5 次：前 3 次非 429，第 4、5 次 429
      const statuses: number[] = []
      for (let i = 0; i < 5; i++) {
        const resp = await gwGet(page, '/e2e-cc/ping', ip)
        statuses.push(resp.status())
      }
      expect(statuses[0], `statuses=${statuses}`).not.toBe(429)
      expect(statuses[1]).not.toBe(429)
      expect(statuses[2]).not.toBe(429)
      expect(statuses[3]).toBe(429)
      expect(statuses[4]).toBe(429)
    } finally {
      if (policyId) {
        await deleteRateLimitPolicy(page, policyId)
        await publishAndWait(page, 'rate-limit-policies')
      }
    }
  })

  test('临时封禁：CC 触发封禁 403，解封后恢复', async ({ page }) => {
    test.setTimeout(90000)
    const name = `e2e-tb-${rand()}`
    const ip = '203.0.113.112'
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureTrustedProxy(page)
    let policyId = ''
    try {
      policyId = await createRateLimitPolicy(page, {
        name,
        uriPrefix: '/e2e-tb/',
        requestsLimit: 2,
        burst: 2,
        action: 'TEMP_BLOCK',
        blockDurationSeconds: 600,
      })
      await publishAndWait(page, 'rate-limit-policies')
      // 前 2 次放行，第 3 次超限 429 并触发临时封禁，第 4 次命中封禁 403
      const s1 = (await gwGet(page, '/e2e-tb/x', ip)).status()
      const s2 = (await gwGet(page, '/e2e-tb/x', ip)).status()
      const s3 = (await gwGet(page, '/e2e-tb/x', ip)).status()
      const s4 = (await gwGet(page, '/e2e-tb/x', ip)).status()
      expect(s1, `s1..s4=${[s1, s2, s3, s4]}`).not.toBe(429)
      expect(s1).not.toBe(403)
      expect(s2).not.toBe(429)
      expect(s2).not.toBe(403)
      expect(s3).toBe(429)
      expect(s4).toBe(403)
      // 管理端出现 ACTIVE 封禁记录（采集器约 2s 一轮）
      let blockId = ''
      const deadline = Date.now() + 20000
      while (!blockId && Date.now() < deadline) {
        const list = await page.request.get(
          `${API_URL}/temporary-blocks?status=ACTIVE&client_ip=${ip}&page=1&page_size=10`,
        )
        expect(list.status()).toBe(200)
        const items = ((await list.json())?.data?.items || []) as Array<{ id: string }>
        if (items.length > 0) blockId = items[0].id
        else await page.waitForTimeout(1000)
      }
      expect(blockId, 'ACTIVE temporary block not found').toBeTruthy()
      // 人工解封 → 网关轮询（1s）后不再 403（CC 窗口仍在，允许 429/404/200）
      const csrf = await csrfToken(page)
      const rel = await page.request.post(`${API_URL}/temporary-blocks/${blockId}/release`, {
        headers: { 'X-CSRF-Token': csrf },
      })
      expect(rel.status()).toBe(200)
      await page.waitForTimeout(3000)
      const after = await gwGet(page, '/e2e-tb/x', ip)
      expect(after.status()).not.toBe(403)
    } finally {
      // 清理：释放该 IP 残留的 ACTIVE 封禁（解封后的验证请求会再次触发封禁；
      // 采集器约 2s 一轮且可能延迟落库，在固定窗口内轮询释放直至无残留），
      // 删除策略并发布
      const csrf = await csrfToken(page)
      const cleanupDeadline = Date.now() + 12000
      while (Date.now() < cleanupDeadline) {
        const list = await page.request.get(
          `${API_URL}/temporary-blocks?status=ACTIVE&client_ip=${ip}&page=1&page_size=20`,
        )
        const items = ((await list.json())?.data?.items || []) as Array<{ id: string }>
        for (const b of items) {
          await page.request.post(`${API_URL}/temporary-blocks/${b.id}/release`, {
            headers: { 'X-CSRF-Token': csrf },
          })
        }
        if (Date.now() < cleanupDeadline) await page.waitForTimeout(1000)
      }
      if (policyId) {
        await deleteRateLimitPolicy(page, policyId)
        await publishAndWait(page, 'rate-limit-policies')
      }
    }
  })

  test('审计管理员：阶段5列表只读、写操作拒绝', async ({ page }) => {
    // 系统管理员创建 AUDIT_ADMIN 用户（随机名）
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    const username = `e2e_audit_${rand()}`
    const { password: tempPwd } = await createUserViaAPI(page, username, 'AUDIT_ADMIN')
    const newPwd = 'AuditAdmin@E2E2026!'
    await loginViaAPI(page, username, tempPwd)
    await changePasswordViaAPI(page, tempPwd, newPwd)
    await page.context().clearCookies()
    await loginViaAPI(page, username, newPwd)

    // 5 个阶段5列表全部可读
    for (const ep of [
      'trusted-proxies',
      'access-rules',
      'rate-limit-policies',
      'temporary-blocks',
      'access-control-events',
    ]) {
      const resp = await page.request.get(`${API_URL}/${ep}?page=1&page_size=5`)
      expect(resp.status(), `audit admin GET ${ep}`).toBe(200)
    }
    // 写操作全部 403
    const csrf = await csrfToken(page)
    const headers = { 'X-CSRF-Token': csrf }
    const tp = await page.request.post(`${API_URL}/trusted-proxies`, {
      data: {
        name: `audit-forbidden-${rand()}`,
        cidr: '192.0.2.1',
        header_type: 'X_FORWARDED_FOR',
        custom_header_name: '',
        priority: 100,
        scope: 'GLOBAL',
        node_name: '',
        description: '',
      },
      headers,
    })
    expect(tp.status(), 'audit admin POST trusted-proxies').toBe(403)
    const ar = await page.request.post(`${API_URL}/access-rules`, {
      data: {
        name: `audit-forbidden-${rand()}`,
        rule_type: 'DENY',
        scope_type: 'GLOBAL',
        address: '192.0.2.9',
        validity_type: 'PERMANENT',
        reason: 'x',
      },
      headers,
    })
    expect(ar.status(), 'audit admin POST access-rules').toBe(403)
    const rl = await page.request.post(`${API_URL}/rate-limit-policies`, {
      data: {
        name: `audit-forbidden-${rand()}`,
        description: '',
        scope_type: 'GLOBAL',
        uri_match_type: 'ALL',
        uri_pattern: '',
        dimension: 'CLIENT_IP',
        algorithm: 'TOKEN_BUCKET',
        requests_limit: 100,
        window_seconds: 60,
        burst_capacity: 0,
        action: 'REJECT',
        block_duration_seconds: 0,
        observe_only: false,
        priority: 10,
      },
      headers,
    })
    expect(rl.status(), 'audit admin POST rate-limit-policies').toBe(403)
  })
})
