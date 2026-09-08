import { test, expect, type Page } from '@playwright/test'
import Redis from 'ioredis'
import { loginViaAPI, createUserViaAPI, changePasswordViaAPI, API_URL } from './helpers'

/**
 * JWT-15 E2E：JWT 信任策略（WDSP P0-03）页面关键流程的状态可见性
 * （docs/tasks/wdsp-p0/P0-03_JWT_TRUST_CHAIN.md §10 验收用例 JWT-15 的管理面页面子集）
 *
 * 覆盖：新建应用空态「未配置」→ 保存 OBSERVE 草稿（草稿待发布、未生效）→ 静态 JWKS
 * 私钥粘贴即时拒收 → 发布预检结果可见 → 审计管理员只读/无权限 → 安全事件详情 JWT 验证区块。
 * 发布与回退为网关侧链路（走既有 gateway-config 发布通道），不在本 UI 规格内。
 *
 * 环境依赖（与 stage5/stage8 spec 一致）：
 * - stage5 编排：管理 API 127.0.0.1:18081，前端 vite dev 5173（/api 代理，baseURL 可用
 *   E2E_BASE_URL 覆盖）；Valkey 供验证码读取（VALKEY_HOST/PORT/PASSWORD/DB）。
 * - 安全管理员 sec_admin_s5（E2E_SEC_USER/E2E_SEC_PWD 覆盖）；系统管理员 jiuzhang_admin
 *   （E2E_SYSADMIN_USER/E2E_SYSADMIN_PWD 覆盖）用于现场创建审计管理员。
 * - JWT 信任策略管理面路由无条件注册、页签按 jwt_trust.read 权限挂载，不依赖 WDSP 形态开关；
 *   预检「API 管线门禁」在非 WDSP 形态为「警告」，不阻断 OBSERVE 草稿保存与预检。
 * - 用例「事件详情」依赖环境中存在携带 jwt_verification 的安全事件；当前 security_events
 *   唯一来源为 Coraza 审计日志（恒不携带 JWT 数据，见 server/internal/securityevents/normalize.go），
 *   JWT 处置事件落 access_control_events / api_runtime_events（迁移 000127），故常规环境下
 *   该用例扫描最近事件后跳过并以 annotations 记录原因，不伪造事件。
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'
const SYS_USER = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYS_PWD = process.env.E2E_SYSADMIN_PWD || 'SysAdmin@S5!2026'

const rand = () => Math.random().toString(36).slice(2, 8)

/**
 * 固定测试公钥材料（仅公钥 n/e，无私钥）：2048 位 RSA，与跨模块共享测试向量同源
 * （server/internal/jwttrust/jwks_test.go jwksParityVector 的 RSA 公钥）。
 */
const TEST_RSA_PUBLIC_N =
  '2qdfkJaiGwLLMwTefJ0WiqpKieWuiU6y3heFT1BBLKdFnqSK8_mMJ6s3fmeGKsZr6q11F_ZfafCtvc9Q1mlg8fIKqr2IDiUBgiADHIYIKV6ym8zt8ybTIU_mtcSlo4oOSd8fCaJ_fFrhTZGEd8inHekOpcu60IF_AlZPuNSzhMNL4KfRwob1TfiwIX9AusLHYuu3wD_yAUH3e4LnAwqZLJ9qh_YX9kTRp28mr_wxZi60S1deGT6mqYOzDvfV7Y_DZuXQWalhu9eJMV2iG1ryeJkHUL8ACNO1B0T8JjTWRlUNck-Gmvw3KZEZbR4VjwgtyjhjZsn5Did0lt7jeS2qmQ'

const TEST_RSA_JWKS = `{"keys":[{"kty":"RSA","kid":"e2e-jwt-rsa-1","alg":"RS256","n":"${TEST_RSA_PUBLIC_N}","e":"AQAB"}]}`

/** 含私钥参数 "d" 的 JWKS（同一公钥 + 伪造私参；粘贴即时拒收按参数存在性检测，不要求合法取值） */
const PRIVATE_MATERIAL_JWKS = `{"keys":[{"kty":"RSA","kid":"e2e-jwt-priv-1","alg":"RS256","n":"${TEST_RSA_PUBLIC_N}","e":"AQAB","d":"e2e-fake-private-material"}]}`

/** 静态公钥 JWKS 输入框占位文案（web/src/pages/applications/detail/JwtTrustTab.tsx） */
const JWKS_PLACEHOLDER = '{"keys":[{"kty":"RSA","kid":"...","n":"...","e":"AQAB"}]}'

async function csrfToken(page: Page): Promise<string> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  return ((await me.json())?.data?.csrf_token as string) || ''
}

/** 创建最小要素测试应用（不启用不发布；JWT 策略管理与域名/发布无关），返回 id/code */
async function createApp(page: Page): Promise<{ id: string; code: string }> {
  const csrf = await csrfToken(page)
  const code = `e2e-jwt-${rand()}`
  const resp = await page.request.post(`${API_URL}/applications`, {
    data: { code, name: `E2E JWT信任策略 ${code}`, protection_mode: 'OFF' },
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status(), `create application ${code}: ${await resp.text()}`).toBe(200)
  const id = ((await resp.json())?.data?.id as string) || ''
  expect(id, 'application id').toBeTruthy()
  return { id, code }
}

/** 清理测试应用（逻辑删除；本规格应用从未发布，满足删除前置条件） */
async function deleteApp(page: Page, id: string) {
  const csrf = await csrfToken(page)
  const resp = await page.request.delete(`${API_URL}/applications/${id}`, {
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status(), `delete application ${id}`).toBe(200)
}

/** 打开应用详情并切到「JWT 信任策略」页签，等待策略状态卡渲染完成 */
async function openJwtTrustTab(page: Page, appId: string) {
  await page.goto(`/applications/${appId}`)
  await page.getByRole('tab', { name: 'JWT 信任策略' }).click()
  await expect(page.locator('.ant-card-head-title', { hasText: '策略状态' })).toBeVisible({
    timeout: 10000,
  })
}

/** 「策略状态」卡中的描述项（按 label 定位，文案见 JwtTrustTab.tsx Descriptions） */
function statusItem(page: Page, label: string) {
  return page
    .locator('.ant-descriptions-item')
    .filter({ has: page.locator('.ant-descriptions-item-label', { hasText: label }) })
}

/**
 * 填写合法 OBSERVE 草稿表单（保存与预检共用）：
 * 选择器 path_prefix=/api + token_required=true（方法默认 GET）；发行方 issuer/audience/
 * 算法 RS256（添加发行方表单缺省）+ 静态公钥 JWKS；变更理由必填。
 */
async function fillObserveDraftForm(page: Page) {
  await page.locator('.ant-radio-wrapper', { hasText: '观察（校验并记录，不拦截）' }).click()
  // 校验范围（选择器）
  await page.getByRole('button', { name: '添加选择器' }).click()
  await page.getByPlaceholder('如 /api/orders').fill('/api')
  const tokenSwitch = page.getByRole('switch')
  await tokenSwitch.click()
  await expect(tokenSwitch).toBeChecked()
  // 受信发行方
  await page.getByRole('button', { name: '添加发行方' }).click()
  await page.getByPlaceholder('如 https://idp.example.com/').fill('https://idp.e2e.example.com/')
  const audItem = page.locator('.ant-form-item', { has: page.locator('label[title="Audiences"]') })
  // antd v6 Select（@rc-component/select）tags 模式的搜索输入无 selection-search-input 类，
  // 以 role="combobox" 暴露；Enter 在 open={false} 下经 onSearchSubmit 生成标签
  const audInput = audItem.getByRole('combobox')
  await audInput.click()
  await audInput.fill('e2e-audience')
  await audInput.press('Enter')
  await expect(
    audItem.locator('.ant-select-selection-item', { hasText: 'e2e-audience' }),
  ).toBeVisible()
  const algItem = page.locator('.ant-form-item', { has: page.locator('label[title="算法白名单"]') })
  await expect(algItem.locator('.ant-select-selection-item')).toContainText('RS256')
  await page.getByPlaceholder(JWKS_PLACEHOLDER).fill(TEST_RSA_JWKS)
  await page
    .getByPlaceholder('说明本次变更原因，如：接入新的身份发行方')
    .fill('E2E JWT-15：接入测试发行方（观察模式草稿）')
}

test.describe('JWT-15：JWT 信任策略页面流程', () => {
  // 验证码/登录共用按 IP 限流桶（默认 10 次/分钟；system_settings 校验上限 10000，
  // global-setup 提额到 100000 被后端 400 拒绝），连跑时后续用例易撞限，逐用例前清空
  test.beforeEach(async () => {
    const r = new Redis({
      host: process.env.VALKEY_HOST || '127.0.0.1',
      port: Number(process.env.VALKEY_PORT || 6379),
      password: process.env.VALKEY_PASSWORD || 'CHANGE_ME_STRONG_PASSWORD',
      db: Number(process.env.VALKEY_DB || 0),
    })
    try {
      const keys = await r.keys('jiuzhang:ratelimit:*')
      if (keys.length > 0) await r.del(...keys)
    } finally {
      r.disconnect()
    }
  })

  /* ==================== 1. 新建应用 → 空态「未配置」 ==================== */

  test('新建应用空态：未配置/默认关闭与版本字段可见', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page)
    try {
      await openJwtTrustTab(page, app.id)
      await expect(statusItem(page, '应用范围')).toContainText(app.code)
      await expect(statusItem(page, '配置状态').locator('.ant-tag')).toHaveText('未配置')
      await expect(statusItem(page, '当前模式').locator('.ant-tag')).toHaveText('关闭')
      await expect(statusItem(page, '草稿版本')).toContainText('无草稿')
      await expect(statusItem(page, '已生效版本')).toContainText('未随发布下发')
      await expect(
        page.locator('.ant-alert', { hasText: '尚未配置 JWT 信任策略，当前不校验业务 Token' }),
      ).toBeVisible()
      // 安全管理员持有 jwt_trust.manage：操作入口可见
      await expect(page.getByRole('button', { name: '发布预检' })).toBeVisible()
      await expect(page.getByRole('button', { name: '保存草稿' })).toBeVisible()
    } finally {
      await deleteApp(page, app.id)
    }
  })

  /* ==================== 2. 保存 OBSERVE 草稿 → 草稿待发布（未生效） ==================== */

  test('保存 OBSERVE 草稿：提示草稿已保存且状态为草稿待发布（未生效）', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page)
    try {
      await openJwtTrustTab(page, app.id)
      await fillObserveDraftForm(page)
      await page.getByRole('button', { name: '保存草稿' }).click()
      // 保存反馈（逐字，JwtTrustTab.tsx message.success）
      await expect(
        page.getByText('草稿已保存；发布并获节点回执后才会生效', { exact: true }),
      ).toBeVisible({ timeout: 10000 })
      // 状态卡：草稿待发布、当前模式观察中、草稿 v1、已生效版本仍未下发
      await expect(statusItem(page, '配置状态').locator('.ant-tag')).toHaveText('草稿待发布', {
        timeout: 10000,
      })
      await expect(statusItem(page, '当前模式').locator('.ant-tag')).toHaveText('观察中')
      await expect(statusItem(page, '草稿版本')).toContainText('v1')
      await expect(statusItem(page, '已生效版本')).toContainText('未随发布下发')
      await expect(page.locator('.ant-alert', { hasText: '草稿已保存，尚未生效' })).toBeVisible()
      // 保存草稿不等于线上生效：不得出现「已生效」提示
      await expect(page.locator('.ant-alert', { hasText: '已生效：' })).toHaveCount(0)
    } finally {
      await deleteApp(page, app.id)
    }
  })

  /* ==================== 3. 静态 JWKS 粘贴私钥 → 立即拒绝且不回显 ==================== */

  test('静态 JWKS 粘贴私钥材料：立即拒绝并清空，不回显已粘贴内容', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page)
    try {
      await openJwtTrustTab(page, app.id)
      await page.getByRole('button', { name: '添加发行方' }).click()
      const jwksInput = page.getByPlaceholder(JWKS_PLACEHOLDER)
      await jwksInput.fill(PRIVATE_MATERIAL_JWKS)
      // 前端粘贴即时校验（逐字，JwtTrustTab.tsx onJwksChange message.error）
      await expect(
        page.getByText(
          '检测到私钥或对称密钥材料（"d"/"p"/"q" 等私钥参数或 "kty":"oct"），已拒绝并清空输入；静态 JWKS 仅允许公钥',
          { exact: true },
        ),
      ).toBeVisible({ timeout: 10000 })
      // 不回显已粘贴内容：输入框被清空
      await expect(jwksInput).toHaveValue('')
    } finally {
      await deleteApp(page, app.id)
    }
  })

  /* ==================== 4. 发布预检 → 结果区域可见 ==================== */

  test('发布预检：结果区域列出各检查项及状态', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page)
    try {
      await openJwtTrustTab(page, app.id)
      // 未点击前不渲染结果区域
      await expect(page.locator('.ant-card-head-title', { hasText: '发布预检结果' })).toHaveCount(0)
      await fillObserveDraftForm(page)
      await page.getByRole('button', { name: '发布预检' }).click()
      await expect(page.locator('.ant-card-head-title', { hasText: '发布预检结果' })).toBeVisible({
        timeout: 15000,
      })
      // 各检查项及状态标签（名称逐字，utils/jwtTrust.ts JWT_TRUST_CHECK_NAME_LABELS）
      for (const label of [
        '结构与公钥',
        '远程地址 SSRF',
        '远程连通性（管理端）',
        'API 管线门禁',
        '节点状态与能力',
      ]) {
        const item = page.locator('.ant-list-item', { hasText: label })
        await expect(item, `预检检查项 ${label}`).toBeVisible()
        await expect(item.locator('.ant-tag')).toBeVisible()
      }
      // 合法静态公钥 → 结构与公钥「通过」；纯静态 JWKS → 远程地址项「跳过」
      await expect(
        page.locator('.ant-list-item', { hasText: '结构与公钥' }).locator('.ant-tag'),
      ).toHaveText('通过')
      await expect(
        page.locator('.ant-list-item', { hasText: '远程地址 SSRF' }).locator('.ant-tag'),
      ).toHaveText('跳过')
      // 预检口径说明：不保存、不发布
      await expect(page.getByText(/预检不保存、不发布/)).toBeVisible()
    } finally {
      await deleteApp(page, app.id)
    }
  })

  /* ==================== 5/7. 审计管理员：只读与无权限（真实 403，不 mock） ==================== */

  test('审计管理员：策略 API 可读、写与预检 403；应用详情路由跳无权限页', async ({ page }) => {
    // 安全管理员先建应用
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const app = await createApp(page)
    try {
      // 系统管理员现场创建 AUDIT_ADMIN 用户并完成首次改密（同 stage5/stage8 惯例）
      await loginViaAPI(page, SYS_USER, SYS_PWD)
      const username = `e2e_audit_${rand()}`
      const { password: tempPwd } = await createUserViaAPI(page, username, 'AUDIT_ADMIN')
      const newPwd = 'AuditAdmin@Jwt2026!'
      await loginViaAPI(page, username, tempPwd)
      await changePasswordViaAPI(page, tempPwd, newPwd)
      await page.context().clearCookies()
      await loginViaAPI(page, username, newPwd)

      // API 层只读：jwt_trust.read 三角色全授（迁移 000126）→ 可读策略
      const getResp = await page.request.get(`${API_URL}/applications/${app.id}/jwt-trust-policy`)
      expect(getResp.status(), 'audit admin GET jwt-trust-policy').toBe(200)
      // 写与预检需 jwt_trust.manage（仅 SYSTEM_ADMIN/SECURITY_ADMIN）→ 403
      const csrf = await csrfToken(page)
      const headers = { 'X-CSRF-Token': csrf }
      const putResp = await page.request.put(`${API_URL}/applications/${app.id}/jwt-trust-policy`, {
        data: {
          mode: 'OBSERVE',
          expected_version: 0,
          selectors: [],
          issuers: [],
          reason: 'audit admin 越权写尝试',
        },
        headers,
      })
      expect(putResp.status(), 'audit admin PUT jwt-trust-policy').toBe(403)
      const preflightResp = await page.request.post(
        `${API_URL}/applications/${app.id}/jwt-trust-policy/preflight`,
        { data: {}, headers },
      )
      expect(preflightResp.status(), 'audit admin POST preflight').toBe(403)

      // UI 层：应用详情路由由 RequirePermission("applications.read") 守卫，审计管理员持
      // applications.read_audit → 直访应用详情（含 JWT 页签）跳 /403 无权限页。
      // 注：页签内「只读态（无保存/预检按钮）」的 UI 显隐由组件测试覆盖
      // （web/src/pages/applications/__tests__/JwtTrustTab.test.tsx 只读权限用例），
      // E2E 无法以内置角色到达该状态（无「applications.read + jwt_trust.read 但无 manage」角色）。
      await page.goto(`/applications/${app.id}`)
      await expect(page).toHaveURL(/\/403/, { timeout: 10000 })
      await expect(page.getByText('无访问权限')).toBeVisible()
      await expect(page.getByText('您没有访问该页面的权限，请联系系统管理员。')).toBeVisible()
    } finally {
      await loginViaAPI(page, SEC_USER, SEC_PWD)
      await deleteApp(page, app.id)
    }
  })

  /* ==================== 6. 事件详情：JWT 验证信息区块（无事件则跳过并记录） ==================== */

  test('事件详情：携带 jwt_verification 的事件展示 JWT 验证区块', async ({ page }) => {
    test.setTimeout(90000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    // 列表项不含 jwt_verification，需逐条取详情判定（扫描上限 50 条）
    let hit: { id: string; requestId: string } | null = null
    const list = await page.request.get(`${API_URL}/security-events?page=1&page_size=50`)
    expect(list.status(), 'list security events').toBe(200)
    const items = ((await list.json())?.data?.items ?? []) as Array<{
      id: string
      request_id: string
    }>
    for (const item of items) {
      const resp = await page.request.get(`${API_URL}/security-events/${item.id}`)
      if (resp.status() !== 200) continue
      const evt = (await resp.json())?.data?.event as
        | { jwt_verification?: { status?: string } | null }
        | undefined
      if (evt?.jwt_verification) {
        hit = { id: item.id, requestId: item.request_id }
        break
      }
    }
    if (!hit) {
      const reason =
        '最近 50 条安全事件详情均未携带 jwt_verification（当前 security_events 唯一来源为 Coraza 审计日志，' +
        '恒不携带 JWT 数据；JWT 处置事件落 access_control_events / api_runtime_events，迁移 000127）。' +
        '按任务要求不伪造事件，跳过 UI 区块断言。'
      test.info().annotations.push({ type: 'skip-reason', description: reason })
      test.skip(true, reason)
      return
    }
    // 打开安全事件页，按请求 ID 过滤定位该事件并打开详情抽屉
    await page.goto('/security-events')
    await page.getByPlaceholder('请求 ID').fill(hit.requestId)
    await page.keyboard.press('Enter')
    const rows = page.locator('.ant-table-tbody tr.ant-table-row')
    await expect(rows).toHaveCount(1, { timeout: 10000 })
    await rows.first().getByRole('button', { name: '详情' }).click()
    // JWT 验证信息区块（EventDetailDrawer.tsx）：标题恒定渲染，
    // 「验证状态/原因/策略版本/可信主体指纹」仅当事件携带 jwt_verification 时渲染
    const drawer = page.locator('.ant-drawer', { hasText: '安全事件详情' })
    await expect(drawer).toBeVisible({ timeout: 10000 })
    await expect(drawer.getByText('JWT 验证信息', { exact: true })).toBeVisible()
    for (const label of ['验证状态', '原因', '策略版本', '可信主体指纹']) {
      await expect(
        drawer.locator('.ant-descriptions-item-label', { hasText: label }),
      ).toBeVisible()
    }
  })
})
