import { test, expect, type Page } from '@playwright/test'
import { execSync } from 'node:child_process'
import { createPrivateKey, createSign } from 'node:crypto'
import { loginViaAPI, API_URL } from './helpers'

/**
 * NG-AZ-04 管理向导 E2E（D9 五场景）：态势六要素 / 向导五步全流 / 能力门阻塞提示 /
 * jiuzhang_admin 越权 / VERIFIED_VIOLATION 决策详情证据区块。
 *
 * 环境依赖（与既有 spec 一致）：stage5 编排（API 18081、网关 18080、Valkey 验证码）；
 * az4app fixture（PROTECT 模式应用 + tenants 对象模型 + OWNER 关系 + JWT 策略 STATIC_JWKS，
 * 由集成批预置；E2E 临时密钥与策略注册同源，现场还原后失效）。
 * 场景③需操作 stage5 网关节点能力清单（docker exec 改 az/2 自报模拟旧节点，用毕恢复）。
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'
const SYS_USER = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYS_PWD = process.env.E2E_SYSADMIN_PWD || 'SysAdmin@S5!2026'

const GATEWAY_URL = process.env.E2E_GATEWAY_URL || 'http://127.0.0.1:18080'
const AZ4_HOST = 'az4-s5.local'
const AZ4_APP_LABEL = 'az4app'
const TENANTS_ROW = 'GET /api/v1/tenants/{id}/projects/p002/items'
const ORDERS_ROW = 'GET /v1/az4/orders/{id}'

/** E2E 临时 ES256 密钥（与 stage5 az4app jwt_trust STATIC_JWKS 注册公钥同源） */
const E2E_PRIVATE_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'PubnIVrTrCnQ0Ntd4Dsb8CaCiMnNWdHZlwyVNHg87AQ',
  y: 'WWv_vKPhq7qUIKvxMxSfwMRUamUj_XgjRmp_N-Q337M',
  d: 'c6ASaWp7_upgpOkc8lXu4LkaOtuYTAh-3Q2xKR1MmqI',
  kid: 'az4-k1',
  alg: 'ES256',
}
const E2E_ISS = 'https://az4-e2e-issuer.example.com'

const b64u = (b: Buffer | string) =>
  (typeof b === 'string' ? Buffer.from(b) : b).toString('base64url')

/** node:crypto 手写 ES256 JWT（与网关 jwtverify 同形态；E2E 临时材料） */
function mintJWT(sub: string, roles: string[]): string {
  const header = b64u(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'az4-k1' }))
  const now = Math.floor(Date.now() / 1000)
  const payload = b64u(
    JSON.stringify({ iss: E2E_ISS, aud: 'az4app', sub, iat: now - 60, nbf: now - 60, exp: now + 7200, roles }),
  )
  const key = createPrivateKey({ key: E2E_PRIVATE_JWK, format: 'jwk' })
  const sig = createSign('SHA256').update(`${header}.${payload}`).sign({ key, dsaEncoding: 'ieee-p1363' })
  return `${header}.${payload}.${b64u(sig)}`
}

async function csrfToken(page: Page): Promise<string> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  return ((await me.json())?.data?.csrf_token as string) || ''
}

async function apiJSON(page: Page, method: string, path: string, body?: unknown) {
  const csrf = await csrfToken(page)
  const resp = await page.request.fetch(`${API_URL}${path}`, {
    method,
    data: body,
    headers: { 'X-CSRF-Token': csrf },
  })
  const json = await resp.json().catch(() => ({}))
  return { status: resp.status(), json }
}

/** 发布并轮询终态（返回 status/failure_code/failure_message；LOCK_BUSY 退避沿用 s5_publish 惯例） */
async function publishAndWait(page: Page): Promise<{ status: string; code: string; message: string }> {
  for (let attempt = 0; attempt < 6; attempt++) {
    const created = await apiJSON(page, 'POST', '/gateway-config/publish', { idempotency_key: `e2e-az4-${Date.now()}` })
    const taskId = created.json?.data?.id as string
    if (!taskId) throw new Error(`publish create failed: ${JSON.stringify(created.json)}`)
    for (let i = 0; i < 40; i++) {
      const t = await apiJSON(page, 'GET', `/publish-tasks/${taskId}`)
      const d = t.json?.data ?? {}
      if (d.status === 'SUCCESS') return { status: 'SUCCESS', code: '', message: '' }
      if (d.status === 'FAILED') {
        const code = (d.failure_code as string) || ''
        const message = (d.failure_message as string) || ''
        if (code === 'LOCK_BUSY') break
        return { status: 'FAILED', code, message }
      }
      await new Promise((r) => setTimeout(r, 1000))
    }
  }
  return { status: 'FAILED', code: 'TIMEOUT', message: 'publish polling timeout' }
}

/** 对象模型行查询（endpoint_key+object_segment 双键——同端点多行消歧） */
async function findObjectModelId(page: Page, endpointKey: string, objectSegment: string): Promise<string> {
  const r = await apiJSON(page, 'GET', `/api-security/object-models?page_size=100&object_segment=${encodeURIComponent(objectSegment)}`)
  const items = (r.json?.data?.items ?? []) as { id: string; endpoint_key?: string; object_segment?: string }[]
  const hit = items.find((i) => i.endpoint_key === endpointKey && i.object_segment === objectSegment)
  if (!hit) throw new Error(`object model not found: ${endpointKey} ${objectSegment}`)
  return hit.id
}

/** PATCH 切回 OBSERVE（免 confirm_token） */
async function resetToObserve(page: Page, endpointKey: string) {
  const id = await findObjectModelId(page, endpointKey, 'path:3')
  const r = await apiJSON(page, 'PATCH', `/api-security/object-models/${id}`, { enforcement: 'OBSERVE' })
  if (r.json?.code !== 'SUCCESS') throw new Error(`reset observe failed: ${JSON.stringify(r.json)}`)
}

/** 改节点能力清单 authzdecide 版本并刷新 generated_at（模拟旧/新节点自报） */
function setNodeAzVersion(version: 'az/2' | 'az/3') {
  // 读清单 JSON → 改 detectors+generated_at → stdin 写回（零 sed/引号嵌套）
  const raw = execSync('docker exec jiuzhang-stage5-gateway cat /run/caddy/sidecars/capability.json', { encoding: 'utf-8' })
  const manifest = JSON.parse(raw) as { detectors: { name: string; version: string }[]; generated_at?: string }
  for (const d of manifest.detectors) if (d.name === 'authzdecide') d.version = version
  manifest.generated_at = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
  execSync(
    'docker exec -i jiuzhang-stage5-gateway sh -c "cat > /run/caddy/sidecars/.cap.tmp && mv /run/caddy/sidecars/.cap.tmp /run/caddy/sidecars/capability.json"',
    { input: JSON.stringify(manifest, null, 2), encoding: 'utf-8' },
  )
}

/** 态势 Tab 打开并选 az4app */
async function openPostureTab(page: Page) {
  await page.goto('/api-authz')
  await page.getByRole('tab', { name: '态势与实断资格' }).click()
  // 应用选择器（AntD Select 的 placeholder 渲染为 div 非 input 属性——按容器文本定位；
  // 选项在下拉弹出层 .ant-select-item）
  const sel = page.locator('.ant-select', { hasText: '选择应用后查看态势与实断资格' })
  await sel.click()
  await sel.locator('input').fill('az4')
  await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item', { hasText: AZ4_APP_LABEL }).first().click()
}

/** 对象授权 Tab 选 az4app（未选应用时内层 Tabs 不渲染；showSearch 输入过滤后回车选中） */
async function selectAppInObjectAuthz(page: Page) {
  const sel = page.locator('.ant-select', { hasText: '选择应用后查看对象授权' })
  await sel.click()
  await sel.locator('input').fill('az4')
  await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item', { hasText: AZ4_APP_LABEL }).first().click()
}

/** 向导从态势表行进入（endpoint_key+object_segment 双过滤——同端点多对象模型行消歧） */
async function openWizardFromRow(page: Page, endpointKey: string, objectSegment: string) {
  const row = page
    .getByRole('row')
    .filter({ hasText: endpointKey })
    .filter({ hasText: objectSegment })
    .first()
  await row.getByRole('button', { name: '切换 PROTECT' }).click()
  const drawer = page.getByRole('dialog', { name: '切换 PROTECT（实断）' })
  await expect(drawer).toBeVisible()
  return drawer
}

test.describe.configure({ mode: 'serial' })

test.describe('NG-AZ-04 管理向导 E2E（D9 五场景）', () => {
  test.beforeEach(async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
  })

  test('① 态势 Tab 六要素展示（readiness 徽章/关系来源与最后同步/冲突/节点 ACK）', async ({ page }) => {
    await openPostureTab(page)
    // 统计卡（六要素量化面）
    await expect(page.getByText('已确认关系').first()).toBeVisible()
    await expect(page.getByText('OPEN 冲突').first()).toBeVisible()
    await expect(page.getByText('节点 ACK（FRESH/全部）')).toBeVisible()
    await expect(page.getByText('可实断端点（READY/全部）')).toBeVisible()
    await expect(page.getByText('最大陈旧窗口')).toBeVisible()
    // 来源与最后同步
    await expect(page.getByText('关系来源与最后同步')).toBeVisible()
    await expect(page.getByText('已确认关系来源')).toBeVisible()
    // readiness 徽章三态（tenants=实断中或就绪；debug=资格不齐；orders=存在 OPEN 冲突）
    await expect(page.getByText('资格不齐').first()).toBeVisible()
    await expect(page.getByText('存在 OPEN 冲突').first()).toBeVisible()
    // 冲突表与节点 ACK 表
    await expect(page.getByRole('cell', { name: 'orders' }).first()).toBeVisible()
    await expect(page.getByText('gateway-stage5-01').first()).toBeVisible()
  })

  test('② 向导五步全流（评估→四要素→签署→提交→发布生效→403 实证→决策可见）', async ({ page }) => {
    // 前置：tenants 行回 OBSERVE（幂等）+ 发布
    await resetToObserve(page, TENANTS_ROW)
    const pre = await publishAndWait(page)
    expect(pre.status).toBe('SUCCESS')

    await openPostureTab(page)
    const drawer = await openWizardFromRow(page, TENANTS_ROW, 'path:3')

    // preset 携带时向导初始即第 2 步（影响评估）——等评估数字出现
    await expect(drawer.getByText('切换后将被 403（近似）')).toBeVisible({ timeout: 15000 })
    await expect(drawer.getByText('涉及主体数')).toBeVisible()
    await drawer.getByRole('button', { name: '下一步' }).click()
    // 第 3 步：四要素（owner 填写 + 证据来源选择 + on_unknown 固定只读）
    await drawer.getByPlaceholder('如 zhang.lei@example.com').fill('e2e.tester@example.com')
    await drawer.getByRole('radio', { name: /MANUAL_CONFIRMED/ }).click()
    await expect(drawer.locator('input[value="ALLOW_UNKNOWN"]')).toBeVisible()
    await drawer.getByRole('button', { name: '下一步' }).click()
    // 第 4 步：确认单签署（确认文案回显 + 勾选 + 提交签署 → 已签署）
    await expect(drawer.getByText('确认语义（确认文案 v1）')).toBeVisible()
    await drawer.locator('.ant-checkbox-input').check()
    await drawer.getByRole('button', { name: '提交签署' }).click()
    await expect(drawer.getByText('已签署（signed_at 已落库）')).toBeVisible({ timeout: 10000 })
    await drawer.getByRole('button', { name: '下一步' }).click()
    // 第 5 步：提交 → 发布轮询 → 已生效
    await drawer.getByRole('button', { name: '确认提交切换' }).click()
    await expect(drawer.getByText('已生效：端点已进入 PROTECT（实断）')).toBeVisible({ timeout: 60000 })

    // 403 实证（other 主体经网关 → AUTHZ_VIOLATION_DENIED 精确体）
    const token = mintJWT('user-other-2', ['viewer'])
    const resp = await page.request.get(`${GATEWAY_URL}/api/v1/tenants/t001/projects/p002/items`, {
      headers: { Host: AZ4_HOST, Authorization: `Bearer ${token}` },
    })
    expect(resp.status()).toBe(403)
    const body = await resp.json()
    expect(body.code).toBe('AUTHZ_VIOLATION_DENIED')
    expect(body.message).toBe('无权访问该对象')
    expect(body.request_id).toBeTruthy()

    // decisions 过滤 VERIFIED_VIOLATION 可见（对象授权 Tab → OBSERVE 决策子 Tab）
    await page.keyboard.press('Escape')
    await page.getByRole('tab', { name: '对象授权' }).click()
    await selectAppInObjectAuthz(page)
    await page.waitForTimeout(4000) // 采集器批次
    await page.getByRole('tab', { name: /OBSERVE 决策/ }).click()
    await page.locator('.ant-select', { hasText: '全部结论' }).click()
    await page.locator('.ant-select-item', { hasText: '已验证违规（实断）' }).first().click()
    await expect(page.getByRole('cell', { name: '已验证违规（实断）' }).first()).toBeVisible({ timeout: 15000 })
  })

  test('⑤ VERIFIED_VIOLATION 决策详情证据区块（authz_enforcement 八因子/已实断/四要素回执）', async ({ page }) => {
    await page.goto('/api-authz')
    await page.getByRole('tab', { name: '对象授权' }).click()
    // 应用过滤 az4app + decision 过滤 VERIFIED_VIOLATION（OBSERVE 决策子 Tab）
    await selectAppInObjectAuthz(page)
    await page.getByRole('tab', { name: /OBSERVE 决策/ }).click()
    await page.locator('.ant-select', { hasText: '全部结论' }).click()
    await page.locator('.ant-select-item', { hasText: '已验证违规（实断）' }).first().click()
    const row = page.getByRole('row', { name: /已验证违规（实断）/ }).first()
    await expect(row).toBeVisible({ timeout: 15000 })
    await row.click()
    const drawer = page.getByRole('dialog', { name: '授权决策详情' })
    await expect(drawer).toBeVisible()
    await expect(drawer.getByText('实断证据（authz_enforcement）')).toBeVisible()
    await expect(drawer.getByText('已实断')).toBeVisible()
    await expect(drawer.getByText('VERIFIED_VIOLATION').first()).toBeVisible()
    for (const label of ['可信身份', '模型适用', '关系有效', '无冲突', '租户一致', '证据新鲜', '他人属主', '排他所有权']) {
      await expect(drawer.getByText(label)).toBeVisible()
    }
    await expect(drawer.getByText('e2e.tester@example.com').first()).toBeVisible()
  })

  test('③ 能力门阻塞提示（az/2 自报→发布 FAILED→配置与生效不一致+CAP_MISSING→快捷切回）', async ({ page }) => {
    // 前置：全 OBSERVE（az/3 下发布成功）→ 改清单 az/2 模拟旧节点
    await resetToObserve(page, TENANTS_ROW).catch(() => {})
    await resetToObserve(page, ORDERS_ROW).catch(() => {})
    const pre = await publishAndWait(page)
    expect(pre.status).toBe('SUCCESS')
    setNodeAzVersion('az/2')
    try {
      await openPostureTab(page)
      const drawer = await openWizardFromRow(page, ORDERS_ROW, 'path:3')
      // preset 形态初始即第 2 步（影响评估）
      await expect(drawer.getByText('切换后将被 403（近似）')).toBeVisible({ timeout: 15000 })
      await drawer.getByRole('button', { name: '下一步' }).click()
      await drawer.getByPlaceholder('如 zhang.lei@example.com').fill('e2e.tester@example.com')
      await drawer.getByRole('radio', { name: /MANUAL_CONFIRMED/ }).click()
      await drawer.getByRole('button', { name: '下一步' }).click()
      await drawer.locator('.ant-checkbox-input').check()
      await drawer.getByRole('button', { name: '提交签署' }).click()
      await expect(drawer.getByText('已签署（signed_at 已落库）')).toBeVisible({ timeout: 10000 })
      await drawer.getByRole('button', { name: '下一步' }).click()
      await drawer.getByRole('button', { name: '确认提交切换' }).click()
      // 发布 FAILED（含 PROTECT 快照要求 az/3，az/2 旧节点 fail-closed）→ 配置与生效不一致区块
      await expect(drawer.getByText('配置与生效不一致')).toBeVisible({ timeout: 60000 })
      await expect(drawer.getByText(/CAP_MISSING:detectors\.authzdecide\(required=az\/3/)).toBeVisible()
      // 快捷切回（全 OBSERVE 快照 az/2 可收——滚动升级路径）；Popconfirm 二次确认
      await drawer.getByRole('button', { name: '立即切回 OBSERVE' }).click()
      await page.getByRole('button', { name: '立即切回', exact: true }).click()
      await expect(drawer.getByText('已切回 OBSERVE')).toBeVisible({ timeout: 60000 })
    } finally {
      setNodeAzVersion('az/3')
    }
    // 恢复后发布回稳（az/3）
    const post = await publishAndWait(page)
    expect(post.status).toBe('SUCCESS')
  })

  test('④ jiuzhang_admin 越权对照（新端点与签署全 403）', async ({ page }) => {
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    for (const path of [
      '/api-security/authz/enforcement-readiness?application_id=00000000-0000-0000-0000-000000000000',
      '/api-security/authz/enforcement-confirmations',
      '/api-security/authz/conflicts',
    ]) {
      const resp = await page.request.get(`${API_URL}${path}`)
      expect(resp.status()).toBe(403)
    }
    const impact = await apiJSON(page, 'POST', '/api-security/authz/enforcement-impact', {
      endpoint_id: '00000000-0000-0000-0000-000000000000',
      window_days: 7,
    })
    expect(impact.status).toBe(403)
    const sign = await apiJSON(page, 'POST', `/api-security/authz/enforcement-confirmations/${crypto.randomUUID()}/sign`, {
      enforcement_owner: 'a@b.c',
      evidence_source: 'MANUAL_CONFIRMED',
      on_unknown: 'ALLOW_UNKNOWN',
    })
    expect(sign.status).toBe(403)
  })
})
