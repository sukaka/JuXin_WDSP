import { test, expect, type Locator, type Page } from '@playwright/test'
import { loginViaAPI, createUserViaAPI, changePasswordViaAPI, API_URL } from './helpers'

/**
 * 阶段8 E2E 增补：API 安全运营操作流（任务书 §217 可操作子集）
 *
 * 与 stage8-api-security.spec.ts（菜单/发现/模型/策略/学习/权限基线）互补，
 * 本规格覆盖运营闭环的八个可操作场景，每个场景独立 test、独立随机标签造数：
 *
 * - 用例1 风险处置流    findings：确认 → 开始处置 → 标记解决（处置说明必填校验）→ 状态流转
 * - 用例2 弱点整改流    weaknesses：确认 → 指派（owner+due_date）→ 整改完成 → 复测通过归档
 * - 用例3 脱敏规则流    新建 ENDPOINT 级 MASK 规则 → 列表可见 → 编辑 → 停用
 * - 用例4 敏感类型流    新建自定义类型 → 导入/导出按钮存在 → 内置类型删除禁用
 * - 用例5 规范中心流    URL 导入弹窗校验、粘贴导入 v1/v2、版本对比抽屉、激活与权限显隐
 * - 用例6 授权基线流    api-authz 三 Tab 渲染、角色基线新建 → 确认为正式基线
 * - 用例7 主动扫描流    目标新建 → 签发授权弹窗（双人分离提示）→ 任务/授权/发现页签渲染
 * - 用例8 运行时策略页  模型冻结编译策略 → 发布生效 → 列表渲染 + 回滚确认弹窗
 *
 * 先决数据条件（逐场景说明，全部真实造数，无 mock）：
 * - 用例1/2 依赖网关真实流量：向唯一路径 POST JSON 且查询串携带敏感字段名（?phone=…），
 *   命中 sensitive.in_query（HIGH）检测 → 采集器 2s 轮询物化 SENSITIVE_IN_QUERY 风险发现；
 *   弱点由 server 端 Sweeper（5min 周期，server/cmd/api/main.go）从运行时事件派生，
 *   故用例2 轮询窗口放宽到 ~6.5 分钟（先决：server 周期作业存活，stage5 编排默认满足）。
 * - 用例3/4/5 纯管理面 CRUD，无流量先决；用例4 的内置类型来自迁移 000040 种子。
 * - 用例6/8 依赖端点资产（同 stage8 既有规格的网关自动发现链路）；用例8 另需
 *   模型候选 → 冻结（编译 DRAFT 运行时策略）→ 整站发布（DRAFT → ACTIVE）。
 * - 用例7 依赖应用 s5app（缺失时按 stage5 最小要素自动创建并发布）；扫描引擎开关
 *   （settings api_scan.enabled）只门禁任务发起/复测，不影响目标新建与授权弹窗，
 *   本用例不发起真实扫描任务（授权双人分离由后端 403 强校验，server 单测已覆盖，
 *   此处仅断言 UI 提示与页签渲染）。
 *
 * 环境依赖（与 stage8-api-security.spec.ts 一致）：
 * - stage5 编排 + wdsp 覆盖（PRODUCT_EDITION=wdsp 且 API_DYNAMIC_PROTECTION_ENABLED=true），
 *   管理 API 127.0.0.1:18081，防护网关 127.0.0.1:18080，前端 vite dev 5173（/api 代理）；
 *   Valkey 连接走 helpers 的 VALKEY_HOST/VALKEY_PORT（stage5 编排映射 127.0.0.1:16379）。
 * - 测试用户：安全管理员 sec_admin_s5（E2E_SEC_USER/E2E_SEC_PWD 可覆盖）、
 *   系统管理员 jiuzhang_admin（E2E_SYSADMIN_USER/E2E_SYSADMIN_PWD）；审计用户用例5内现场创建。
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'
const SYS_USER = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYS_PWD = process.env.E2E_SYSADMIN_PWD || 'SysAdmin@S5!2026'
const GATEWAY_URL = process.env.E2E_GATEWAY_URL || 'http://127.0.0.1:18080'
const HOST = process.env.E2E_HOST || 'waf-s5.local'
const APP_CODE = process.env.E2E_APP_CODE || 's5app'

/** 通用随机串（用户名等场景，与 stage5/stage8 既有规格一致） */
const rand = () => Math.random().toString(36).slice(2, 8)

/** 路径段随机标签：仅小写字母，避开归一化（纯数字→{id}、长十六进制→{hex}），保证端点键唯一 */
const randTag = () =>
  'e2e' + Array.from({ length: 6 }, () => String.fromCharCode(97 + Math.floor(Math.random() * 26))).join('')

async function csrfToken(page: Page): Promise<string> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  return ((await me.json())?.data?.csrf_token as string) || ''
}

/** WDSP 环境前置校验：产品形态 wdsp 且 API 动态防护开启（否则阶段8菜单/接口均不可用） */
async function ensureWdspEnv(page: Page) {
  const resp = await page.request.get(`${API_URL}/product/edition`)
  expect(resp.status(), 'get product edition').toBe(200)
  const data = (await resp.json())?.data
  expect(
    data?.edition === 'wdsp' && data?.api_dynamic_protection === true,
    `需 WDSP 环境（PRODUCT_EDITION=wdsp 且 API_DYNAMIC_PROTECTION_ENABLED=true），当前=${JSON.stringify(data)}`,
  ).toBe(true)
}

/**
 * 发布网关配置并轮询任务直至 SUCCESS（≤30s）。
 * 配置版本号为秒级时间戳+配置哈希，同一秒内重复发布会撞 version_number 唯一约束，跨秒重试。
 */
async function publishGatewayConfigAndWait(page: Page) {
  for (let attempt = 1; ; attempt++) {
    const csrf = await csrfToken(page)
    const resp = await page.request.post(`${API_URL}/gateway-config/publish`, {
      data: { idempotency_key: `e2e-s8ops-${Date.now()}-${rand()}` },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(resp.status(), 'publish gateway-config').toBe(200)
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

/** 确保测试应用存在且配置已发布（应用缺失时按 stage5 编排最小要素创建，同 stage8 既有规格） */
async function ensureAppPublished(page: Page) {
  const list = await page.request.get(`${API_URL}/applications?keyword=${APP_CODE}&page=1&page_size=100`)
  expect(list.status(), 'list applications').toBe(200)
  const items = ((await list.json())?.data?.items || []) as Array<{ id: string; code: string }>
  let appId = items.find((a) => a.code === APP_CODE)?.id
  if (!appId) {
    const csrf = await csrfToken(page)
    const headers = { 'X-CSRF-Token': csrf }
    const create = await page.request.post(`${API_URL}/applications`, {
      data: {
        code: APP_CODE,
        name: '阶段8 E2E 测试应用',
        description: '接口动态防护 E2E 造数',
        business_owner: 'test',
        technical_owner: 'test',
        protection_mode: 'OFF',
      },
      headers,
    })
    expect(create.status(), `create application: ${await create.text()}`).toBe(200)
    appId = ((await create.json())?.data?.id as string) || ''
    expect(appId, 'application id').toBeTruthy()
    const domain = await page.request.post(`${API_URL}/applications/${appId}/domains`, {
      data: {
        hostname: HOST,
        is_primary: true,
        http_enabled: true,
        https_enabled: false,
        http_port: 8080,
        redirect_http_to_https: false,
      },
      headers,
    })
    expect(domain.status(), `add domain: ${await domain.text()}`).toBe(200)
    const upstream = await page.request.post(`${API_URL}/applications/${appId}/upstreams`, {
      data: {
        name: 'testorigin',
        scheme: 'http',
        host: 'testorigin',
        port: 8081,
        weight: 1,
        priority: 1,
        health_check_enabled: false,
        health_check_path: '/health',
        health_check_method: 'GET',
        health_check_interval_seconds: 10,
        health_check_timeout_seconds: 3,
        expected_status_codes: '200',
        connect_timeout_ms: 3000,
        response_header_timeout_ms: 10000,
        tls_server_name: '',
        tls_verify: false,
      },
      headers,
    })
    expect(upstream.status(), `add upstream: ${await upstream.text()}`).toBe(200)
    const enable = await page.request.post(`${API_URL}/applications/${appId}/enable`, { headers })
    expect(enable.status(), `enable application: ${await enable.text()}`).toBe(200)
  }
  await publishGatewayConfigAndWait(page)
}

interface DiscoveredEndpoint {
  id: string
  endpointKey: string
}

/**
 * 经网关真实流量造端点发现数据（同 stage8 既有规格链路），withSensitiveQuery=true 时
 * 查询串追加敏感字段名（?phone=…），命中 sensitive.in_query（HIGH）→ 物化 SENSITIVE_IN_QUERY
 * 风险发现，并供弱点派生扫描（SENSITIVE_IN_QUERY 规则）取数。
 * 路径形如 /e2e/api/<tag>/orders/<n>，归一化后端点键为 POST /e2e/api/<tag>/orders/{id}。
 */
async function discoverEndpoint(
  page: Page,
  tag: string,
  opts?: { withSensitiveQuery?: boolean },
): Promise<DiscoveredEndpoint> {
  await ensureAppPublished(page)
  const endpointKey = `POST /e2e/api/${tag}/orders/{id}`
  const query = opts?.withSensitiveQuery ? '?phone=13800138000' : ''
  for (let i = 1; i <= 3; i++) {
    await page.request.post(`${GATEWAY_URL}/e2e/api/${tag}/orders/${i}${query}`, {
      headers: { Host: HOST, 'Content-Type': 'application/json' },
      data: { id: i, name: 'widget' },
    })
  }
  const deadline = Date.now() + 30000
  let found: DiscoveredEndpoint | null = null
  while (Date.now() < deadline) {
    const resp = await page.request.get(
      `${API_URL}/api-security/endpoints?keyword=${tag}&page=1&page_size=20`,
    )
    expect(resp.status(), 'list api endpoints').toBe(200)
    const items = ((await resp.json())?.data?.items || []) as Array<{
      id: string
      endpoint_key: string
    }>
    const hit = items.find((e) => e.endpoint_key === endpointKey)
    if (hit) {
      found = { id: hit.id, endpointKey }
      break
    }
    await page.waitForTimeout(1000)
  }
  expect(found, `端点自动发现 ${endpointKey}（30s 内应被采集入库）`).toBeTruthy()
  return found as DiscoveredEndpoint
}

/** 轮询风险发现列表直至出现本标签端点的 SENSITIVE_IN_QUERY 发现（采集器 2s 轮询物化，≤60s） */
async function waitFinding(page: Page, tag: string): Promise<string> {
  const deadline = Date.now() + 60000
  while (Date.now() < deadline) {
    const resp = await page.request.get(`${API_URL}/api-security/findings?status=NEW&page=1&page_size=100`)
    expect(resp.status(), 'list api findings').toBe(200)
    const items = ((await resp.json())?.data?.items || []) as Array<{
      id: string
      endpoint_key?: string
      finding_type: string
    }>
    const hit = items.find((f) => f.endpoint_key?.includes(tag) && f.finding_type === 'SENSITIVE_IN_QUERY')
    if (hit) return hit.id
    await page.waitForTimeout(1500)
  }
  throw new Error(`风险发现未在 60s 内物化（标签 ${tag}，期望 SENSITIVE_IN_QUERY）`)
}

/**
 * 轮询弱点列表直至派生出本标签端点的弱点（server 端 Sweeper 周期 5min，
 * 信号规则 SENSITIVE_IN_QUERY：近 24h 存在 sensitive.in_query 命中即派生，窗口放到 6.5min）。
 */
async function waitWeakness(page: Page, tag: string): Promise<string> {
  const deadline = Date.now() + 390000
  while (Date.now() < deadline) {
    const resp = await page.request.get(`${API_URL}/api-security/weaknesses?page=1&page_size=100`)
    expect(resp.status(), 'list api weaknesses').toBe(200)
    const items = ((await resp.json())?.data?.items || []) as Array<{
      id: string
      endpoint_key?: string
      weakness_code: string
    }>
    const hit = items.find((w) => w.endpoint_key?.includes(tag) && w.weakness_code === 'SENSITIVE_IN_QUERY')
    if (hit) return hit.id
    await page.waitForTimeout(10000)
  }
  throw new Error(`弱点未在 6.5min 内派生（标签 ${tag}，期望 SENSITIVE_IN_QUERY；依赖 server 5min 周期 sweep）`)
}

/** 当前展开下拉中的选项（stage7 既有模式：只匹配未隐藏 dropdown） */
function dropdownOption(page: Page, text: string | RegExp): Locator {
  return page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option', {
    hasText: text,
  })
}

/** 打开表单弹窗中指定字段（Form.Item name → label[for]）的下拉选择器 */
async function openFormItemSelect(page: Page, dialog: Locator, field: string) {
  await dialog
    .locator('.ant-form-item')
    .filter({ has: page.locator(`label[for="${field}"]`) })
    .locator('.ant-select')
    .click()
}

/** 确认弹框（modal.confirm / Form Modal 共用 .ant-modal 容器，同一场景同一时刻仅一个弹层） */
function confirmDialog(page: Page): Locator {
  return page.locator('.ant-modal')
}

/** 在对话框/页面范围内按字段标签定位并点击下拉，再点选可见选项 */
async function pickSelectOption(page: Page, dialog: Locator, field: string, optionText: string | RegExp) {
  await openFormItemSelect(page, dialog, field)
  await dropdownOption(page, optionText).first().click()
}

test.describe('阶段8：API 安全运营操作流（§217）', () => {
  /* ==================== 1. 风险处置流 ==================== */

  test('风险处置：确认→开始处置→标记解决（必填校验）→状态流转', async ({ page }) => {
    test.setTimeout(240_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    // 造数：敏感查询串流量 → SENSITIVE_IN_QUERY 风险发现（NEW）
    const tag = randTag()
    await discoverEndpoint(page, tag, { withSensitiveQuery: true })
    await waitFinding(page, tag)

    await page.goto('/api-findings')
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 风险发现' })).toBeVisible()
    // 列表按 last_seen_at 倒序，新物化发现在首页；同一端点一次流量会物化多类型发现
    // （SHADOW/BOLA/AUTH/SENSITIVE_*），按标签 + 类型双重定位本用例行
    const row = page.locator('tbody tr', { hasText: tag }).filter({ hasText: 'SENSITIVE_IN_QUERY' })
    await expect(row).toBeVisible({ timeout: 15000 })
    await expect(row.getByText('SENSITIVE_IN_QUERY')).toBeVisible()
    await expect(row.getByText('待确认')).toBeVisible()

    // 行内「确认」→ 二次确认 → 状态变「已确认」
    await row.getByRole('button', { name: '确认' }).click()
    await confirmDialog(page).getByRole('button', { name: /确 ?定/ }).click()
    await expect(row.getByText('已确认')).toBeVisible({ timeout: 10000 })

    // 行内「开始处置」→ 状态变「处理中」
    await row.getByRole('button', { name: '开始处置' }).click()
    await confirmDialog(page).getByRole('button', { name: /确 ?定/ }).click()
    await expect(row.getByText('处理中')).toBeVisible({ timeout: 10000 })

    // 标记解决仅在详情抽屉：处置说明必填（先空提交验证必填校验，再填写提交）
    await row.getByRole('button', { name: '详情' }).click()
    const drawer = page.locator('.ant-drawer', { hasText: '风险详情' })
    await expect(drawer).toBeVisible()
    await drawer.getByRole('button', { name: '标记解决' }).click()
    const resolveModal = confirmDialog(page)
    await expect(resolveModal).toBeVisible()
    await resolveModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('请输入处置说明')).toBeVisible()
    await resolveModal.locator('#resolution').fill('E2E 处置说明：查询串敏感字段已整改为表单提交')
    await resolveModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('已标记为解决')).toBeVisible({ timeout: 10000 })
    await expect(row.getByText('已解决')).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 2. 弱点整改流 ==================== */

  test('弱点整改：确认→指派（负责人+期限）→整改完成→复测通过归档', async ({ page }) => {
    // 弱点由 server 5min 周期 sweep 派生，单测超时放宽到 9.5min
    test.setTimeout(570_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    // 造数：敏感查询串流量（匿名）→ sweep 派生 SENSITIVE_IN_QUERY 弱点
    const tag = randTag()
    await discoverEndpoint(page, tag, { withSensitiveQuery: true })
    await waitWeakness(page, tag)

    await page.goto('/api-weaknesses')
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 弱点中心' })).toBeVisible()
    // 列表按 last_seen 倒序，新派生弱点在首页
    const row = page.locator('tbody tr', { hasText: tag })
    await expect(row).toBeVisible({ timeout: 15000 })
    await expect(row.getByText('待确认')).toBeVisible()

    // 详情抽屉 → 确认（备注可选）
    await row.getByRole('button', { name: '详情' }).click()
    const drawer = page.locator('.ant-drawer', { hasText: '弱点详情' })
    await expect(drawer).toBeVisible()
    await expect(drawer.getByRole('button', { name: /确 ?认/ })).toBeVisible({ timeout: 10000 })
    await drawer.getByRole('button', { name: /确 ?认/ }).click()
    await confirmDialog(page).getByRole('button', { name: /确 ?定/ }).click()
    await expect(drawer.getByText('已确认')).toBeVisible({ timeout: 10000 })

    // 指派：负责人必填校验 → 填负责人 + 整改期限 → 状态「待整改」
    await drawer.getByRole('button', { name: /指 ?派/ }).click()
    const assignModal = confirmDialog(page)
    await expect(assignModal).toBeVisible()
    await assignModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('请填写整改负责人')).toBeVisible()
    await assignModal.locator('#owner').fill(`e2e_owner_${tag}`)
    await assignModal.locator('#due_date').click()
    await page.keyboard.type('2030-12-31 10:00:00')
    await page.keyboard.press('Enter')
    await assignModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(drawer.getByText('待整改')).toBeVisible({ timeout: 10000 })
    // 期限落库（Descriptions 展示 2030 年）
    await expect(drawer.getByText(/2030-12-31/)).toBeVisible({ timeout: 10000 })

    // 整改完成 → 状态「待复测」
    await drawer.getByRole('button', { name: '整改完成' }).click()
    await confirmDialog(page).getByRole('button', { name: /确 ?定/ }).click()
    await expect(drawer.getByText('待复测')).toBeVisible({ timeout: 10000 })

    // 复测（默认通过）→ 归档关闭
    await drawer.getByRole('button', { name: /复 ?测/ }).click()
    const retestModal = confirmDialog(page)
    await expect(retestModal).toBeVisible()
    await retestModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('复测通过，弱点已归档关闭')).toBeVisible({ timeout: 10000 })
    await expect(drawer.getByText('已归档')).toBeVisible({ timeout: 10000 })
    // 处置历史留痕（确认/指派/整改/复测全链路）
    await expect(drawer.getByText('确认弱点')).toBeVisible()
    await expect(drawer.getByText('指派整改')).toBeVisible()
    await expect(drawer.getByText('复测通过')).toBeVisible()
  })

  /* ==================== 3. 脱敏规则流 ==================== */

  test('脱敏规则：新建接口级掩码规则→列表可见→编辑→停用', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()
    const name = `e2e-mask-${tag}`
    const endpointKey = `GET /e2e/api/${tag}/mask/{id}`

    await page.goto('/api-masking-rules')
    await expect(page.locator('.ant-card-head-title', { hasText: '脱敏规则' })).toBeVisible()

    // 新建 ENDPOINT 级 MASK 规则（endpoint_key 仅格式校验，不要求资产存在）
    await page.getByRole('button', { name: '新建规则' }).click()
    const dialog = confirmDialog(page)
    await expect(dialog.getByText('新建脱敏规则')).toBeVisible()
    await dialog.locator('#name').fill(name)
    await pickSelectOption(page, dialog, 'scope', '接口级（ENDPOINT）')
    await dialog.locator('#endpoint_key').fill(endpointKey)
    await dialog.locator('#field_path').fill('user.phone')
    await dialog.getByRole('button', { name: /确 ?定/ }).click()

    const row = page.locator('tbody tr', { hasText: name })
    await expect(row).toBeVisible({ timeout: 10000 })
    await expect(row.getByText('接口级')).toBeVisible()
    await expect(row.getByText('掩码')).toBeVisible()
    await expect(row.getByText('启用', { exact: true })).toBeVisible()

    // 编辑：改名保存
    await row.getByRole('button', { name: '编辑' }).click()
    const editDialog = confirmDialog(page)
    await expect(editDialog.getByText(`编辑规则：${name}`)).toBeVisible()
    await editDialog.locator('#name').fill(`${name}-v2`)
    await editDialog.getByRole('button', { name: /确 ?定/ }).click()
    const rowV2 = page.locator('tbody tr', { hasText: `${name}-v2` })
    await expect(rowV2).toBeVisible({ timeout: 10000 })

    // 停用：二次确认后状态变「禁用」
    await rowV2.getByRole('button', { name: '禁用' }).click()
    await confirmDialog(page).getByRole('button', { name: /确 ?定/ }).click()
    await expect(rowV2.getByText('禁用')).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 4. 敏感类型流 ==================== */

  test('敏感类型：新建自定义类型→导入导出按钮存在→内置类型删除禁用', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()

    await page.goto('/api-sensitive-types')
    await expect(page.locator('.ant-card-head-title', { hasText: '敏感数据类型' })).toBeVisible()

    // 新建自定义类型（等级默认「一般」，启用默认开）
    await page.getByRole('button', { name: '新建类型' }).click()
    const dialog = confirmDialog(page)
    await expect(dialog.getByText('新建敏感数据类型')).toBeVisible()
    await dialog.locator('#name').fill(`E2E自定义类型${tag}`)
    await dialog.locator('#data_type').fill(`e2e_${tag}`)
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    const row = page.locator('tbody tr', { hasText: `e2e_${tag}` })
    await expect(row).toBeVisible({ timeout: 10000 })
    // 自定义类型无「内置」标记
    await expect(row.getByText('内置')).toHaveCount(0)

    // 导入/导出按钮存在（管理权限下均可见）
    await expect(page.getByRole('button', { name: '导入' })).toBeVisible()
    await expect(page.getByRole('button', { name: '导出' })).toBeVisible()

    // 内置类型（迁移 000040 种子）删除按钮禁用
    const builtinRow = page.locator('tbody tr', { hasText: '内置' }).first()
    await expect(builtinRow).toBeVisible()
    await expect(builtinRow.getByRole('button', { name: '删除' })).toBeDisabled()
  })

  /* ==================== 5. 规范中心流 ==================== */

  test('规范中心：URL导入校验/粘贴导入两版/版本对比/激活与权限显隐', async ({ page }) => {
    test.setTimeout(180_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()
    const specName = `e2e-spec-${tag}`
    // 两个版本同一 title 形成版本链；v2 改参数类型并新增加必填参数，制造 CHANGED 级差异
    const specV1 = JSON.stringify({
      openapi: '3.0.0',
      info: { title: specName, version: '1.0.0' },
      paths: {
        [`/e2e/api/${tag}/items/{id}`]: {
          get: {
            parameters: [{ name: 'limit', in: 'query', required: false, schema: { type: 'integer' } }],
            responses: { '200': { description: 'ok' } },
          },
        },
      },
    })
    const specV2 = JSON.stringify({
      openapi: '3.0.0',
      info: { title: specName, version: '2.0.0' },
      paths: {
        [`/e2e/api/${tag}/items/{id}`]: {
          get: {
            parameters: [
              { name: 'limit', in: 'query', required: false, schema: { type: 'string' } },
              { name: 'verbose', in: 'query', required: true, schema: { type: 'boolean' } },
            ],
            responses: { '200': { description: 'ok' } },
          },
        },
      },
    })

    await page.goto('/api-specs')
    await expect(page.locator('.ant-card-head-title', { hasText: '规范对比' })).toBeVisible()

    // URL 导入弹窗：URL 必填校验 + 认证头名值成对校验（纯前端校验，不发请求）
    await page.getByRole('button', { name: 'URL 导入' }).click()
    const urlDialog = confirmDialog(page)
    await expect(urlDialog.getByText('从 URL 导入规范')).toBeVisible()
    await urlDialog.getByRole('button', { name: /导 ?入/ }).click()
    await expect(page.getByText('请输入规范文档 URL')).toBeVisible()
    await urlDialog.locator('#url').fill('https://example.com/openapi.json')
    await urlDialog.locator('#header_name').fill('Authorization')
    await urlDialog.getByRole('button', { name: /导 ?入/ }).click()
    await expect(page.getByText('认证头名称已填写时，认证头值不能为空')).toBeVisible()
    await urlDialog.getByRole('button', { name: /取 ?消/ }).click()

    // 粘贴导入 v1 → 成功提示 + 列表可见（同名唯一 ACTIVE）
    await page.getByRole('button', { name: '导入规范' }).click()
    let importDialog = confirmDialog(page)
    await importDialog.locator('#spec_json').fill(specV1)
    await importDialog.getByRole('button', { name: /导 ?入/ }).click()
    await expect(page.getByText(/导入成功：/, { exact: false }).first()).toBeVisible({ timeout: 10000 })
    const rowV1 = page.locator('tbody tr', { hasText: specName }).filter({ hasText: 'v1' })
    await expect(rowV1).toBeVisible({ timeout: 10000 })
    await expect(rowV1.getByText('激活', { exact: true })).toBeVisible()

    // 粘贴导入 v2（同名 → v2 版本，v1 降为历史）
    await page.getByRole('button', { name: '导入规范' }).click()
    importDialog = confirmDialog(page)
    await importDialog.locator('#spec_json').fill(specV2)
    await importDialog.getByRole('button', { name: /导 ?入/ }).click()
    await expect(page.getByText(/导入成功：/).first()).toBeVisible({ timeout: 10000 })
    const rowV2 = page.locator('tbody tr', { hasText: specName }).filter({ hasText: 'v2' })
    await expect(rowV2).toBeVisible({ timeout: 10000 })
    await expect(rowV1.getByText('历史')).toBeVisible({ timeout: 10000 })

    // 版本对比抽屉：基准 v2 → 目标 v1，渲染定义变更
    await rowV2.getByRole('button', { name: '版本对比' }).click()
    const vdDrawer = page.locator('.ant-drawer', { hasText: `版本对比：${specName}` })
    await expect(vdDrawer).toBeVisible()
    await vdDrawer.locator('.ant-select').click()
    await dropdownOption(page, /v1（历史）/).click()
    await expect(vdDrawer.getByText(/共 \d+ 处定义变更/)).toBeVisible({ timeout: 10000 })
    await vdDrawer.locator('.ant-drawer-close').click()

    // 查看差异抽屉可打开（运行时对比，差异可为空）
    await rowV2.getByRole('button', { name: '查看差异' }).click()
    const diffDrawer = page.locator('.ant-drawer', { hasText: '规范差异：' })
    await expect(diffDrawer).toBeVisible()
    await diffDrawer.locator('.ant-drawer-close').click()

    // 激活（api_spec.manage）：v1 行激活按钮可见，确认后 v1 回激活、v2 降历史
    await rowV1.getByRole('button', { name: '激活', exact: true }).click()
    const activateModal = confirmDialog(page)
    await expect(activateModal.locator('.ant-modal-confirm-title')).toHaveText('激活规范版本')
    await activateModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(rowV1.getByText('激活', { exact: true })).toBeVisible({ timeout: 10000 })
    await expect(rowV2.getByText('历史')).toBeVisible({ timeout: 10000 })

    // 权限显隐：审计管理员只读——导入/激活不渲染，查看差异可读
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    const username = `e2e_audit_${rand()}`
    const { password: tempPwd } = await createUserViaAPI(page, username, 'AUDIT_ADMIN')
    const newPwd = 'AuditAdmin@S8Ops!2026'
    await loginViaAPI(page, username, tempPwd)
    await changePasswordViaAPI(page, tempPwd, newPwd)
    await page.context().clearCookies()
    await loginViaAPI(page, username, newPwd)

    await page.goto('/api-specs')
    await expect(page.locator('.ant-card-head-title', { hasText: '规范对比' })).toBeVisible()
    await expect(page.getByRole('button', { name: '导入规范' })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'URL 导入' })).toHaveCount(0)
    const auditRowV2 = page.locator('tbody tr', { hasText: specName }).filter({ hasText: 'v2' })
    await expect(auditRowV2).toBeVisible({ timeout: 10000 })
    await expect(auditRowV2.getByRole('button', { name: '查看差异' })).toBeVisible()
    await expect(auditRowV2.getByRole('button', { name: '激活', exact: true })).toHaveCount(0)
    await expect(auditRowV2.getByRole('button', { name: '版本对比' })).toBeVisible()
  })

  /* ==================== 6. 授权基线流 ==================== */

  test('授权基线：三Tab渲染→角色基线新建→确认为正式基线', async ({ page }) => {
    test.setTimeout(180_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    // 造数：端点资产（基线须挂真实端点）
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)

    await page.goto('/api-authz')
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 授权管理' })).toBeVisible()

    // 三 Tab 渲染
    await expect(page.getByRole('tab', { name: '角色基线（BFLA）' })).toBeVisible()
    await page.getByRole('tab', { name: '对象权属（BOLA）' }).click()
    await expect(
      page.locator('.ant-tabs-content-active').getByText(/权属基线由系统从运行时流量自动生产/),
    ).toBeVisible()
    await page.getByRole('tab', { name: '字段权限' }).click()
    await expect(page.locator('.ant-tabs-content-active').getByText('仅默认行')).toBeVisible()
    await page.getByRole('tab', { name: '角色基线（BFLA）' }).click()

    // 新建基线：接口（端点选择器过滤定位）+ 角色码 + 方法 + 动作（判定/来源/置信度取默认）
    await page.getByRole('button', { name: '新建基线' }).click()
    const dialog = confirmDialog(page)
    await expect(dialog.getByText('新建角色基线')).toBeVisible()
    await openFormItemSelect(page, dialog, 'endpoint_id')
    await page.locator('.ant-select-item-option').first().waitFor()
    await page.keyboard.type(tag)
    await dropdownOption(page, ep.endpointKey).click()
    await dialog.locator('#role').fill(`e2e_role_${tag}`)
    await pickSelectOption(page, dialog, 'method', 'GET')
    await dialog.locator('#action').fill('READ')
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('已创建（候选基线，确认后生效）')).toBeVisible({ timeout: 10000 })

    // 列表出现候选基线
    const row = page.locator('tbody tr', { hasText: `e2e_role_${tag}` })
    await expect(row).toBeVisible({ timeout: 10000 })
    await expect(row.getByText('候选')).toBeVisible()

    // 确认 → 二次确认 → 变「已确认」正式基线
    await row.getByRole('button', { name: '确认', exact: true }).click()
    const confirmModal = confirmDialog(page)
    await expect(confirmModal.locator('.ant-modal-confirm-title')).toHaveText('确认基线')
    await confirmModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(row.getByText('已确认')).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 7. 主动扫描流 ==================== */

  test('主动扫描：目标新建→授权弹窗双人分离提示→任务/授权/发现页签渲染', async ({ page }) => {
    test.setTimeout(180_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    // 先决：扫描目标须挂应用（s5app 缺失时自动创建并发布）
    await ensureAppPublished(page)
    const tag = randTag()

    await page.goto('/api-scan')
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 主动扫描' })).toBeVisible()
    await expect(page.getByRole('tab', { name: '扫描目标' })).toBeVisible()

    // 新建目标（创建即 ENABLED；不发起真实任务，无需开启 api_scan.enabled）
    await page.getByRole('button', { name: '新建目标' }).click()
    const dialog = confirmDialog(page)
    await expect(dialog.getByText('新建扫描目标')).toBeVisible()
    await openFormItemSelect(page, dialog, 'application_id')
    await dropdownOption(page, `（${APP_CODE}）`).first().click()
    await dialog.locator('#name').fill(`e2e-target-${tag}`)
    await dialog.locator('#base_url').fill('http://testorigin:8081')
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('已创建扫描目标')).toBeVisible({ timeout: 10000 })
    const row = page.locator('tbody tr', { hasText: `e2e-target-${tag}` })
    await expect(row).toBeVisible({ timeout: 10000 })
    await expect(row.getByText('启用')).toBeVisible()

    // 签发授权弹窗：双人分离提示（建标人自签由后端 403 强校验，此处仅断言 UI 提示后取消）
    await row.getByRole('button', { name: '签发授权' }).click()
    const authzDialog = confirmDialog(page)
    await expect(authzDialog.getByText(`签发扫描授权：e2e-target-${tag}`)).toBeVisible()
    await expect(authzDialog.getByText('双人分离：目标创建人与授权人不得为同一人')).toBeVisible()
    await authzDialog.getByRole('button', { name: /取 ?消/ }).click()

    // 任务页签渲染（发起任务按钮按 api_scan.manage 显隐）
    await page.getByRole('tab', { name: '扫描任务' }).click()
    await expect(
      page.locator('.ant-tabs-content-active').getByRole('button', { name: '发起任务' }),
    ).toBeVisible()

    // 授权页签渲染（未选目标时空态提示）
    await page.getByRole('tab', { name: '扫描授权' }).click()
    await expect(page.locator('.ant-tabs-content-active').getByText('请先选择扫描目标')).toBeVisible()

    // 发现页签渲染（过滤器区可见）
    await page.getByRole('tab', { name: '扫描发现' }).click()
    await expect(
      page.locator('.ant-tabs-content-active').locator('.ant-select', { hasText: '严重级别' }).first(),
    ).toBeVisible()
  })

  /* ==================== 8. 运行时策略页 ==================== */

  test('运行时策略：模型冻结编译策略发布生效→列表渲染→回滚确认弹窗', async ({ page }) => {
    test.setTimeout(240_000)
    // 回归说明：本用例曾受服务端 policySelect 列前缀缺陷阻塞（JOIN 后列歧义 42702）；
    // 服务端修复（runtime_policy.go policySelect 逐列 p. 前缀）后恢复为正常回归用例。
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    // 造数：端点 → 候选模型 → 冻结（编译 DRAFT 策略）→ 整站发布（ACTIVE）
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)
    const csrf = await csrfToken(page)
    const createResp = await page.request.post(`${API_URL}/api-security/endpoints/${ep.id}/models`, {
      data: { schema: { order_id: 'number', amount: 'number' }, change_summary: 'E2E 运行时策略造数' },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(createResp.status(), `create candidate: ${await createResp.text()}`).toBe(200)
    const versionId = (await createResp.json())?.data?.version?.id as string
    expect(versionId, 'model version id').toBeTruthy()
    const confirmResp = await page.request.post(`${API_URL}/api-security/models/${versionId}/confirm`, {
      data: {},
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(confirmResp.status(), `confirm model: ${await confirmResp.text()}`).toBe(200)
    await publishGatewayConfigAndWait(page)

    // 策略已生效（发布成功回写 ACTIVE；兜底轮询 15s）
    const deadline = Date.now() + 15000
    let activeSeen = false
    while (Date.now() < deadline) {
      const resp = await page.request.get(
        `${API_URL}/api-security/runtime-policies?endpoint_id=${ep.id}&status=ACTIVE&page=1&page_size=5`,
      )
      expect(resp.status(), 'list runtime policies').toBe(200)
      if ((((await resp.json())?.data?.items || []) as unknown[]).length > 0) {
        activeSeen = true
        break
      }
      await page.waitForTimeout(1000)
    }
    expect(activeSeen, '模型冻结发布后应存在 ACTIVE 运行时策略').toBe(true)

    // 页面：endpoint_id 预填过滤，列表渲染生效中策略
    await page.goto(`/api-runtime-policies?endpoint_id=${ep.id}`)
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 运行时策略' })).toBeVisible()
    const row = page.locator('tbody tr', { hasText: ep.endpointKey })
    await expect(row).toBeVisible({ timeout: 10000 })
    await expect(row.getByText('生效中')).toBeVisible()

    // 回滚确认弹窗（ACTIVE 可回滚；弹窗确认即真实回滚，此处断言弹窗后取消，不污染环境）
    await row.getByRole('button', { name: '回滚' }).click()
    const rollbackModal = confirmDialog(page)
    await expect(rollbackModal.locator('.ant-modal-confirm-title')).toHaveText('回滚运行时策略')
    await expect(rollbackModal.getByText(/回退到上一已知良好版本/)).toBeVisible()
    await rollbackModal.getByRole('button', { name: /取 ?消/ }).click()
    await expect(rollbackModal).toHaveCount(0)
  })
})
