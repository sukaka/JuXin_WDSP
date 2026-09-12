import { randomUUID } from 'node:crypto'
import { test, expect, type Page } from '@playwright/test'
import { loginViaAPI, createUserViaAPI, changePasswordViaAPI, API_URL } from './helpers'

/**
 * 阶段8 E2E：接口动态防护（WDSP）—— 任务书第六十二章七场景的管理面可达子集
 *
 * 用例与任务书场景映射：
 * - 用例1 菜单可见性 + 用例2 端点资产      ← 场景一「自动发现API」（造数链路即真实自动发现路径）
 * - 用例3 模型版本（候选→冻结→正式）      ← 场景三「版本生成与对比」+ 场景四「模型冻结」的 UI 可达部分
 * - 用例4 策略页（模式持久化）            ← 防护模式 db 覆盖生效验证
 * - 用例5 学习中心（启动/停止）           ← 场景二「动态参数学习」的入口操作
 * - 用例6 审计管理员只读                  ← 场景七「独立API权限」的 UI 显隐部分
 * - 用例8 参数学习闭环                    ← 场景二「动态参数学习」（学习完成→参数模型类型/置信度）
 * - 用例9 模型冻结+偏离                   ← 场景四「模型冻结」（偏离出事件、正式模型不变、偏离不进学习）
 * - 用例10 重新学习分支对比               ← 场景五「重新学习」（正式模型持续检测、学习分支、对比、确认激活）
 * - 用例11 统一事件单主事件多明细         ← 场景六「统一事件」（WAF+Schema 偏离同请求一主事件多明细）
 * - 用例7 WAF 形态（test.skip）           ← 产品形态边界，需 waf 形态环境单独执行
 *
 * 真实环境复跑说明：用例8-11 依赖 stage5+wdsp 真实栈（网关流量采集 2s 轮询、学习调度默认 30s 周期、
 * testorigin 上游），本机无后端时不可用 npx playwright test 实跑，应在集成环境按
 * Makefile stage8-test-e2e 口径复跑；学习完成等待上限 240s，如调度间隔被 system_settings
 * 调大需同步放宽。
 *
 * 环境依赖（与 Makefile stage8-test-e2e 一致）：
 * - stage5 编排 + wdsp 覆盖（PRODUCT_EDITION=wdsp 且 API_DYNAMIC_PROTECTION_ENABLED=true，
 *   即 deployment/docker-compose.stage5.yml + deployment/docker-compose.wdsp.yml），
 *   管理 API 127.0.0.1:18081，防护网关 127.0.0.1:18080，前端 vite dev 5173（/api 代理）。
 *   非 WDSP 环境下阶段8菜单与接口均不可用，用例1-6 的前置校验会明确失败。
 * - 测试用户：安全管理员 sec_admin_s5（stage5 运行手册预置，可用 E2E_SEC_USER/E2E_SEC_PWD 覆盖）；
 *   系统管理员 jiuzhang_admin（E2E_SYSADMIN_USER/E2E_SYSADMIN_PWD）；审计用户在用例6内现场创建。
 *
 * 造数方式说明（端点发现数据）：
 * - 管理面无“创建端点”接口（POST /api-security/endpoints 不存在），端点只能经网关自动发现入库；
 *   web 端 E2E 基建仅有 ioredis、无 postgres 客户端，故不直连 SQL。
 * - 本规格复用 stage5 spec 的网关请求方式（Host 头 + page.request），向网关发送 JSON 流量，
 *   走任务书场景一的真实链路：guard 管线产出 api-runtime 事件 → 管理面采集器（2s 轮询）
 *   → UpsertDiscovery 幂等入库 → 端点列表可见。应用 s5app 缺失时自动按最小要素创建并发布。
 * - 归一化规则（gateway/dynamic_security/normalizer）：纯数字段 → {id}；随机 tag 只用小写字母，
 *   保证路径段按字面量保留、每次运行端点键唯一，用例间互不干扰。
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'
const SYS_USER = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYS_PWD = process.env.E2E_SYSADMIN_PWD || 'SysAdmin@S5!2026'
const GATEWAY_URL = process.env.E2E_GATEWAY_URL || 'http://127.0.0.1:18080'
const HOST = process.env.E2E_HOST || 'waf-s5.local'
const APP_CODE = process.env.E2E_APP_CODE || 's5app'

/** 通用随机串（用户名等场景，与 stage5 一致） */
const rand = () => Math.random().toString(36).slice(2, 8)

/** 路径段随机标签：仅小写字母，避开归一化（纯数字→{id}、长十六进制→{hex}），保证端点键唯一 */
const randTag = () =>
  'e2e' + Array.from({ length: 6 }, () => String.fromCharCode(97 + Math.floor(Math.random() * 26))).join('')

/** 「接口防护」分组 12 个菜单项（与 web/src/utils/menu.ts 一致） */
const API_SECURITY_MENU_LABELS = [
  '接口端点资产',
  '接口模型版本',
  '学习中心',
  '参数模型',
  '用途分类',
  '敏感数据',
  '规范对比',
  '安全图谱',
  '调用拓扑',
  '接口风险',
  '影子与僵尸接口',
  '接口策略',
]

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

/** 确保侧边栏分组展开（antd SubMenu 关闭时子项不渲染；直接路由进入分组页面会自动展开，已展开则不重复点击） */
async function ensureMenuGroupOpen(page: Page, groupLabel: string, probeLabel: string) {
  const probe = page.getByRole('menuitem', { name: probeLabel })
  if ((await probe.count()) === 0) {
    await page.locator('.ant-menu-submenu-title', { hasText: groupLabel }).click()
  }
}

/**
 * 发布网关配置并轮询任务直至 SUCCESS（≤30s）。
 * 注意：配置版本号为秒级时间戳+配置哈希，同一秒内重复发布会撞 version_number
 * 唯一约束（SAVE_VERSION_FAILED duplicate key），跨秒重试即可（同 stage5 经验）。
 */
async function publishGatewayConfigAndWait(page: Page) {
  for (let attempt = 1; ; attempt++) {
    const csrf = await csrfToken(page)
    const resp = await page.request.post(`${API_URL}/gateway-config/publish`, {
      data: { idempotency_key: `e2e-s8-${Date.now()}-${rand()}` },
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

/**
 * 确保测试应用存在且配置已发布（应用缺失时按 stage5 编排最小要素创建：
 * OFF 防护模式避免 WAF/CRS 干扰，域名 waf-s5.local，源站指向 testorigin 容器）。
 */
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
  // 发布使网关挂接含 API 动态防护的 guard 管线（wdsp 覆盖下发布配置自带该能力）
  await publishGatewayConfigAndWait(page)
}

interface DiscoveredEndpoint {
  id: string
  endpointKey: string
}

/**
 * 经网关真实流量造端点发现数据：向唯一路径发送 3 笔 JSON POST（命中计数累积），
 * 管理面采集器 2s 轮询网关事件日志并 UpsertDiscovery，轮询端点列表直至出现（≤30s）。
 * 路径形如 /e2e/api/<tag>/orders/<n>，归一化后端点键为 POST /e2e/api/<tag>/orders/{id}。
 */
async function discoverEndpoint(page: Page, tag: string): Promise<DiscoveredEndpoint> {
  await ensureAppPublished(page)
  const endpointKey = `POST /e2e/api/${tag}/orders/{id}`
  for (let i = 1; i <= 3; i++) {
    await page.request.post(`${GATEWAY_URL}/e2e/api/${tag}/orders/${i}`, {
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

/** 在端点选择器（showSearch，optionFilterProp=label）中按端点键选中目标端点 */
async function selectEndpointByKey(page: Page, endpointKey: string) {
  const select = page.locator('.ant-select').first()
  await select.click()
  // 等待选项加载后输入端点键过滤
  await page.locator('.ant-select-item-option').first().waitFor()
  await page.keyboard.type(endpointKey)
  await page.locator('.ant-select-item-option', { hasText: endpointKey }).click()
}

/** 设置 API 防护模式（API 直达，用于用例4基线与恢复，等价于页面保存动作） */
async function setApiPolicyMode(page: Page, mode: 'OFF' | 'OBSERVE' | 'PROTECT') {
  const csrf = await csrfToken(page)
  const resp = await page.request.put(`${API_URL}/api-security/policy`, {
    data: { mode },
    headers: { 'X-CSRF-Token': csrf },
  })
  expect(resp.status(), `set api policy mode ${mode}: ${await resp.text()}`).toBe(200)
}

test.describe('阶段8：接口动态防护（WDSP）', () => {
  /* ==================== 1. 菜单可见性 ==================== */

  test('菜单可见性：接口防护分组12项与安全管理员核心页面', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    await page.goto('/dashboard')

    // 「接口防护」分组可见且含全部 12 个菜单项
    await ensureMenuGroupOpen(page, '接口防护', '接口端点资产')
    for (const label of API_SECURITY_MENU_LABELS) {
      await expect(page.getByRole('menuitem', { name: label })).toBeVisible()
    }

    // 逐一点击打开三个核心页面（URL + 页面标题断言）
    await page.getByRole('menuitem', { name: '接口端点资产' }).click()
    await expect(page).toHaveURL(/\/api-endpoints/)
    await expect(page.locator('.ant-card-head-title', { hasText: '接口端点资产' })).toBeVisible()

    await page.getByRole('menuitem', { name: '学习中心' }).click()
    await expect(page).toHaveURL(/\/api-learning/)
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 学习中心' })).toBeVisible()

    await page.getByRole('menuitem', { name: '接口策略' }).click()
    await expect(page).toHaveURL(/\/api-policy/)
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 动态防护策略' })).toBeVisible()
  })

  /* ==================== 2. 端点资产（任务书场景一） ==================== */

  test('端点资产：流量自动发现、中文状态标签、行内确认', async ({ page }) => {
    test.setTimeout(150_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    // 造数：网关 JSON 流量 → 采集器 → 端点自动发现（DISCOVERED）
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)

    await page.goto('/api-endpoints')
    await expect(page.locator('.ant-card-head-title', { hasText: '接口端点资产' })).toBeVisible()
    // 关键词过滤定位本用例端点
    await page.getByPlaceholder('路径 / 端点键').fill(tag)
    await page.keyboard.press('Enter')
    const row = page.locator('tr', { hasText: ep.endpointKey.replace(/^[A-Z]+ /, '') })
    await expect(row).toBeVisible({ timeout: 10000 })
    // 方法、路径模板与中文状态标签
    await expect(row).toContainText('POST')
    await expect(row.getByText('已发现')).toBeVisible()
    await expect(row.getByText('未开始')).toBeVisible()

    // 行内「确认」→ 二次确认 → 资产状态变「已确认」
    await row.getByRole('button', { name: '确认' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(row.getByText('已确认')).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 3. 模型版本（任务书场景三/四） ==================== */

  test('模型版本：创建候选并确认冻结为正式', async ({ page }) => {
    test.setTimeout(150_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)

    await page.goto('/api-models')
    await expect(page.locator('.ant-card-head-title', { hasText: '接口模型版本' })).toBeVisible()
    await selectEndpointByKey(page, ep.endpointKey)

    // 创建候选（Drawer 填 schema JSON）
    await page.getByRole('button', { name: '创建候选' }).click()
    const drawer = page.locator('.ant-drawer', { hasText: '创建候选版本' })
    await expect(drawer).toBeVisible()
    await drawer.locator('#schema_json').fill('{"order_id":"number","amount":"number","currency":"string"}')
    await drawer.getByPlaceholder('本次候选相对上一版本的变化').fill('E2E 初始候选')
    await drawer.getByRole('button', { name: /创 ?建/ }).click()

    // 列表出现候选版本
    const row = page.locator('tr', { hasText: ep.endpointKey.replace(/^[A-Z]+ /, '') })
    await expect(row.getByText('候选')).toBeVisible({ timeout: 10000 })

    // 确认冻结 → 状态变「正式」
    await row.getByRole('button', { name: '确认冻结' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(row.getByText('正式')).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 4. 策略页（模式持久化） ==================== */

  test('策略页：防护模式改防护保存后刷新保持，再恢复观察', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    // 基线统一为「观察」，避免历史运行残留的数据库覆盖影响脏检查
    await setApiPolicyMode(page, 'OBSERVE')

    await page.goto('/api-policy')
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 动态防护策略' })).toBeVisible()
    const modeItem = page
      .locator('.ant-descriptions-item')
      .filter({ has: page.locator('.ant-descriptions-item-label', { hasText: '防护模式' }) })
    await expect(modeItem.locator('.ant-tag', { hasText: '观察' })).toBeVisible({ timeout: 10000 })

    // 改「防护」→ 保存 → 二次确认
    await page.locator('.ant-radio-wrapper', { hasText: '防护' }).click()
    await page.getByRole('button', { name: /保 ?存/ }).click()
    await page.locator('.ant-modal').getByRole('button', { name: '确认保存' }).click()
    await expect(modeItem.locator('.ant-tag', { hasText: '防护' })).toBeVisible({ timeout: 10000 })
    // 模式来源变为「数据库」（db 覆盖）
    await expect(page.locator('.ant-descriptions-item', { hasText: '模式来源' })).toContainText('数据库')

    // 刷新页面模式保持（数据库覆盖生效，不回退 env/default）
    await page.reload()
    await expect(modeItem.locator('.ant-tag', { hasText: '防护' })).toBeVisible({ timeout: 10000 })

    // 恢复「观察」（不污染环境）
    await page.locator('.ant-radio-wrapper', { hasText: '观察' }).click()
    await page.getByRole('button', { name: /保 ?存/ }).click()
    await page.locator('.ant-modal').getByRole('button', { name: '确认保存' }).click()
    await expect(modeItem.locator('.ant-tag', { hasText: '观察' })).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 5. 学习中心 ==================== */

  test('学习中心：启动学习变学习中，停止后已暂停', async ({ page }) => {
    test.setTimeout(150_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)

    await page.goto('/api-learning')
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 学习中心' })).toBeVisible()
    await selectEndpointByKey(page, ep.endpointKey)

    // 启动学习 → 学习状态变「学习中」，操作切换为「停止学习」
    await page.getByRole('button', { name: '启动学习' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.locator('.ant-tag', { hasText: '学习中' })).toBeVisible({ timeout: 10000 })
    await expect(page.getByRole('button', { name: '停止学习' })).toBeVisible()

    // 停止学习 → 学习状态变「已暂停」（样本保留，可再次启动）
    await page.getByRole('button', { name: '停止学习' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.locator('.ant-tag', { hasText: '已暂停' })).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 6. 权限（审计管理员只读） ==================== */

  test('权限：审计管理员菜单可见但行内操作按钮不渲染', async ({ page }) => {
    test.setTimeout(150_000)
    // 先以安全管理员造一条 DISCOVERED 端点（用于验证只读行内无「确认/忽略」按钮）
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)

    // 系统管理员现场创建 AUDIT_ADMIN 用户并完成首次改密
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    const username = `e2e_audit_${rand()}`
    const { password: tempPwd } = await createUserViaAPI(page, username, 'AUDIT_ADMIN')
    const newPwd = 'AuditAdmin@S8!2026'
    await loginViaAPI(page, username, tempPwd)
    await changePasswordViaAPI(page, tempPwd, newPwd)
    await page.context().clearCookies()
    await loginViaAPI(page, username, newPwd)

    // 接口防护菜单可见（审计管理员拥有全部只读权限点）
    await page.goto('/api-endpoints')
    await ensureMenuGroupOpen(page, '接口防护', '接口端点资产')
    for (const label of API_SECURITY_MENU_LABELS) {
      await expect(page.getByRole('menuitem', { name: label })).toBeVisible()
    }

    // 端点列表可读、中文状态可见，但行内「确认/忽略」按钮不渲染
    await page.getByPlaceholder('路径 / 端点键').fill(tag)
    await page.keyboard.press('Enter')
    const row = page.locator('tr', { hasText: ep.endpointKey.replace(/^[A-Z]+ /, '') })
    await expect(row).toBeVisible({ timeout: 10000 })
    await expect(row.getByText('已发现')).toBeVisible()
    await expect(row.getByRole('button', { name: '确认' })).toHaveCount(0)
    await expect(row.getByRole('button', { name: '忽略' })).toHaveCount(0)

    // 模型版本页：列表可读，但「创建候选」不渲染
    await page.goto('/api-models')
    await expect(page.locator('.ant-card-head-title', { hasText: '接口模型版本' })).toBeVisible()
    await expect(page.getByRole('button', { name: '创建候选' })).toHaveCount(0)

    // 策略页：当前模式可读，但「保存」「发布到网关」均不渲染
    await page.goto('/api-policy')
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 动态防护策略' })).toBeVisible()
    await expect(
      page.locator('.ant-descriptions-item-label', { hasText: '防护模式' }),
    ).toBeVisible()
    await expect(page.getByRole('button', { name: /保 ?存/ })).toHaveCount(0)
    await expect(page.getByRole('button', { name: '发布到网关' })).toHaveCount(0)
  })

  /* ==================== 7. WAF 产品形态 ==================== */

  // 需以 PRODUCT_EDITION=waf 重启环境（stage5 编排默认形态，不叠加 docker-compose.wdsp.yml）
  // 后单独执行：该形态下「接口防护」菜单不可见、直访路由跳转 /404。
  // 当前 WDSP 环境下跳过；CI 应以 waf 形态作为独立 job 运行本用例（去掉 test.skip 标记）。
  test.skip('WAF形态：接口防护菜单不可见（需 waf 形态环境单独运行）', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/dashboard')
    await expect(page.locator('.ant-menu-submenu-title', { hasText: '接口防护' })).toHaveCount(0)
    await page.goto('/api-endpoints')
    await expect(page).toHaveURL(/\/404/)
  })

  /* ==================== 8. 动态参数学习（任务书场景二） ==================== */

  test('参数学习：学习完成后参数模型呈现字符串/数字/数组/对象与置信度', async ({ page }) => {
    test.setTimeout(420_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)

    // 启动学习（样本目标取下限 10 加速完成；默认条件 min_valid_samples=10、min_unique_ips=1）
    await page.goto('/api-learning')
    await expect(page.locator('.ant-card-head-title', { hasText: 'API 学习中心' })).toBeVisible()
    await selectEndpointByKey(page, ep.endpointKey)
    await page.getByRole('button', { name: '启动学习' }).click()
    const startModal = page.locator('.ant-modal')
    await startModal.locator('.ant-input-number input').fill('10')
    await startModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.locator('.ant-tag', { hasText: '学习中' })).toBeVisible({ timeout: 10000 })

    // 发送 12 组同字段不同取值流量（字符串/数字/数组/对象各一），唯一 X-Request-Id 防样本幂等键碰撞
    for (let i = 1; i <= 12; i++) {
      await page.request.post(`${GATEWAY_URL}/e2e/api/${tag}/orders/${100 + i}`, {
        headers: {
          Host: HOST,
          'Content-Type': 'application/json',
          'X-Request-Id': randomUUID(),
        },
        data: { name: `widget-${i}`, amount: i * 10 + 0.5, tags: ['e2e', `t${i}`], meta: { channel: 'e2e' } },
      })
    }

    // 等待学习完成（采集 2s 轮询 + 学习调度默认 30s 周期）
    let learned = false
    const deadline = Date.now() + 240_000
    while (Date.now() < deadline) {
      const st = await page.request.get(`${API_URL}/api-security/endpoints/${ep.id}/learning/status`)
      const data = (await st.json())?.data
      if (data?.learning_status === 'LEARNED' || data?.job?.status === 'COMPLETED') {
        learned = true
        break
      }
      await page.waitForTimeout(3000)
    }
    expect(learned, '学习应在 240s 内完成（有效样本达 10）').toBeTruthy()

    // 学习中心 UI：任务已完成、样本目标/已采集可见；有效样本数经 API 复核达标
    await page.reload()
    const jobCard = page
      .locator('.ant-card')
      .filter({ has: page.locator('.ant-card-head-title', { hasText: '学习任务' }) })
    await expect(jobCard.getByText('已完成')).toBeVisible({ timeout: 15000 })
    await expect(jobCard.getByText('样本目标')).toBeVisible()
    const stResp = await page.request.get(`${API_URL}/api-security/endpoints/${ep.id}/learning/status`)
    const job = (await stResp.json())?.data?.job
    expect(job?.valid_count, '有效样本数应达到样本目标 10').toBeGreaterThanOrEqual(10)

    // 参数模型页：选择接口（版本选择器自动选中学习生成的候选），验证字段类型模型与置信度
    await page.goto('/api-parameters')
    await expect(page.locator('.ant-card-head-title', { hasText: '参数模型' })).toBeVisible()
    await page.locator('.ant-select', { hasText: '选择接口' }).click()
    await page.locator('.ant-select-item-option').first().waitFor()
    await page.keyboard.type(ep.endpointKey)
    await page.locator('.ant-select-item-option', { hasText: ep.endpointKey }).click()
    // 逐字段断言基础类型（类型模型而非具体取值/字段名单）
    for (const [param, typeLabel] of [
      ['name', '字符串'],
      ['amount', '数字'],
      ['tags', '数组'],
      ['meta', '对象'],
    ] as const) {
      const prow = page
        .locator('tbody tr')
        .filter({ has: page.locator('code', { hasText: new RegExp(`^${param}$`) }) })
      await expect(prow, `参数 ${param} 应出现在参数模型中`).toHaveCount(1, { timeout: 15000 })
      await expect(prow.getByText(typeLabel)).toBeVisible()
    }
    // 置信度列呈现百分比
    await expect(page.locator('tbody').getByText(/\d+%/).first()).toBeVisible()
  })

  /* ==================== 9. 模型冻结 + 偏离不进学习（任务书场景四） ==================== */

  test('模型冻结：偏离请求产生模型校验事件、正式模型不变且偏离样本不进学习', async ({ page }) => {
    test.setTimeout(480_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    await setApiPolicyMode(page, 'OBSERVE')
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)

    // 1. 确认参数范围：创建候选 {id:number} → 确认冻结 → 激活 → 发布（正式模型下发网关）
    await page.goto('/api-models')
    await selectEndpointByKey(page, ep.endpointKey)
    await page.getByRole('button', { name: '创建候选' }).click()
    const createDrawer = page.locator('.ant-drawer', { hasText: '创建候选版本' })
    await expect(createDrawer).toBeVisible()
    await createDrawer.locator('#schema_json').fill('{"id":"number"}')
    await createDrawer.getByRole('button', { name: /创 ?建/ }).click()
    const row = page.locator('tr', { hasText: ep.endpointKey.replace(/^[A-Z]+ /, '') })
    await expect(row.getByText('候选')).toBeVisible({ timeout: 10000 })
    await row.getByRole('button', { name: '确认冻结' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(row.getByText('正式')).toBeVisible({ timeout: 10000 })
    // 记录正式模型哈希与版本数（偏离后比对「正式模型未变化」）
    const listModels = async () => {
      const resp = await page.request.get(
        `${API_URL}/api-security/endpoints/${ep.id}/models?page=1&page_size=50`,
      )
      expect(resp.status(), 'list model versions').toBe(200)
      return ((await resp.json())?.data?.items ?? []) as Array<{
        status: string
        content_hash: string
        version_number: number
      }>
    }
    const before = await listModels()
    const formalBefore = before.filter((m) => m.status === 'FORMAL')
    expect(formalBefore).toHaveLength(1)
    await row.getByRole('button', { name: '激活' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText(/已激活/).first()).toBeVisible({ timeout: 10000 })
    await publishGatewayConfigAndWait(page)

    // 2. 发送超出参数范围请求（id 应为 number，实发 string → schema.type_mismatch）
    for (let i = 0; i < 3; i++) {
      await page.request.post(`${GATEWAY_URL}/e2e/api/${tag}/orders/${200 + i}`, {
        headers: {
          Host: HOST,
          'Content-Type': 'application/json',
          'X-Request-Id': randomUUID(),
        },
        data: { id: `not-a-number-${i}` },
      })
    }
    // 3. 验证生成风险事件：统一事件含 api_schema（模型校验）明细
    let hasSchemaEvent = false
    const evDeadline = Date.now() + 60_000
    while (Date.now() < evDeadline) {
      const resp = await page.request.get(
        `${API_URL}/api-security/runtime/events?endpoint_key=${encodeURIComponent(ep.endpointKey)}&page=1&page_size=20`,
      )
      expect(resp.status(), 'list runtime events').toBe(200)
      const items = ((await resp.json())?.data?.items ?? []) as Array<{
        details?: Array<{ detector?: string }> | null
      }>
      if (items.some((e) => (e.details ?? []).some((d) => d.detector === 'api_schema'))) {
        hasSchemaEvent = true
        break
      }
      await page.waitForTimeout(2000)
    }
    expect(hasSchemaEvent, '偏离请求应在 60s 内产生含模型校验明细的统一事件').toBeTruthy()

    // UI：运行时事件详情呈现模型校验明细
    await page.goto('/api-runtime-events')
    await page.getByPlaceholder(/接口键/).fill(ep.endpointKey)
    await page.keyboard.press('Enter')
    const firstRow = page.locator('tbody tr').first()
    await expect(firstRow).toBeVisible({ timeout: 10000 })
    await firstRow.getByRole('button', { name: '详情' }).click()
    const evDrawer = page.locator('.ant-drawer-content')
    await expect(evDrawer.getByText('检测明细（details）')).toBeVisible({ timeout: 10000 })
    await expect(evDrawer.getByText('模型校验').first()).toBeVisible()
    await expect(evDrawer.getByText(/type mismatch/).first()).toBeVisible()
    await page.keyboard.press('Escape')

    // 4. 正式模型未变化：版本数与 FORMAL 哈希均不变（偏离不自动扩宽）
    const after = await listModels()
    expect(after.length, '偏离不得产生新模型版本').toBe(before.length)
    expect(after.find((m) => m.status === 'FORMAL')?.content_hash).toBe(formalBefore[0].content_hash)

    // 5. 异常请求未进入学习：启动学习后偏离流量全部排除（schema_deviation），无一采纳
    const start = await page.request.post(`${API_URL}/api-security/endpoints/${ep.id}/learning/start`, {
      data: { sample_target: 10 },
      headers: { 'X-CSRF-Token': await csrfToken(page) },
    })
    expect(start.status(), `start learning: ${await start.text()}`).toBe(200)
    for (let i = 0; i < 2; i++) {
      await page.request.post(`${GATEWAY_URL}/e2e/api/${tag}/orders/${300 + i}`, {
        headers: {
          Host: HOST,
          'Content-Type': 'application/json',
          'X-Request-Id': randomUUID(),
        },
        data: { id: `still-not-a-number-${i}` },
      })
    }
    let excludedSeen = false
    const sampleDeadline = Date.now() + 60_000
    while (Date.now() < sampleDeadline) {
      const resp = await page.request.get(
        `${API_URL}/api-security/endpoints/${ep.id}/learning/samples?accepted=false&page=1&page_size=20`,
      )
      const items = ((await resp.json())?.data?.items ?? []) as Array<{ exclude_reason?: string }>
      if (items.some((s) => s.exclude_reason === 'schema_deviation')) {
        excludedSeen = true
        break
      }
      await page.waitForTimeout(2000)
    }
    expect(excludedSeen, '偏离请求应以 schema_deviation 排除在学习样本之外').toBeTruthy()
    const accepted = await page.request.get(
      `${API_URL}/api-security/endpoints/${ep.id}/learning/samples?accepted=true&page=1&page_size=1`,
    )
    expect(
      (await accepted.json())?.data?.total ?? 0,
      '偏离请求不得进入有效学习样本',
    ).toBe(0)

    // UI 学习中心：已排除样本可见排除原因；随后停止学习恢复现场
    await page.goto('/api-learning')
    await selectEndpointByKey(page, ep.endpointKey)
    await page.locator('.ant-select', { hasText: '样本状态' }).click()
    await page
      .locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option', {
        hasText: '已排除',
      })
      .click()
    await expect(page.locator('tbody').getByText('schema_deviation').first()).toBeVisible({
      timeout: 10000,
    })
    await page.getByRole('button', { name: '停止学习' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.locator('.ant-tag', { hasText: '已暂停' })).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 10. 重新学习分支对比（任务书场景五） ==================== */

  test('重新学习：正式模型持续检测偏离，学习分支完成后对比并确认激活新版本', async ({ page }) => {
    test.setTimeout(600_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    await setApiPolicyMode(page, 'OBSERVE')
    const tag = randTag()
    const ep = await discoverEndpoint(page, tag)
    const csrf = await csrfToken(page)

    // 1. 准备正式模型 v1（API 快速建：创建/冻结/激活的 UI 全流程已由用例3/用例9 覆盖）
    const create = await page.request.post(`${API_URL}/api-security/endpoints/${ep.id}/models`, {
      data: { schema: { id: 'number' }, change_summary: 'E2E 场景五 v1' },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(create.status(), `create candidate: ${await create.text()}`).toBe(200)
    const v1 = (await create.json())?.data?.version
    expect(v1?.id).toBeTruthy()
    const confirm1 = await page.request.post(`${API_URL}/api-security/models/${v1.id}/confirm`, {
      data: {},
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(confirm1.status(), `confirm v1: ${await confirm1.text()}`).toBe(200)
    const activate1 = await page.request.post(`${API_URL}/api-security/models/${v1.id}/activate`, {
      data: {},
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(activate1.status(), `activate v1: ${await activate1.text()}`).toBe(200)
    await publishGatewayConfigAndWait(page)

    // 2. 正式版本继续检测：带未定义字段 remark 的流量 → schema.undefined_field 偏离事件
    for (let i = 0; i < 2; i++) {
      await page.request.post(`${GATEWAY_URL}/e2e/api/${tag}/orders/${400 + i}`, {
        headers: {
          Host: HOST,
          'Content-Type': 'application/json',
          'X-Request-Id': randomUUID(),
        },
        data: { id: 400 + i, remark: `new-field-${i}` },
      })
    }
    let deviationSeen = false
    const devDeadline = Date.now() + 60_000
    while (Date.now() < devDeadline) {
      const resp = await page.request.get(
        `${API_URL}/api-security/runtime/events?endpoint_key=${encodeURIComponent(ep.endpointKey)}&page=1&page_size=20`,
      )
      const items = ((await resp.json())?.data?.items ?? []) as Array<{
        details?: Array<{ rule_id?: string }> | null
      }>
      if (items.some((e) => (e.details ?? []).some((d) => d.rule_id === 'schema.undefined_field'))) {
        deviationSeen = true
        break
      }
      await page.waitForTimeout(2000)
    }
    expect(deviationSeen, '重新学习前正式模型应持续检测未定义字段偏离').toBeTruthy()

    // 3. 从正式版本启动重新学习（UI 入口）
    await page.goto('/api-models')
    await selectEndpointByKey(page, ep.endpointKey)
    await page.getByRole('button', { name: '重新学习' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText(/学习任务已启动/).first()).toBeVisible({ timeout: 10000 })

    // 4. 新业务流量：与正式模型同形状的字段才进学习（偏离流量被排除，见用例9）
    for (let i = 1; i <= 12; i++) {
      await page.request.post(`${GATEWAY_URL}/e2e/api/${tag}/orders/${500 + i}`, {
        headers: {
          Host: HOST,
          'Content-Type': 'application/json',
          'X-Request-Id': randomUUID(),
        },
        data: { id: 500 + i },
      })
    }
    let relearned = false
    const learnDeadline = Date.now() + 240_000
    while (Date.now() < learnDeadline) {
      const st = await page.request.get(`${API_URL}/api-security/endpoints/${ep.id}/learning/status`)
      const data = (await st.json())?.data
      if (data?.learning_status === 'LEARNED' || data?.job?.status === 'COMPLETED') {
        relearned = true
        break
      }
      await page.waitForTimeout(3000)
    }
    expect(relearned, '重新学习应在 240s 内完成').toBeTruthy()

    // 5. 对比学习分支：学习达标自动生成 v2（自动提交评审），与 v1 字段级对比
    await page.reload()
    await page.locator('.ant-select').first().click()
    await page.locator('.ant-select-item-option').first().waitFor()
    await page.keyboard.type(ep.endpointKey)
    await page.locator('.ant-select-item-option', { hasText: ep.endpointKey }).click()
    const rows = page.locator('tbody tr', { hasText: ep.endpointKey.replace(/^[A-Z]+ /, '') })
    await expect(rows, '学习完成后应存在 v1/v2 两个版本').toHaveCount(2, { timeout: 15000 })
    const v2row = page.locator('tbody tr', { hasText: 'v2' })
    await expect(v2row.getByText('评审中')).toBeVisible()
    await v2row.getByRole('button', { name: '对比' }).click()
    const diffDrawer = page.locator('.ant-drawer-content')
    await expect(diffDrawer.getByText(/版本对比：v2/)).toBeVisible()
    await diffDrawer.locator('.ant-select').click()
    await page
      .locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option', {
        hasText: 'v1 · 正式',
      })
      .click()
    // 差异分区渲染（新业务流量与正式模型同形状：新增/移除/类型变化均应为「无」）
    await expect(diffDrawer.getByText('新增字段')).toBeVisible()
    await expect(diffDrawer.getByText('移除字段')).toBeVisible()
    await expect(diffDrawer.getByText('类型变化')).toBeVisible()
    await expect(diffDrawer.getByText('无').first()).toBeVisible({ timeout: 10000 })
    await page.keyboard.press('Escape')

    // 6. 确认新版本并激活：v2 冻结为正式（v1 已被取代），再激活为当前模型
    await v2row.getByRole('button', { name: '确认冻结' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(v2row.getByText('正式')).toBeVisible({ timeout: 10000 })
    const v1row = page.locator('tbody tr', { hasText: 'v1' })
    await expect(v1row.getByText('已被取代')).toBeVisible({ timeout: 10000 })
    await v2row.getByRole('button', { name: '激活' }).click()
    await page.locator('.ant-modal').getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText(/已激活/).first()).toBeVisible({ timeout: 10000 })
  })

  /* ==================== 11. 统一事件：单主事件多明细（任务书场景六） ==================== */

  test('统一事件：同请求同时命中WAF与Schema偏离只生成一个主事件且含多条检测明细', async ({ page }) => {
    test.setTimeout(600_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    await setApiPolicyMode(page, 'OBSERVE')
    await ensureAppPublished(page)

    // 将测试应用防护模式临时切为观察（WAF 检测不阻断，保证请求走完统一管线）；
    // 结束后恢复 OFF 并重新发布（不污染环境）。
    const appList = await page.request.get(
      `${API_URL}/applications?keyword=${APP_CODE}&page=1&page_size=100`,
    )
    const app = ((await appList.json())?.data?.items ?? []).find(
      (a: { code: string }) => a.code === APP_CODE,
    ) as { id: string } | undefined
    if (!app) throw new Error('测试应用应存在')
    const appDetailResp = await page.request.get(`${API_URL}/applications/${app.id}`)
    const appDetail = (await appDetailResp.json())?.data
    const setProtectionMode = async (mode: 'OFF' | 'OBSERVE') => {
      const csrfNow = await csrfToken(page)
      const resp = await page.request.put(`${API_URL}/applications/${app.id}`, {
        data: {
          name: appDetail.name,
          description: appDetail.description,
          business_owner: appDetail.business_owner,
          technical_owner: appDetail.technical_owner,
          protection_mode: mode,
          version: appDetail.version,
        },
        headers: { 'X-CSRF-Token': csrfNow },
      })
      expect(resp.status(), `set protection_mode ${mode}: ${await resp.text()}`).toBe(200)
      appDetail.version += 1
      await publishGatewayConfigAndWait(page)
    }
    await setProtectionMode('OBSERVE')

    try {
      // 准备正式模型 {id:number} 并发布（Schema 偏离检测生效）
      const tag = randTag()
      const ep = await discoverEndpoint(page, tag)
      const csrf = await csrfToken(page)
      const create = await page.request.post(`${API_URL}/api-security/endpoints/${ep.id}/models`, {
        data: { schema: { id: 'number' }, change_summary: 'E2E 场景六' },
        headers: { 'X-CSRF-Token': csrf },
      })
      expect(create.status(), `create candidate: ${await create.text()}`).toBe(200)
      const v1 = (await create.json())?.data?.version
      for (const action of ['confirm', 'activate']) {
        const r = await page.request.post(`${API_URL}/api-security/models/${v1.id}/${action}`, {
          data: {},
          headers: { 'X-CSRF-Token': csrf },
        })
        expect(r.status(), `${action} v1: ${await r.text()}`).toBe(200)
      }
      await publishGatewayConfigAndWait(page)

      // 构造同时命中 WAF（SQLi 特征）与 Schema 偏离（id 类型不匹配）的请求，唯一请求 ID 便于断言单主事件
      const requestId = randomUUID()
      await page.request.post(`${GATEWAY_URL}/e2e/api/${tag}/orders/999`, {
        headers: {
          Host: HOST,
          'Content-Type': 'application/json',
          'X-Request-Id': requestId,
        },
        data: { id: "1' OR '1'='1" },
      })

      // 断言：该请求仅一个主事件，且明细同时含 waf 与 api_schema
      interface RuntimeEventItem {
        request_id?: string
        details?: Array<{ detector?: string }> | null
      }
      let mainEvent: RuntimeEventItem | null = null
      let mainCount = 0
      const deadline = Date.now() + 60_000
      while (Date.now() < deadline) {
        const resp = await page.request.get(
          `${API_URL}/api-security/runtime/events?endpoint_key=${encodeURIComponent(ep.endpointKey)}&page=1&page_size=50`,
        )
        expect(resp.status(), 'list runtime events').toBe(200)
        const items = ((await resp.json())?.data?.items ?? []) as RuntimeEventItem[]
        const mine = items.filter((e) => e.request_id === requestId)
        if (
          mine.length === 1 &&
          (mine[0].details ?? []).some((d) => d.detector === 'waf') &&
          (mine[0].details ?? []).some((d) => d.detector === 'api_schema')
        ) {
          mainCount = mine.length
          mainEvent = mine[0]
          break
        }
        await page.waitForTimeout(2000)
      }
      expect(mainCount, '同一请求只应生成一个统一主事件').toBe(1)
      expect(mainEvent, '主事件应同时含 WAF 与模型校验明细').toBeTruthy()

      // UI：运行时事件详情抽屉呈现多条检测明细（WAF 检测 + 模型校验）
      await page.goto('/api-runtime-events')
      await page.getByPlaceholder(/接口键/).fill(ep.endpointKey)
      await page.keyboard.press('Enter')
      const firstRow = page.locator('tbody tr').first()
      await expect(firstRow).toBeVisible({ timeout: 10000 })
      await firstRow.getByRole('button', { name: '详情' }).click()
      const evDrawer = page.locator('.ant-drawer-content')
      await expect(evDrawer.getByText('运行时事件详情')).toBeVisible({ timeout: 10000 })
      await expect(evDrawer.getByText(requestId)).toBeVisible()
      await expect(evDrawer.getByText('检测明细（details）')).toBeVisible()
      await expect(evDrawer.getByText('WAF 检测').first()).toBeVisible()
      await expect(evDrawer.getByText('模型校验').first()).toBeVisible()
    } finally {
      await setProtectionMode('OFF')
    }
  })
})
