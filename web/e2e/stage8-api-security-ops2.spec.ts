import { test, expect, type Locator, type Page } from '@playwright/test'
import { loginViaAPI, API_URL } from './helpers'

/**
 * 阶段8 E2E 增补二：API 安全 W15 六个新页面的真实 UI 流（第十六波）
 *
 * 与 stage8-api-security.spec.ts（菜单/发现/模型/策略/学习/权限基线）与
 * stage8-api-security-ops.spec.ts（风险/弱点/脱敏/敏感类型/规范/授权/扫描/运行时策略）互补，
 * 本规格覆盖第十五波注册的 6 个管理页面，每场景独立 test、名称带随机标签避免相互污染：
 *
 * - 用例1 AI 运营（/api-ai-ops）          计划 Tab 渲染 → 新建计划弹窗（任务类型下拉、非法 cron
 *                                         前端预检提示）→ 创建 → 启停开关 → 运行记录 Tab
 * - 用例2 LLM 观测（/api-llm）            五统计卡/模型分布/列表渲染 → 模型过滤空态 →
 *                                         仅看命中勾选 → 统计窗口 7天→30天 切换
 * - 用例3 数据出境（/api-cross-border）   看板骨架渲染 + geo_enabled 两种形态兼容断言
 *                                         （false 降级警示卡 / true 无警示看板直出）
 * - 用例4 服务资产（/api-service-assets） 聚合表渲染：有数据校验 host:port 行形态，无数据空态友好
 * - 用例5 节点校验（/api-nodes）          节点列表 + 一致性横幅（一致/不一致/无版本数据三形态兼容）
 * - 用例6 文件合规（/api-file-compliance）规则列表 → 新建弹窗（match_type 联动提示切换：
 *                                         EXT→MIME 占位符与说明同步变化）→ 启停开关 → 删除清理
 *
 * 先决数据条件（逐场景说明，写操作全部真实落库，无 mock）：
 * - 用例1/6 纯管理面 CRUD，无流量先决；计划与规则名带随机标签幂等重跑；
 *   用例1 结尾将计划停回创建时默认（不留活动计划），用例6 结尾删除规则清理现场。
 * - 用例2/3/4/5 为只读看板/列表页，不造数；无业务数据时零值统计与「暂无数据」空态均为合法形态。
 * - 用例3 形态取决于 GeoIP 数据源（runtime/geoip/country.mmdb 是否部署进 api 容器数据目录）：
 *   stage5 编排默认未挂载 → geo_enabled=false 降级卡分支；部署后走看板分支。spec 按接口实际
 *   返回的 geo_enabled 分支断言，两种形态均判通过。
 * - 用例5 横幅形态取决于网关节点事件上报（本规格不产生网关流量，沿用环境既有节点数据），
 *   三种形态（一致/不一致/无版本数据可比）均判通过。
 *
 * 环境依赖（与 stage8-api-security.spec.ts 一致）：
 * - stage5 编排 + wdsp 覆盖（PRODUCT_EDITION=wdsp 且 API_DYNAMIC_PROTECTION_ENABLED=true），
 *   管理 API 127.0.0.1:18081，Valkey 127.0.0.1:16379（VALKEY_HOST/VALKEY_PORT 可覆盖）；
 *   前端 vite dev 经 E2E_BASE_URL 指定（默认 http://localhost:5173；本机 5173 被其他项目占用时
 *   用本项目实际端口，如 E2E_BASE_URL=http://localhost:5374）。
 * - 测试用户：安全管理员 sec_admin_s5（E2E_SEC_USER/E2E_SEC_PWD 可覆盖），SECURITY_ADMIN 预置
 *   本规格全部权限点（api_ai.execute/api_data.manage/api_runtime.read/api_asset.read 等）。
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'

/** 路径段随机标签：仅小写字母，保证造数名称每次运行唯一（与 stage8 既有规格一致） */
const randTag = () =>
  'e2e' + Array.from({ length: 6 }, () => String.fromCharCode(97 + Math.floor(Math.random() * 26))).join('')

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

/** 当前展开下拉中的选项（stage7/stage8 既有模式：只匹配未隐藏 dropdown） */
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

/** 在对话框范围内按字段标签定位并点击下拉，再点选可见选项 */
async function pickSelectOption(page: Page, dialog: Locator, field: string, optionText: string | RegExp) {
  await openFormItemSelect(page, dialog, field)
  await dropdownOption(page, optionText).first().click()
}

/** 确认弹框（modal.confirm / Form Modal 共用 .ant-modal 容器，同一场景同一时刻仅一个弹层） */
function confirmDialog(page: Page): Locator {
  return page.locator('.ant-modal')
}

test.describe('阶段8：API 安全 W15 新页面（ops2）', () => {
  /* ==================== 1. AI 运营 ==================== */

  test('AI运营：计划Tab渲染→新建弹窗（类型下拉/非法cron提示）→启停→运行记录Tab', async ({ page }) => {
    test.setTimeout(120_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()
    const name = `e2e-ai-${tag}`

    await page.goto('/api-ai-ops')
    await expect(page.locator('.ant-card-head-title', { hasText: 'AI 定时运营' })).toBeVisible()
    // 计划 Tab 默认激活，计划列表表头渲染
    await expect(page.getByRole('tab', { name: '计划' })).toBeVisible()
    await expect(page.getByRole('tab', { name: '运行记录' })).toBeVisible()
    await expect(page.locator('.ant-tabs-tab-active', { hasText: '计划' })).toBeVisible()
    await expect(page.locator('.ant-table-thead').getByText('计划名称')).toBeVisible()
    await expect(page.locator('.ant-table-thead').getByText('cron 表达式')).toBeVisible()

    // 新建计划弹窗：任务类型下拉（词表来自 /task-types，接口异常时回退同名本地词表）
    await page.getByRole('button', { name: '新建计划' }).click()
    const dialog = confirmDialog(page)
    await expect(dialog.getByText('新建运营计划')).toBeVisible()
    await pickSelectOption(page, dialog, 'task_type', '资产变化摘要（API_ASSET_DIGEST）')
    await dialog.locator('#name').fill(name)
    // 非法 cron：五段但含非法字符 → 前端预检提示（仅提示不发请求，后端为权威校验）
    await dialog.locator('#cron_expr').fill('JAN MON * * *')
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    await expect(
      page.getByText('cron 表达式仅支持数字与 * , - / 字符（不支持 JAN/MON 等名字）'),
    ).toBeVisible()
    // 修正为合法五段 → 创建成功
    await dialog.locator('#cron_expr').fill('0 7 * * *')
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('计划已创建')).toBeVisible({ timeout: 10000 })
    const row = page.locator('tbody tr', { hasText: name })
    await expect(row).toBeVisible({ timeout: 10000 })
    await expect(row.getByText('0 7 * * *')).toBeVisible()

    // 启停开关：启用 → 成功反馈且开关置位；再停用恢复创建默认（不留活动计划污染环境）
    await row.locator('.ant-switch').click()
    await expect(page.getByText(`计划「${name}」已启用`)).toBeVisible({ timeout: 10000 })
    await expect(row.locator('.ant-switch')).toHaveAttribute('aria-checked', 'true', {
      timeout: 10000,
    })
    await row.locator('.ant-switch').click()
    await expect(page.getByText(`计划「${name}」已停用`)).toBeVisible({ timeout: 10000 })
    await expect(row.locator('.ant-switch')).toHaveAttribute('aria-checked', 'false', {
      timeout: 10000,
    })

    // 运行记录 Tab：未选计划空态提示 → 选择本计划 → 执行记录表渲染（可为空）
    await page.getByRole('tab', { name: '运行记录' }).click()
    await expect(page.locator('.ant-tabs-content-active').getByText('请先选择计划')).toBeVisible()
    await page.locator('.ant-tabs-content-active .ant-select').first().click()
    await page.locator('.ant-select-item-option').first().waitFor()
    await page.keyboard.type(name)
    await dropdownOption(page, name).click()
    await expect(
      page.locator('.ant-tabs-content-active .ant-table-thead').getByText('开始时间'),
    ).toBeVisible({ timeout: 10000 })
    await expect(page.locator('.ant-tabs-content-active .ant-table-thead').getByText('耗时')).toBeVisible()
  })

  /* ==================== 2. LLM 观测 ==================== */

  test('LLM观测：stats与列表渲染→模型过滤空态→仅看命中→窗口切换', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)

    // 接口锚定：stats/observations 必须 200（防止旧二进制 404 时零值渲染被误判通过）
    const statsPromise = page.waitForResponse(
      (r) => r.url().includes('/api-security/llm/stats') && r.status() === 200,
      { timeout: 15000 },
    )
    const listPromise = page.waitForResponse(
      (r) => r.url().includes('/api-security/llm/observations') && r.status() === 200,
      { timeout: 15000 },
    )
    await page.goto('/api-llm')
    await statsPromise
    await listPromise
    await expect(page.locator('.ant-card-head-title', { hasText: 'LLM API 观测' })).toBeVisible()
    // stats 区域五卡（无观测数据时零值亦为合法形态）
    for (const title of ['观测总数', '命中观测', 'token 合计', '流式调用', '涉及模型']) {
      await expect(page.locator('.ant-statistic-title', { hasText: title })).toBeVisible()
    }
    // 模型分布图卡与观测列表表头
    await expect(page.locator('.ant-card-head-title', { hasText: '模型分布（按观测数）' })).toBeVisible()
    await expect(page.locator('.ant-table-thead').getByText('prompt 长度桶')).toBeVisible()
    await expect(page.locator('.ant-table-thead').getByText('MCP 方法')).toBeVisible()
    await expect(page.getByPlaceholder('API 键（精确匹配）')).toBeVisible()

    // 模型过滤：搜索不存在模型 → 列表空态友好（暂无数据；antd Empty 含 SVG title 同名节点，定位 description）
    const modelSearch = page.getByPlaceholder('模型（精确匹配，如 gpt-4o）')
    await modelSearch.fill(`gpt-none-${randTag()}`)
    await modelSearch.press('Enter')
    await expect(page.locator('.ant-table-tbody .ant-empty-description')).toHaveText('暂无数据', {
      timeout: 10000,
    })
    // 清空恢复全量（交互反馈：查询条件移除）
    await modelSearch.fill('')
    await modelSearch.press('Enter')

    // 仅看命中观测：勾选即按 findings_only 重新查询（复选框置为选中）
    const findingsOnly = page.locator('.ant-checkbox-wrapper', { hasText: '仅看命中观测' })
    await findingsOnly.click()
    await expect(findingsOnly.locator('input')).toBeChecked()

    // 统计窗口切换 7天→30天（stats 与列表共用窗口口径）
    await page.locator('.ant-radio-button-wrapper', { hasText: '30天' }).click()
    await expect(page.locator('.ant-radio-button-wrapper-checked', { hasText: '30天' })).toBeVisible()
  })

  /* ==================== 3. 数据出境 ==================== */

  test('数据出境：看板骨架渲染 + geo_enabled 降级/看板两种形态兼容断言', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)

    // 先挂响应等待再进页面，按接口实际 geo_enabled 分支断言（两种形态均合法）
    const respPromise = page.waitForResponse(
      (r) => r.url().includes('/api-security/cross-border') && r.status() === 200,
      { timeout: 15000 },
    )
    await page.goto('/api-cross-border')
    const resp = await respPromise
    const geoEnabled = (await resp.json())?.data?.geo_enabled

    await expect(page.locator('.ant-card-head-title', { hasText: '数据出境看板' })).toBeVisible()
    // 看板骨架（两种形态共有）：统计卡、本土基准、趋势、聚合 Tab、明细表
    await expect(page.locator('.ant-statistic-title', { hasText: '跨境事件' })).toBeVisible()
    await expect(page.locator('.ant-statistic-title', { hasText: '高风险事件' })).toBeVisible()
    await expect(page.getByText('本土地区判定基准：')).toBeVisible()
    await expect(page.locator('.ant-card-head-title', { hasText: '趋势（按天）' })).toBeVisible()
    await expect(page.locator('.ant-tabs-tab', { hasText: '按国家/地区' })).toBeVisible()
    await expect(page.locator('.ant-table-thead').getByText('客户端 IP')).toBeVisible()

    const degraded = page.locator('.ant-alert', { hasText: 'GeoIP 数据源未加载，跨境识别已降级' })
    if (geoEnabled === false) {
      // 降级形态：警示卡 + 历史数据说明（stage5 编排默认未部署 GeoIP，预期走此分支）
      await expect(degraded).toBeVisible()
      await expect(degraded.getByText('历史观察数据')).toBeVisible()
    } else {
      // GeoIP 就绪形态：无警示卡，看板直出
      expect(geoEnabled, 'cross-border geo_enabled 应为布尔').toBe(true)
      await expect(degraded).toHaveCount(0)
    }
  })

  /* ==================== 4. 服务资产 ==================== */

  test('服务资产：聚合表渲染（有数据校验行形态，无数据空态友好）', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)

    const respPromise = page.waitForResponse(
      (r) => r.url().includes('/api-security/service-assets') && r.status() === 200,
      { timeout: 15000 },
    )
    await page.goto('/api-service-assets')
    const resp = await respPromise
    const total = Number((await resp.json())?.data?.total ?? 0)

    await expect(page.locator('.ant-card-head-title', { hasText: '服务资产' })).toBeVisible()
    // 聚合表表头恒渲染（与是否有数据无关）
    for (const col of ['服务地址', '应用数', '接口数', '近 7 天请求量', '涉敏接口', '未闭环风险']) {
      await expect(page.locator('.ant-table-thead').getByText(col)).toBeVisible()
    }
    if (total > 0) {
      // 有数据：首行服务地址为 host:port 形态（首列为展开图标，行内整体匹配）
      const firstRow = page.locator('tbody tr.ant-table-row').first()
      await expect(firstRow).toBeVisible()
      await expect(firstRow).toContainText(/:\d+/)
    } else {
      // 无数据：空态友好（应用源站为空时合法形态）
      await expect(page.locator('.ant-table-tbody .ant-empty-description')).toHaveText('暂无数据')
    }
  })

  /* ==================== 5. 节点校验 ==================== */

  test('节点校验：节点列表 + 一致性横幅渲染（三种形态兼容）', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)

    // 节点列表与一致性两个接口：consistency 路径包含 nodes 前缀，谓词需排除
    const listPromise = page.waitForResponse(
      (r) =>
        r.url().includes('/api-security/nodes') &&
        !r.url().includes('consistency') &&
        r.status() === 200,
      { timeout: 15000 },
    )
    const consPromise = page.waitForResponse(
      (r) => r.url().includes('/api-security/nodes/consistency') && r.status() === 200,
      { timeout: 15000 },
    )
    await page.goto('/api-nodes')
    await listPromise
    await consPromise

    await expect(page.locator('.ant-card-head-title', { hasText: '网关节点版本校验' })).toBeVisible()
    // 一致性横幅：一致 / 不一致 / 无版本数据 三形态其一（取决于节点上报，均合法）
    const banner = page.locator('.ant-alert').first()
    await expect(banner).toBeVisible()
    await expect(banner).toContainText(/活跃节点策略版本一致|节点策略版本不一致|无版本数据可比/)

    // 节点列表表头恒渲染；有节点时状态词表（活跃/停滞/静默）可见其一，无节点空态友好
    for (const col of ['节点名称', '状态', '最近事件时间', '策略版本', '模型版本', '事件数', '版本一致']) {
      await expect(page.locator('.ant-table-thead').getByText(col, { exact: true })).toBeVisible()
    }
    if ((await page.locator('tbody tr.ant-table-row').count()) > 0) {
      await expect(page.locator('tbody tr.ant-table-row').first()).toContainText(/活跃|停滞|静默/)
    } else {
      await expect(page.locator('.ant-table-tbody .ant-empty-description')).toHaveText('暂无数据')
    }
  })

  /* ==================== 6. 文件合规 ==================== */

  test('文件合规：规则列表→新建弹窗match_type联动提示→启停开关→删除清理', async ({ page }) => {
    test.setTimeout(120_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await ensureWdspEnv(page)
    const tag = randTag()
    // 匹配值带随机标签：MIME 形态合法且全局唯一，重跑不撞 409 冲突
    const matchValue = `application/x-${tag}`
    const switchLabel = `启停规则 MIME:${matchValue}`

    await page.goto('/api-file-compliance')
    await expect(page.locator('.ant-card-head-title', { hasText: '文件合规规则' })).toBeVisible()
    // 过滤器区与规则列表表头
    await expect(page.locator('.ant-select', { hasText: '匹配类型' }).first()).toBeVisible()
    await expect(page.locator('.ant-table-thead').getByText('匹配值')).toBeVisible()

    // 新建弹窗：默认 EXT 提示 → 切换 MIME 后占位符与说明联动变化
    await page.getByRole('button', { name: '新建规则' }).click()
    const dialog = confirmDialog(page)
    await expect(dialog.getByText('新建文件合规规则')).toBeVisible()
    await expect(dialog.getByText(/扩展名，如 \.exe/)).toBeVisible()
    await expect(dialog.locator('#match_value')).toHaveAttribute('placeholder', '.exe')
    await pickSelectOption(page, dialog, 'match_type', 'MIME 类型（MIME）')
    await expect(dialog.getByText(/MIME 类型，如 application\/pdf/)).toBeVisible()
    await expect(dialog.locator('#match_value')).toHaveAttribute('placeholder', 'application/pdf')

    // 合法 MIME 匹配值 + 理由 → 创建成功（默认 上传/观察/启用）
    await dialog.locator('#match_value').fill(matchValue)
    await dialog.locator('#reason').fill(`E2E 联动提示校验 ${tag}`)
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('已创建')).toBeVisible({ timeout: 10000 })
    const row = page.locator('tbody tr', { hasText: tag })
    await expect(row).toBeVisible({ timeout: 10000 })
    await expect(row.getByText('上传')).toBeVisible()
    await expect(row.getByText('MIME 类型')).toBeVisible()
    await expect(row.getByText('观察')).toBeVisible()
    await expect(row.getByLabel(switchLabel)).toHaveAttribute('aria-checked', 'true')

    // 启停开关：停用 → 二次确认 → 开关复位；再启用恢复（两方向均验证）
    await row.getByLabel(switchLabel).click()
    const stopModal = confirmDialog(page)
    await expect(stopModal.locator('.ant-modal-confirm-title')).toHaveText('停用规则')
    await stopModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('已保存')).toBeVisible({ timeout: 10000 })
    await expect(row.getByLabel(switchLabel)).toHaveAttribute('aria-checked', 'false', {
      timeout: 10000,
    })
    await row.getByLabel(switchLabel).click()
    const startModal = confirmDialog(page)
    await expect(startModal.locator('.ant-modal-confirm-title')).toHaveText('启用规则')
    await startModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(row.getByLabel(switchLabel)).toHaveAttribute('aria-checked', 'true', {
      timeout: 10000,
    })

    // 删除清理（危险按钮二次确认；不污染环境）
    await row.getByRole('button', { name: '删除' }).click()
    const delModal = confirmDialog(page)
    await expect(delModal.locator('.ant-modal-confirm-title')).toHaveText('删除规则')
    await delModal.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('已删除')).toBeVisible({ timeout: 10000 })
    await expect(page.locator('tbody tr', { hasText: tag })).toHaveCount(0, { timeout: 10000 })
  })
})
