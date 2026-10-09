import { test, expect, type Page } from '@playwright/test'
import { execSync } from 'node:child_process'
import { loginViaAPI, API_URL } from './helpers'

/**
 * NG-FLOW-04 强流程管理面 E2E（五场景）：定义全流页面操作 / 正常流实例确认 /
 * PROTECT 违规 403 轨迹 / INDETERMINATE 对账恢复 / jiuzhang_admin 越权。
 *
 * 环境依赖：stage5 编排（API 18081、网关 18080、Valkey 验证码）；sfapp fixture
 * （sf-s5.local 已发布应用 + POST /submit、POST /api/json 已 CONFIRMED 端点——
 * 集成批预置）。INDETERMINATE 经「判定式不命中」路径制造（pay 步 $.status 等值
 * 判定对 echo 响应恒不命中——无需慢端点/Valkey 停启）。afterAll 现场还原
 * （E2E-* 定义全 RETIRED、实例/事件清理、发布还原、限流键清理）。
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'
const SYS_USER = process.env.E2E_SYSADMIN_USER || 'jiuzhang_admin'
const SYS_PWD = process.env.E2E_SYSADMIN_PWD || 'SysAdmin@S5!2026'

const GATEWAY_URL = process.env.E2E_GATEWAY_URL || 'http://127.0.0.1:18080'
const SF_HOST = 'sf-s5.local'
const SF_APP_CODE = 'sfapp'

const DEF_PAGE = 'E2E-页面流程'
const DEF_API = 'E2E-接口流程'
const DEF_INDET = 'E2E-对账流程'

/** 本轮唯一 ref 后缀：Valkey 实例热状态（sflow:v1: 24h TTL）跨轮残留——
 * 实例键 HMAC 输入不含 definition_id（应用+租户+主体+定义版本+引用），
 * 历史同版本号定义同 ref 会撞键（instance_terminal 联调实证）——每轮 ref 唯一化 */
const RUN = Date.now().toString(36)

async function csrfToken(page: Page): Promise<string> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  return ((await me.json())?.data?.csrf_token as string) || ''
}

async function apiJSON(
  page: Page,
  method: string,
  path: string,
  body?: unknown,
) {
  const csrf = await csrfToken(page)
  const resp = await page.request.fetch(`${API_URL}${path}`, {
    method,
    data: body,
    headers: { 'X-CSRF-Token': csrf },
  })
  const json = await resp.json().catch(() => ({}))
  return { status: resp.status(), json }
}

/** 发布并轮询终态（LOCK_BUSY 退避沿用 s5_publish 惯例） */
async function publishAndWait(page: Page): Promise<string> {
  for (let attempt = 0; attempt < 6; attempt++) {
    const created = await apiJSON(page, 'POST', '/gateway-config/publish', {
      idempotency_key: `e2e-flow04-${Date.now()}`,
    })
    const taskId = created.json?.data?.id as string
    if (!taskId)
      throw new Error(`publish create failed: ${JSON.stringify(created.json)}`)
    for (let i = 0; i < 40; i++) {
      const t = await apiJSON(page, 'GET', `/publish-tasks/${taskId}`)
      const d = t.json?.data ?? {}
      if (d.status === 'SUCCESS') return 'SUCCESS'
      if (d.status === 'FAILED') {
        if (d.failure_code === 'LOCK_BUSY') break
        throw new Error(
          `publish failed: ${d.failure_code} ${d.failure_message}`,
        )
      }
      await new Promise((r) => setTimeout(r, 1000))
    }
    await new Promise((r) => setTimeout(r, 3000))
  }
  throw new Error('publish timeout')
}

/** 网关直发请求（带 Host 头；sfapp 数据面）。node undici fetch 静默丢弃 Host 头
 * （forbidden header）——必须经 curl 承载（手工复刻实证）。 */
async function gwRequest(
  method: string,
  path: string,
  body: string,
): Promise<{ status: number; originMark: string | null }> {
  const out = execSync(
    `curl -s -o /dev/null -D - -w '\\n%{http_code}' -H 'Host: ${SF_HOST}' -H 'Content-Type: application/json' -X ${method} "${GATEWAY_URL}${path}" -d '${body.replace(/'/g, `'\\''`)}'`,
    { encoding: 'utf-8' },
  )
  const lines = out.trim().split('\n')
  const status = Number(lines[lines.length - 1])
  const mark = lines.find((l) => /^X-Wdsp-Origin-Mark:/i.test(l))
  return { status, originMark: mark ? mark.split(':')[1].trim() : null }
}

/** 强流程定义载荷（两步 register→pay；判定/租约/模式按场景参数化） */
function defPayload(
  appId: string,
  name: string,
  mode: string,
  payJsonpath?: string,
) {
  const payRule: Record<string, unknown> = { status_codes: [200] }
  if (payJsonpath)
    payRule.body_jsonpath_equals = { path: '$.status', value: 'ok' }
  return {
    application_id: appId,
    name,
    binding_path_prefix: '/',
    instance_key_param: 'query:order_id',
    mode,
    steps: [
      {
        step_key: 'register',
        endpoint_key: 'POST /submit',
        sequence: 1,
        success_rule: { status_codes: [200] },
        timeout_seconds: 30,
        retry_semantics: 'IDEMPOTENT',
        lease_seconds: 60,
        allows_202: false,
      },
      {
        step_key: 'pay',
        endpoint_key: 'POST /api/json',
        sequence: 2,
        success_rule: payRule,
        timeout_seconds: 60,
        retry_semantics: 'REQUIRES_REVIEW',
        lease_seconds: 15,
        allows_202: false,
      },
    ],
  }
}

async function createAndActivate(
  page: Page,
  payload: unknown,
): Promise<{ id: string; version: number }> {
  const created = await apiJSON(
    page,
    'POST',
    '/api-security/strong-flows/definitions',
    payload,
  )
  if (created.status !== 200)
    throw new Error(`create def failed: ${JSON.stringify(created.json)}`)
  const id = created.json?.data?.id as string
  const act = await apiJSON(
    page,
    'POST',
    `/api-security/strong-flows/definitions/${id}/activate`,
    {},
  )
  if (act.status !== 200)
    throw new Error(`activate def failed: ${JSON.stringify(act.json)}`)
  const activatedVersion = Number(act.json?.data?.version ?? 0)
  // activate 的 triggerPublish 遇 LOCK_BUSY 不重试（异步失败仅记日志——定义未下发即
  // 后续请求零绑定命中）——activate 后显式 publishAndWait 确保含本定义的快照下发
  await publishAndWait(page)
  return { id, version: activatedVersion }
}

async function listInstances(
  page: Page,
  appId: string,
  status: string,
): Promise<Array<Record<string, unknown>>> {
  const r = await apiJSON(
    page,
    'GET',
    `/api-security/strong-flows/instances?application_id=${appId}&status=${status}&page_size=20`,
  )
  return (r.json?.data?.items ?? []) as Array<Record<string, unknown>>
}

/** PG 现场清理（实例/事件按 E2E 定义维度；sfapp 限流计数键） */
function cleanupStrongFlowData() {
  const sql = `DELETE FROM api_strong_flow_step_events WHERE instance_id IN (SELECT id FROM api_strong_flow_instances WHERE definition_id IN (SELECT id FROM api_strong_flow_definitions WHERE name LIKE 'E2E-%')); DELETE FROM api_strong_flow_instances WHERE definition_id IN (SELECT id FROM api_strong_flow_definitions WHERE name LIKE 'E2E-%');`
  execSync(
    `docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" jiuzhang-stage5-postgres psql -U jiuzhang -d jiuzhang_waf -c "${sql}"`,
    {
      encoding: 'utf-8',
      env: {
        ...process.env,
        POSTGRES_PASSWORD: process.env.POSTGRES_PASSWORD || '',
      },
    },
  )
}

/** 发布面单定义纪律：多 ACTIVE 定义绑定同端点时 finalize 只消费首个成功预留
 * （一请求一预留，先到先得）——其余绑定实例恒 PENDING 不可 CONFIRMED（联调实证）。
 * 每场景开始前 retire 其他 E2E-* ACTIVE 定义，确保当前场景定义是唯一同端点绑定。 */
async function retireAllE2EDefs(page: Page, appId: string, keepName?: string) {
  const defs = await apiJSON(
    page,
    'GET',
    `/api-security/strong-flows/definitions?application_id=${appId}&status=ACTIVE&page_size=50`,
  )
  for (const d of (defs.json?.data?.items ?? []) as Array<{
    id: string
    name: string
  }>) {
    if (d.name.startsWith('E2E-') && d.name !== keepName) {
      await apiJSON(
        page,
        'POST',
        `/api-security/strong-flows/definitions/${d.id}/retire`,
        {},
      )
    }
  }
}

/** 采集延迟纪律的完整清理：在途事件（网关日志→server 采集数秒延迟）会经
 * resolveInstance upsert 重建实例行——单次清理+发布可能漏删（延迟落库在清理后
 * 到达），重建的 RETIRED 定义非终态实例滞留育龄窗（PROTECT 定义窗内仍实断）。
 * 两遍清理夹采集窗 + 两遍发布（先清存量、再清在途、最终掉出发布面）。 */
async function cleanupStrongFlowSettled(page: Page) {
  cleanupStrongFlowData()
  await publishAndWait(page)
  await new Promise((r) => setTimeout(r, 8000))
  cleanupStrongFlowData()
  await publishAndWait(page)
}

test.describe('NG-FLOW-04 强流程管理面 E2E', () => {
  test.describe.configure({ mode: 'serial' })
  let sfAppId = ''

  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage()
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const apps = await apiJSON(
      page,
      'GET',
      `/applications?keyword=${SF_APP_CODE}`,
    )
    sfAppId = (apps.json?.data?.items ?? []).find(
      (a: { code: string }) => a.code === SF_APP_CODE,
    )?.id as string
    if (!sfAppId) throw new Error('sfapp fixture missing')
    await page.close()
  })

  test.afterAll(async ({ browser }) => {
    const page = await browser.newPage()
    try {
      await loginViaAPI(page, SEC_USER, SEC_PWD)
      for (const name of [DEF_PAGE, DEF_API, DEF_INDET]) {
        const defs = await apiJSON(
          page,
          'GET',
          `/api-security/strong-flows/definitions?application_id=${sfAppId}&status=ACTIVE&page_size=50`,
        )
        for (const d of (defs.json?.data?.items ?? []) as Array<{
          id: string
          name: string
        }>) {
          if (d.name === name)
            await apiJSON(
              page,
              'POST',
              `/api-security/strong-flows/definitions/${d.id}/retire`,
              {},
            )
        }
      }
      await cleanupStrongFlowSettled(page)
    } finally {
      await page.close()
    }
  })

  test('① 定义全流页面操作：新建草稿 → activate → ACTIVE → 详情步骤序列图', async ({
    page,
  }) => {
    test.setTimeout(180000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/api-flow-baselines')
    await page.getByRole('tab', { name: '强流程定义' }).click()

    // 新建草稿（表单+步骤编辑；antd Form.Item 自定义 Select 无 htmlFor——placeholder/下拉项定位）
    await page.getByRole('button', { name: '新建强流程定义' }).click()
    const drawer = page.locator('.ant-drawer').last()
    await expect(drawer).toBeVisible()
    await expect(drawer.getByPlaceholder('如：下单支付流程')).toBeVisible()
    await page.waitForTimeout(800) // 抽屉动画稳定（placeholder 节点在动画期 not stable）
    await drawer.locator('.ant-select').first().click()
    await page
      .locator('.ant-select-item-option', { hasText: SF_APP_CODE })
      .first()
      .click()
    await drawer.getByPlaceholder('如：下单支付流程').fill(DEF_PAGE)
    await drawer.getByPlaceholder('如：/api/v1/orders').fill('/')
    await drawer.getByPlaceholder('如：query:order_id').fill('query:order_id')
    // 步骤 1：step_key=register、端点 POST /submit、状态码集合 200
    await drawer.getByPlaceholder('如：register').fill('register')
    await drawer.locator('.ant-select', { hasText: '选择 API 端点' }).click()
    await page
      .locator('.ant-select-item-option', { hasText: 'POST /submit' })
      .first()
      .click()
    await drawer.getByPlaceholder('如：200,201').fill('200')
    await drawer.locator('.ant-drawer-extra button').last().click()
    await expect(
      page
        .locator('.ant-message')
        .getByText(/已创建草稿/)
        .first(),
    ).toBeVisible({ timeout: 15000 })

    // 列表 DRAFT → 激活（确认弹窗）→ ACTIVE（多轮累积行超一页——状态过滤「草稿」收敛）
    await page.locator('.ant-select').filter({ hasText: '全部状态' }).click()
    await page
      .locator('.ant-select-item-option', { hasText: '草稿' })
      .first()
      .click()
    const row = page
      .getByRole('row', { name: new RegExp(DEF_PAGE) })
      .filter({ hasText: '草稿' })
      .first()
    await expect(row.getByText('草稿')).toBeVisible()
    await row.getByRole('button', { name: '激活' }).click()
    await page.getByRole('button', { name: '确认激活' }).click()
    await expect(
      page
        .locator('.ant-message')
        .getByText(/已激活/)
        .first(),
    ).toBeVisible({ timeout: 15000 })
    await page
      .locator('.ant-select')
      .filter({ hasText: '草稿' })
      .first()
      .click()
    await page
      .locator('.ant-select-item-option', { hasText: '已激活' })
      .first()
      .click()
    await expect(
      page
        .getByRole('row', { name: new RegExp(DEF_PAGE) })
        .filter({ hasText: '已激活' })
        .first(),
    ).toBeVisible({ timeout: 15000 })

    // 详情抽屉：步骤序列图展示（Steps 组件序号+步骤键+端点+成功条件）
    await page
      .getByRole('row', { name: new RegExp(DEF_PAGE) })
      .filter({ hasText: '已激活' })
      .first()
      .getByRole('button', { name: '详情' })
      .click()
    const detail = page.locator('.ant-drawer').last()
    await expect(detail.getByText('步骤序列（按 sequence）')).toBeVisible()
    await expect(detail.getByText('1. register')).toBeVisible()
    await expect(detail.locator('code').getByText('POST /submit')).toBeVisible()
    await expect(detail.getByText(/成功条件：/)).toBeVisible()
    await detail.locator('.ant-drawer-close').first().click()
  })

  test('② 正常流：API 制造完整流程 → 实例 CONFIRMED → 详情轨迹 INSTANCE_CONFIRMED', async ({
    page,
  }) => {
    test.setTimeout(240000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    // 发布面单定义：retire 场景① DEF_PAGE 与其他残留（多绑定同端点 finalize 只消费首个预留）
    await retireAllE2EDefs(page, sfAppId, DEF_API)
    await cleanupStrongFlowSettled(page)
    await createAndActivate(page, defPayload(sfAppId, DEF_API, 'OBSERVE'))
    // API 直发完整两步（register → pay）
    const r1 = await gwRequest(
      'POST',
      `/submit?order_id=order-pw-b1-${RUN}`,
      '{"name":"pw","amount":1}',
    )
    expect(r1.status).toBe(200)
    const r2 = await gwRequest(
      'POST',
      `/api/json?order_id=order-pw-b1-${RUN}`,
      '{"action":"pay","amount":1}',
    )
    expect(r2.status).toBe(200)
    // 等事件采集落库
    let insts: Array<Record<string, unknown>> = []
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 1500))
      insts = await listInstances(page, sfAppId, 'CONFIRMED')
      if (insts.length > 0) break
    }
    expect(insts.length).toBeGreaterThan(0)

    await page.goto('/api-flow-baselines')
    await page.getByRole('tab', { name: '强流程实例' }).click()
    // 状态过滤 CONFIRMED → 行可见 → 详情抽屉轨迹
    await page.locator('.ant-select').filter({ hasText: '全部状态' }).click()
    await page
      .locator('.ant-select-item-option', { hasText: '已确认完成' })
      .first()
      .click()
    await page.getByRole('button', { name: '详情' }).first().click()
    const detail = page.locator('.ant-drawer').last()
    await expect(detail.getByText(/步骤轨迹（/)).toBeVisible({ timeout: 15000 })
    await expect(detail.getByText('COMMIT').first()).toBeVisible()
    await expect(detail.getByText('INSTANCE_CONFIRMED').first()).toBeVisible()
    await detail.locator('.ant-drawer-close').first().click()
  })

  test('③ 违规 403：PROTECT 跳步请求 → 实例轨迹 REJECTED/FLOW-RESERVE-001 页面可见', async ({
    page,
  }) => {
    test.setTimeout(240000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    // 同名 v2 PROTECT（步骤 timeout 变更）activate
    const v2 = defPayload(sfAppId, DEF_API, 'PROTECT') as {
      steps: Array<Record<string, unknown>>
    }
    v2.steps[1].timeout_seconds = 90
    const { version: v2Version } = await createAndActivate(page, v2)
    // 跳步：直接 pay（无 register 预留）→ 403 FLOW_VIOLATION_DENIED + 源站零到达
    const r = await gwRequest(
      'POST',
      `/api/json?order_id=order-pw-b2-${RUN}`,
      '{"action":"pay","amount":2}',
    )
    expect(r.status).toBe(403)
    expect(r.originMark).toBeNull()
    // 等 REJECTED 实例落库（403 事件采集有延迟；按本版本 definition_version 过滤——
    // 不能用 length>0 早退（场景②残留 ACTIVE 实例会误抢））
    let v2Insts: Array<Record<string, unknown>> = []
    for (let i = 0; i < 20; i++) {
      await new Promise((r2) => setTimeout(r2, 1500))
      const insts = await listInstances(page, sfAppId, 'ACTIVE')
      v2Insts = insts.filter((x) => x.definition_version === v2Version)
      if (v2Insts.length > 0) break
    }
    expect(v2Insts.length).toBeGreaterThan(0)

    await page.goto('/api-flow-baselines')
    await page.getByRole('tab', { name: '强流程实例' }).click()
    await page.getByRole('button', { name: '详情' }).first().click()
    const detail = page.locator('.ant-drawer').last()
    await expect(detail.getByText(/步骤轨迹（/)).toBeVisible({ timeout: 15000 })
    await expect(
      detail.locator('.ant-tag', { hasText: '拒绝' }).first(),
    ).toBeVisible()
    await expect(detail.getByText(/FLOW-RESERVE-001/).first()).toBeVisible()
    await detail.locator('.ant-drawer-close').first().click()
  })

  test('④ INDETERMINATE 对账：判定不命中 → 警示条逐字 → 页面恢复 CONFIRMED+恢复记录', async ({
    page,
  }) => {
    test.setTimeout(240000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    // 同名 v3：pay 判定式 $.status=="ok"（echo 响应无 status 字段 → 恒不命中 → INDETERMINATE）
    // 场景③的 DEF_API PROTECT 版本仍 ACTIVE——同端点绑定使命中即跳步实断（v20 视角
    // 新实例 pay predecessor_unconfirmed BLOCK 403，网关事件实证）——先 retire 再 settle
    await retireAllE2EDefs(page, sfAppId, DEF_INDET)
    // 育龄窗纪律：场景③ v2 PROTECT 的非终态实例（含采集延迟在途重建）滞留发布面
    // 会实断 definition_retired——settle 清理后 v2 掉出发布面
    await cleanupStrongFlowSettled(page)
    await createAndActivate(
      page,
      defPayload(sfAppId, DEF_INDET, 'OBSERVE', '$.status'),
    )
    const r1 = await gwRequest(
      'POST',
      `/submit?order_id=order-pw-b3-${RUN}`,
      '{"name":"pw","amount":3}',
    )
    expect(r1.status).toBe(200)
    const r2 = await gwRequest(
      'POST',
      `/api/json?order_id=order-pw-b3-${RUN}`,
      '{"action":"pay","amount":3}',
    )
    expect(r2.status).toBe(200) // UNKNOWN 恒不阻断（放行到源站）
    // 全量跑时前序场景/settle 双发布会让事件采集队列积压——放宽轮询窗（单跑 16s 即过）
    let insts: Array<Record<string, unknown>> = []
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 1500))
      insts = await listInstances(page, sfAppId, 'INDETERMINATE')
      if (insts.length > 0) break
    }
    expect(insts.length).toBeGreaterThan(0)

    await page.goto('/api-flow-baselines')
    await page.getByRole('tab', { name: '强流程实例' }).click()
    await page.locator('.ant-select').filter({ hasText: '全部状态' }).click()
    await page
      .locator('.ant-select-item-option', { hasText: '未知待对账' })
      .first()
      .click()
    await page.getByRole('button', { name: '详情' }).first().click()
    const detail = page.locator('.ant-drawer').last()
    // 警示条「未知，不显示安全通过」逐字断言（§9.4 红线不美化）
    await expect(detail.getByText('未知，不显示安全通过').first()).toBeVisible({
      timeout: 15000,
    })
    await expect(
      detail.getByText('UNKNOWN_NOT_CONFIRMED').first(),
    ).toBeVisible()

    // 恢复操作：CONFIRM_SUCCEEDED + reason 必填 → CONFIRMED + 恢复记录区块
    await detail
      .getByLabel('对账理由')
      .fill('E2E 对账：判定不命中系响应体缺字段（非业务失败），人工确认已执行')
    await detail
      .locator('.ant-radio-wrapper', { hasText: 'CONFIRM_SUCCEEDED' })
      .click()
    await detail.getByRole('button', { name: '提交恢复' }).click()
    await expect(
      page
        .locator('.ant-message')
        .getByText(/实例已按对账结论推进终态/)
        .first(),
    ).toBeVisible({ timeout: 15000 })
    await expect(detail.getByText('已确认完成').first()).toBeVisible({
      timeout: 15000,
    })
    await expect(detail.getByText('实例恢复记录')).toBeVisible()
    await expect(detail.getByText('管理对账').first()).toBeVisible()
    await detail.locator('.ant-drawer-close').first().click()
  })

  test('⑤ 越权：jiuzhang_admin 端点 403 + 页面操作入口隐藏', async ({
    page,
  }) => {
    test.setTimeout(120000)
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    const defs = await page.request.get(
      `${API_URL}/api-security/strong-flows/definitions?application_id=${sfAppId}`,
    )
    expect(defs.status()).toBe(403)
    const insts = await page.request.get(
      `${API_URL}/api-security/strong-flows/instances?application_id=${sfAppId}`,
    )
    expect(insts.status()).toBe(403)
    const instId = '00000000-0000-0000-0000-000000000000'
    const me = await page.request.get(`${API_URL}/auth/me`)
    const csrf = ((await me.json())?.data?.csrf_token as string) || ''
    const resolve = await page.request.fetch(
      `${API_URL}/api-security/strong-flows/instances/${instId}/resolve`,
      {
        method: 'POST',
        data: { action: 'KEEP_UNKNOWN', reason: 'x', expected_version: 1 },
        headers: { 'X-CSRF-Token': csrf },
      },
    )
    expect(resolve.status()).toBe(403)

    // 页面：jiuzhang_admin 无 api_flow.read——路由守卫整页拒绝（无访问权限），
    // 操作入口（新建/激活/停用）无从谈起（比「入口隐藏」更强的越权语义，与端点 403 互证）
    await page.goto('/api-flow-baselines')
    await expect(page.getByText('无访问权限')).toBeVisible({ timeout: 15000 })
    await expect(
      page.getByRole('button', { name: '新建强流程定义' }),
    ).toHaveCount(0)
  })
})
