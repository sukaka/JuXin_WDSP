import { expect, test, type Page } from '@playwright/test'
import Redis from 'ioredis'

/**
 * P1-04 R4a 安全回归管理界面链路（真实 stage5 栈，证据由 run.sh 经 regsign 签名 +
 * imports API 真实登记，无任何 mock）：
 *   链路1：列表（门禁策略卡 + 可用性预判）→ run1 详情（可用于发布）→ 用例差异
 *          → run2 详情（不可用 + 逐项理由/恢复动作）→ 用例差异（状态过滤 +
 *          丢失检测/新增误报分类 + 恶意样本纯文本不执行）
 *   链路2：API 置 ENFORCE → 配置发布页门禁状态 → 真实发布被 REGRESSION_GATE_REJECTED
 *          → 缺失项展示 + 按候选指纹深链回列表（0 条，如实空态）
 */

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:5173'
const API = `${BASE_URL}/api/v1`
const SEC_USER = process.env.REG_E2E_SEC_USER || ''
const SEC_PWD = process.env.REG_E2E_SEC_PWD || ''
const RUN1_ID = process.env.REG_E2E_RUN1_ID || ''
const RUN2_ID = process.env.REG_E2E_RUN2_ID || ''

function valkey() {
  return new Redis({
    host: process.env.VALKEY_HOST || '127.0.0.1',
    port: Number(process.env.VALKEY_PORT || 6379),
    password: process.env.VALKEY_PASSWORD || 'CHANGE_ME_STRONG_PASSWORD',
    db: Number(process.env.VALKEY_DB || 0),
  })
}

/** 真实登录页登录：拦截页面验证码请求拿 captcha_id，从 Valkey 读答案填入。
 *  失败时如实抛出诊断（登录响应状态/页面 toast/当前 URL/console 错误），不静默重试。 */
async function loginViaUI(page: Page) {
  const consoleErrors: string[] = []
  page.on('console', (m) => {
    if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 300))
  })
  page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${String(e).slice(0, 300)}`))
  // vite dev 下 React StrictMode 双挂会连发两次 captcha 请求，页面 state 以后到者为准；
  // 若取首个响应的 captcha_id 填码，提交的是第二个 id → 400 CAPTCHA_INVALID。
  // 故持续跟踪最新 captcha_id，等其在静默窗内收敛（=页面实际将提交的 id）再取码。
  let lastCaptchaId: string | null = null
  page.on('response', (resp) => {
    if (resp.url().includes('/api/v1/auth/captcha') && resp.status() === 200) {
      resp
        .json()
        .then((j: { data?: { captcha_id?: string } }) => {
          if (j?.data?.captcha_id) lastCaptchaId = j.data.captcha_id
        })
        .catch(() => {})
    }
  })
  await page.goto('/login')
  await page.getByPlaceholder('图形验证码').waitFor({ timeout: 15000 })
  let captchaId = ''
  const captchaDeadline = Date.now() + 10000
  while (Date.now() < captchaDeadline) {
    const cur = lastCaptchaId
    if (cur) {
      await page.waitForTimeout(400)
      if (lastCaptchaId === cur) {
        captchaId = cur
        break
      }
    } else {
      await page.waitForTimeout(100)
    }
  }
  if (!captchaId) throw new Error('page captcha_id 未收敛（captcha 响应缺失或持续刷新）')
  const r = valkey()
  let code: string | null
  try {
    code = await r.get(`jiuzhang:captcha:${captchaId}`)
  } finally {
    r.disconnect()
  }
  if (!code) throw new Error('captcha code not found in valkey')
  await page.getByPlaceholder('用户名').fill(SEC_USER)
  await page.getByPlaceholder('密码').fill(SEC_PWD)
  await page.getByPlaceholder('图形验证码').fill(code)
  const loginRespPromise = page.waitForResponse(
    (resp) => resp.url().includes('/api/v1/auth/login'),
    { timeout: 15000 },
  )
  await page.getByRole('button', { name: /登 ?录/ }).click()
  const loginResp = await loginRespPromise
  const loginStatus = loginResp.status()
  const loginBody = (await loginResp.text()).slice(0, 300)
  try {
    await page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 15000 })
  } catch (e) {
    const toast = await page
      .locator('.ant-message')
      .allTextContents()
      .catch(() => [] as string[])
    throw new Error(
      `登录后未离开 /login（url=${page.url()} loginStatus=${loginStatus} ` +
        `loginBody=${loginBody} toast=${JSON.stringify(toast)} console=${JSON.stringify(consoleErrors)}）`,
      { cause: e },
    )
  }
  if (loginStatus !== 200) {
    throw new Error(`登录接口非 200（${loginStatus}）：${loginBody}`)
  }
}

/** 当前会话 CSRF（/auth/me 轮换返回） */
async function csrf(page: Page): Promise<string> {
  const resp = await page.request.get(`${API}/auth/me`)
  const json = (await resp.json()) as { data?: { csrf_token?: string } }
  if (!json?.data?.csrf_token) throw new Error('csrf_token not returned')
  return json.data.csrf_token
}

test.beforeEach(async ({ page }) => {
  test.skip(!SEC_USER || !SEC_PWD || !RUN1_ID || !RUN2_ID, 'run.sh 未提供账号/运行 ID 环境')
  await loginViaUI(page)
})

test('回归控制台链路：列表 → 详情 → 用例差异（真实导入证据）', async ({ page }) => {
  await test.step('列表：门禁策略卡 OFF 明示 + 两个真实运行 + 可用性预判', async () => {
    await page.goto('/security-regressions')
    await expect(page.getByText('回归发布门禁策略')).toBeVisible()
    await expect(
      page.getByText(/回归门禁未强制（OFF）：发布不检查回归证据/),
    ).toBeVisible()
    // 两个真实导入的运行均可见
    const row1 = page.getByRole('row', { name: new RegExp(RUN1_ID) })
    const row2 = page.getByRole('row', { name: new RegExp(RUN2_ID) })
    await expect(row1).toBeVisible()
    await expect(row2).toBeVisible()
    // 可用性预判：run1 可用，run2 不可用且带原因数（文字而非绿色百分比）
    await expect(row1.getByText('可用')).toBeVisible()
    await expect(row2.getByText(/不可用（\d+ 项原因）/)).toBeVisible()
    // 级别/核验/声明列真实渲染
    await expect(row1.getByText('全量')).toBeVisible()
    await expect(row1.getByText('核验通过')).toBeVisible()
    await expect(row2.getByText('声明失败')).toBeVisible()
  })

  await test.step('run1 详情：门禁评估可用（绿色结论 + 终判提示）', async () => {
    await page.goto('/security-regressions')
    await page.getByRole('link', { name: RUN1_ID }).click()
    await expect(page).toHaveURL(/\/security-regressions\/[0-9a-f-]+$/)
    await expect(page.getByText(`回归运行 ${RUN1_ID}`)).toBeVisible()
    await expect(page.getByText('发布门禁可用性评估（按当前门禁策略实时评估）')).toBeVisible()
    await expect(page.getByText('本证据当前可用于支撑发布')).toBeVisible()
    await expect(page.getByText(/发布器门禁将对实际构建的候选指纹做终判/)).toBeVisible()
    // 摘要计数如实：计划/实际/缺失 4 / 4 / 0
    await expect(page.getByText('4 / 4 / 0')).toBeVisible()
  })

  await test.step('run1 用例差异页：真实用例索引 + 无差异如实标注', async () => {
    await page.getByRole('link', { name: '查看用例差异' }).click()
    await expect(page).toHaveURL(/\/cases$/)
    await expect(page.getByText(`用例差异（${RUN1_ID}）`)).toBeVisible()
    await expect(page.getByText('sqli-001')).toBeVisible()
    await expect(page.getByText('benign-017')).toBeVisible()
    // 展开全过用例：无差异摘要如实提示（不伪造内容）
    const row = page.getByRole('row', { name: /sqli-001/ })
    await row.locator('button.ant-table-row-expand-icon').click()
    await expect(page.getByText('无差异摘要（服务端未登记或已脱敏清理）')).toBeVisible()
  })

  await test.step('run2 详情：不可用 + 逐项理由与恢复动作', async () => {
    await page.goto('/security-regressions')
    await page.getByRole('link', { name: RUN2_ID }).click()
    await expect(page.getByText('本证据当前不可用于支撑发布')).toBeVisible()
    await expect(page.getByText('逐项理由与恢复动作')).toBeVisible()
    await expect(page.getByText('回归声明状态非 PASS')).toBeVisible()
    await expect(page.getByText(/强制用例未全部通过（1）/)).toBeVisible()
  })

  await test.step('run2 用例差异：状态服务端过滤 + 差异分类 + 恶意样本纯文本', async () => {
    await page.getByRole('link', { name: '查看用例差异' }).click()
    await expect(page.getByText(`用例差异（${RUN2_ID}）`)).toBeVisible()
    // 状态筛选走服务端：URL 直挂 ?status=FAIL
    await page.goto(`${page.url()}?status=FAIL`)
    await expect(page).toHaveURL(/status=FAIL/)
    await expect(page.getByText('sqli-002')).toBeVisible()
    await expect(page.getByText('benign-042')).toBeVisible()
    await expect(page.getByText('xss-009')).toHaveCount(0)
    // 差异分类：ATTACK+FAIL=丢失检测；BENIGN+FAIL=新增误报
    await expect(page.getByText('丢失检测')).toBeVisible()
    await expect(page.getByText('新增误报')).toBeVisible()
    // 展开 sqli-002：恶意 HTML 样本以纯文本展示，不产生可执行标记
    const row = page.getByRole('row', { name: /sqli-002/ })
    await row.locator('button.ant-table-row-expand-icon').click()
    await expect(
      page.getByText('<img src=x onerror=alert(1)><script>alert(2)</script>', { exact: false }),
    ).toBeVisible()
    await expect(page.locator('img[src="x"]')).toHaveCount(0)
    await expect(page.locator('script', { hasText: 'alert(2)' })).toHaveCount(0)
  })

  await test.step('配置发布页：OFF 门禁状态如实展示', async () => {
    await page.goto('/config-publish')
    await expect(
      page.getByText(/回归门禁未强制（OFF）：本次发布不检查回归证据/),
    ).toBeVisible()
    await expect(page.getByRole('link', { name: '查看安全回归' })).toBeVisible()
  })
})

test('ENFORCE 发布拒绝链路：REGRESSION_GATE_REJECTED 缺失项 + 深链', async ({ page }) => {
  await test.step('API 置 ENFORCE（expected_version 乐观锁 + 审计理由）', async () => {
    const token = await csrf(page)
    const policyResp = await page.request.get(`${API}/security/regression-policy`)
    const policyJson = (await policyResp.json()) as {
      data?: { policy?: { version?: number } }
    }
    const version = policyJson?.data?.policy?.version
    expect(typeof version).toBe('number')
    const put = await page.request.put(`${API}/security/regression-policy`, {
      headers: { 'X-CSRF-Token': token },
      data: {
        mode: 'ENFORCE',
        required_level: 'FULL',
        required_corpus_id: '',
        evidence_max_age_seconds: 604800,
        expected_version: version,
        reason: 'R4a E2E：验证发布门禁拒绝链路（仅本轮临时栈）',
      },
    })
    expect(put.status()).toBe(200)
  })

  await test.step('发布页显示 ENFORCE 状态', async () => {
    await page.goto('/config-publish')
    await expect(page.getByText(/回归门禁强制中（ENFORCE）/)).toBeVisible()
  })

  await test.step('真实发布被门禁拒绝：缺失项 + 指纹深链 + 空态列表', async () => {
    await page.goto('/config-publish')
    await page.getByRole('button', { name: '发布到网关' }).click()
    await page.getByRole('button', { name: '确认发布' }).click()
    // 发布任务失败：门禁拒绝码与缺失项原文展示（失败需构建候选版本，宽限 150s）。
    // 断言收敛到失败 Alert 内——任务记录表的结果摘要列同样含 failure_message 原文。
    const failAlert = page.locator('.ant-alert', {
      hasText: '发布失败（REGRESSION_GATE_REJECTED）',
    })
    await expect(failAlert).toBeVisible({ timeout: 150000 })
    await expect(
      failAlert.getByText(/确切缺失项：安全回归证据不满足发布门禁/),
    ).toBeVisible()
    await expect(failAlert.getByText(/缺少绑定当前候选指纹（cfgfpv1:/)).toBeVisible()
    // 深链：按候选指纹过滤回安全回归列表
    const link = failAlert.getByRole('link', { name: /前往安全回归（按候选指纹过滤）/ })
    await expect(link).toBeVisible()
    await link.click()
    await page.waitForURL(/\/security-regressions\?fingerprint=cfgfpv1/)
    // 该指纹属被拒候选版本，无证据绑定：列表如实空态而非伪造命中
    await expect(page.locator('.ant-empty-description', { hasText: '暂无数据' })).toBeVisible()
  })
})
