import { expect, test, type Page } from '@playwright/test'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * BOT-004 真实浏览器组：HTTPS 挑战 → 页内 JS 求解 → verify 204 →
 * 自动刷新 → 源站成功（REACHED_ORIGIN），全链路可追溯。
 * 如实记录：挑战出现前的导航次数、求解耗时、最终业务结果。
 *
 * 反竞态设计（挑战页内嵌 JS 在 difficulty=12 下毫秒级求解并 location.reload()）：
 *   - 挑战判定以 403 响应状态 + 响应体挑战标记为准——DOM 可见性检查与页面
 *     自动刷新竞态（实测：挑战页在断言执行前已完成求解并刷新离开）；
 *   - webdriver/UA 在首次导航前采集，verify 状态用导航前注册的 response 监听捕获，
 *     clearance 用 Cookie 轮询确认——全部不与页面跳转竞态。
 */

const REPORT_DIR = process.env.BOT_BENCH_REPORT_DIR || '.'

interface FlowMetrics {
  group: string
  nav_attempts_before_challenge: number
  challenge_seen: boolean
  solve_ms: number | null
  final_status: number | null
  final_reached_origin: boolean
  clearance_cookie: boolean
  webdriver: boolean
  user_agent: string
}

/** 导航直至挑战页出现（信号判定依赖行为窗口计数；Peek 快照不含本次请求记账，
 * 前两次导航建立观测基线）。403 + 响应体挑战标记为权威判定，不查 DOM（竞态）。 */
async function navigateUntilChallenged(
  page: Page,
  maxAttempts = 6,
): Promise<{ challenged: boolean; attempts: number; body: string }> {
  for (let i = 1; i <= maxAttempts; i++) {
    const resp = await page.goto('/', { waitUntil: 'domcontentloaded' })
    if (resp?.status() === 403) {
      const body = await resp.text()
      // WAF 阻断同为 403 但无挑战参数标记，须区分（挑战页标记见 render.go）
      if (body.includes('wdsp-bot-params') && body.includes('安全验证')) {
        return { challenged: true, attempts: i, body }
      }
    }
    // 200 = 观测基线建立中（或已持通行），继续下一次导航
  }
  return { challenged: false, attempts: maxAttempts, body: '' }
}

async function runChallengeFlow(group: string, page: Page): Promise<FlowMetrics> {
  // 自动化属性在首次导航前采集（挑战页自动求解刷新后 evaluate 会竞态丢上下文）
  const webdriver = await page.evaluate(() => navigator.webdriver)
  const userAgent = await page.evaluate(() => navigator.userAgent)

  // verify 提交全程监听：页内 JS 自动求解可能早于任何断言注册，事件监听不丢
  const verifyStatuses: number[] = []
  page.on('response', (r) => {
    if (r.url().includes('/_wdsp/bot/v1/verify') && r.request().method() === 'POST') {
      verifyStatuses.push(r.status())
    }
  })

  const nav = await navigateUntilChallenged(page)
  const metrics: FlowMetrics = {
    group,
    nav_attempts_before_challenge: nav.attempts,
    challenge_seen: nav.challenged,
    solve_ms: null,
    final_status: null,
    final_reached_origin: false,
    clearance_cookie: false,
    webdriver,
    user_agent: userAgent,
  }
  expect(nav.challenged, '导航后应出现 Bot 挑战页（链路未通则属 B3 缺口，如实 FAIL）').toBe(true)

  // 挑战页可读状态：等待中文案以 role=status 播报（BOT-006 侧面，响应体静态断言不竞态）
  expect(nav.body).toContain('role="status"')
  expect(nav.body).toContain('正在完成安全验证')

  // 页内 JS 自动求解 → verify 204 → clearance Cookie（事件捕获 + Cookie 轮询）
  const solveStart = Date.now()
  await expect
    .poll(() => verifyStatuses.length, { timeout: 60000 })
    .toBeGreaterThan(0)
  expect(verifyStatuses[0], 'verify 应返回 204（成功不设正文、设置 clearance）').toBe(204)
  await expect
    .poll(
      async () =>
        (await page.context().cookies()).some((c) => c.name.includes('wdsp-bot-clearance')),
      { timeout: 60000 },
    )
    .toBe(true)
  metrics.solve_ms = Date.now() - solveStart
  metrics.clearance_cookie = true

  // verify 后挑战页 JS location.reload()；显式再导航断言通行：Bot 步骤通过后
  // 继续完整防护链，直达源站
  const again = await page.goto('/', { waitUntil: 'domcontentloaded' })
  metrics.final_status = again?.status() ?? null
  expect(metrics.final_status).toBe(200)
  await expect(page.getByText('REACHED_ORIGIN')).toBeVisible({ timeout: 30000 })
  metrics.final_reached_origin = true
  return metrics
}

test.describe('BOT-004 真实浏览器挑战链路 @browser', () => {
  test('挑战 → verify 204 → 一次刷新 → 源站成功', async ({ page }) => {
    const metrics = await runChallengeFlow('browser', page)
    writeFileSync(
      join(REPORT_DIR, 'group-browser.result.json'),
      JSON.stringify(metrics, null, 2),
    )
    console.log('[browser] metrics=', JSON.stringify(metrics))
  })
})

test.describe('BOT-021 能执行 JS 的自动化浏览器组 @automation-js', () => {
  test('headless 自动化浏览器如实记录：可求解 PoW 并通过挑战', async ({ page }) => {
    const metrics = await runChallengeFlow('automation-js', page)
    // 如实标注自动化属性：headless Chromium navigator.webdriver=true；
    // 挑战只增加自动化成本（求解耗时），不证明真人、不识别所有自动化浏览器
    writeFileSync(
      join(REPORT_DIR, 'group-automation-js.result.json'),
      JSON.stringify(metrics, null, 2),
    )
    console.log('[automation-js] metrics=', JSON.stringify(metrics))
    console.log(
      `[automation-js] 如实报告：webdriver=${metrics.webdriver}，求解耗时=${metrics.solve_ms}ms，通行=${metrics.final_reached_origin}`,
    )
  })
})
