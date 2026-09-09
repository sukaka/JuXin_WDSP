import { expect, test, type Page } from '@playwright/test'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { navigateUntilChallenged, registerVerifyListener } from './helpers'

/**
 * BOT-004 真实浏览器组：HTTPS 挑战 → 页内 JS 求解 → verify 204 →
 * 自动刷新 → 源站成功（REACHED_ORIGIN），全链路可追溯。
 * 如实记录：挑战出现前的导航次数、求解耗时、最终业务结果。
 *
 * 多通道（BOT-004 增补）：同一 spec 跨 chromium / firefox / webkit /
 * mobile-safari / mobile-chrome projects 运行，结果按通道（project）分别落盘
 * group-<group>.<project>.result.json；非 Chromium 通道走默认可解析域名
 * bot-bench.localhost（见 playwright.config.ts 头部口径）。
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
  channel: string
  nav_attempts_before_challenge: number
  challenge_seen: boolean
  solve_ms: number | null
  final_status: number | null
  final_reached_origin: boolean
  clearance_cookie: boolean
  webdriver: boolean
  user_agent: string
}

async function runChallengeFlow(group: string, channel: string, page: Page): Promise<FlowMetrics> {
  // 自动化属性在首次导航前采集（挑战页自动求解刷新后 evaluate 会竞态丢上下文）
  const webdriver = await page.evaluate(() => navigator.webdriver)
  const userAgent = await page.evaluate(() => navigator.userAgent)

  // verify 提交全程监听：页内 JS 自动求解可能早于任何断言注册，事件监听不丢
  const verifyStatuses = registerVerifyListener(page)

  const nav = await navigateUntilChallenged(page)
  const metrics: FlowMetrics = {
    group,
    channel,
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
  // 继续完整防护链，直达源站。自动刷新与显式导航可能竞态（Firefox 实测一次
  // "interrupted by another navigation"）：被打断后自动刷新已落地，重试一次。
  let again = null
  try {
    again = await page.goto('/', { waitUntil: 'domcontentloaded' })
  } catch (e) {
    if (!String(e).includes('interrupted by another navigation')) throw e
    again = await page.goto('/', { waitUntil: 'domcontentloaded' })
  }
  metrics.final_status = again?.status() ?? null
  expect(metrics.final_status).toBe(200)
  await expect(page.getByText('REACHED_ORIGIN')).toBeVisible({ timeout: 30000 })
  metrics.final_reached_origin = true
  return metrics
}

test.describe('BOT-004 真实浏览器挑战链路 @browser', () => {
  test('挑战 → verify 204 → 一次刷新 → 源站成功', async ({ page }, testInfo) => {
    const metrics = await runChallengeFlow('browser', testInfo.project.name, page)
    writeFileSync(
      join(REPORT_DIR, `group-browser.${testInfo.project.name}.result.json`),
      JSON.stringify(metrics, null, 2),
    )
    console.log(`[browser:${testInfo.project.name}] metrics=`, JSON.stringify(metrics))
  })
})

test.describe('BOT-021 能执行 JS 的自动化浏览器组 @automation-js', () => {
  test('headless 自动化浏览器如实记录：可求解 PoW 并通过挑战', async ({ page }, testInfo) => {
    const metrics = await runChallengeFlow('automation-js', testInfo.project.name, page)
    // 如实标注自动化属性：headless Chromium navigator.webdriver=true；
    // 挑战只增加自动化成本（求解耗时），不证明真人、不识别所有自动化浏览器
    writeFileSync(
      join(REPORT_DIR, `group-automation-js.${testInfo.project.name}.result.json`),
      JSON.stringify(metrics, null, 2),
    )
    console.log(`[automation-js:${testInfo.project.name}] metrics=`, JSON.stringify(metrics))
    console.log(
      `[automation-js:${testInfo.project.name}] 如实报告：webdriver=${metrics.webdriver}，求解耗时=${metrics.solve_ms}ms，通行=${metrics.final_reached_origin}`,
    )
  })
})
