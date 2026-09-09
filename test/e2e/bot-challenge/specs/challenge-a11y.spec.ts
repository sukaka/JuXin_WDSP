import { expect, test } from '@playwright/test'
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { navigateUntil403, navigateUntilChallenged, registerVerifyListener } from './helpers'

/**
 * BOT-006 增补：慢设备与键盘导航实测（真实 stage5 栈挑战页，非静态核对）。
 *
 *   - 慢设备：Chromium CDP Emulation.setCPUThrottlingRate=6 模拟低端设备，
 *     断言挑战页在节流下完成求解并通行；求解期间用 setTimeout(0) 探针实测
 *     主线程让出（页面分片 2048 迭代 + setTimeout(0) 让出，探针延迟即主线程
 *     占用证据），逐样本落盘，不凭设计文档断言。
 *   - 键盘导航：route.abort() 模拟网络故障（环境操纵，不改产品）使挑战进入
 *     手动重试态，仅用键盘（Tab/Shift+Tab/Enter）读懂状态、触发重试并通行；
 *     焦点位置与焦点环（outline）实测断言，aria snapshot 留证。
 *
 * 两条用例固定 chromium 通道（CDP 为 Chromium 专有；键盘交互语义跨引擎一致，
 * 其余引擎维度的挑战链路证据由 @browser 多通道覆盖）。
 */

const REPORT_DIR = process.env.BOT_BENCH_REPORT_DIR || '.'

test.describe('BOT-006 慢设备与键盘导航实测 @a11y', () => {
  test('慢设备（CPU 6x 节流）完成求解且主线程无长阻塞', async ({ page, browserName }, testInfo) => {
    test.skip(browserName !== 'chromium', 'CDP CPU 节流仅 Chromium 通道支持')

    const cdp = await page.context().newCDPSession(page)
    await cdp.send('Emulation.setCPUThrottlingRate', { rate: 6 })

    // 主线程让出探针：addInitScript 在页内求解器之前注入，setTimeout(0) 链实测
    // 主线程占用（gap = 请求让出到实际触发的延迟）；样本存 sessionStorage
    // （跨挑战页自动刷新保留），challenge 标记区分挑战页/源站页样本。
    // 节流下 CDP evaluate 与求解窗口竞态（实测两轮探针全丢），故探针必须在页内。
    await page.addInitScript(() => {
      const KEY = '__wdsp_mt_probe__'
      const start = performance.now()
      const tick = () => {
        const a = performance.now()
        setTimeout(() => {
          const b = performance.now()
          try {
            const arr = JSON.parse(sessionStorage.getItem(KEY) || '[]')
            if (arr.length < 500) {
              arr.push({ gap: Math.round(b - a), challenge: !!document.getElementById('wdsp-bot-params') })
              sessionStorage.setItem(KEY, JSON.stringify(arr))
            }
          } catch {
            /* sessionStorage 不可用时探针静默停用（如实无样本） */
          }
          if (performance.now() - start < 30000) tick()
        }, 0)
      }
      tick()
    })

    const verifyStatuses = registerVerifyListener(page)
    // 节流下不读 403 响应体（与页面自动刷新竞态会丢 CDP 资源，实测失败过一次）：
    // 挑战存在由 verify 204 + clearance 密码学链路证明。
    const nav = await navigateUntil403(page)
    expect(nav.got403, '导航后应出现 Bot 挑战页（403）').toBe(true)
    const challengeAt = Date.now()

    // 页内 JS 自动求解 → verify 204 → clearance Cookie → 自动刷新
    await expect
      .poll(() => verifyStatuses.length, { timeout: 60000 })
      .toBeGreaterThan(0)
    const solveMs = Date.now() - challengeAt
    expect(verifyStatuses[0], 'verify 应返回 204').toBe(204)
    await expect
      .poll(
        async () =>
          (await page.context().cookies()).some((c) => c.name.includes('wdsp-bot-clearance')),
        { timeout: 60000 },
      )
      .toBe(true)

    // 最终通行：Bot 步骤通过后直达源站（自动刷新与显式导航竞态时重试一次）
    let again = null
    try {
      again = await page.goto('/', { waitUntil: 'domcontentloaded' })
    } catch (e) {
      if (!String(e).includes('interrupted by another navigation')) throw e
      again = await page.goto('/', { waitUntil: 'domcontentloaded' })
    }
    expect(again?.status()).toBe(200)
    await expect(page.getByText('REACHED_ORIGIN')).toBeVisible({ timeout: 30000 })

    // 主线程无长阻塞卡死：挑战页（求解期）样本的最大 gap << 页面单次计算预算
    // 2000ms（render.go budget_ms）；样本逐条落盘，不凭设计文档断言。
    const probes: Array<{ gap: number; challenge: boolean }> = await page.evaluate(() =>
      JSON.parse(sessionStorage.getItem('__wdsp_mt_probe__') || '[]'),
    )
    const challengeSamples = probes.filter((p) => p.challenge).map((p) => p.gap)
    const maxChallengeGap = challengeSamples.length ? Math.max(...challengeSamples) : null
    expect(
      maxChallengeGap,
      '挑战页求解期应至少采到一个主线程探针样本（探针注入于求解器之前）',
    ).not.toBeNull()
    expect(
      maxChallengeGap!,
      `求解期主线程最大占用 ${maxChallengeGap}ms 应远小于 2000ms 预算（无长阻塞卡死）`,
    ).toBeLessThan(2000)

    const metrics = {
      group: 'a11y-slow-device',
      channel: testInfo.project.name,
      cpu_throttle_rate: 6,
      nav_attempts_before_challenge: nav.attempts,
      challenge_seen: nav.got403,
      solve_ms: solveMs,
      verify_status: verifyStatuses[0],
      main_thread_probes: probes,
      challenge_window_gaps_ms: challengeSamples,
      challenge_window_gap_max_ms: maxChallengeGap,
      final_reached_origin: true,
    }
    writeFileSync(
      join(REPORT_DIR, `group-a11y-slow-device.${testInfo.project.name}.result.json`),
      JSON.stringify(metrics, null, 2),
    )
    console.log('[a11y-slow-device] metrics=', JSON.stringify(metrics))
  })

  test('键盘导航：失败态可读、仅键盘重试并通行、焦点可见', async ({ page, browserName }, testInfo) => {
    test.skip(browserName !== 'chromium', '键盘导航取证固定 Chromium 通道')

    // 模拟网络故障（Playwright 网络层拦截，不改产品代码/页面），
    // 使自动求解后的 verify 提交失败 → 挑战页进入手动重试态
    await page.route('**/_wdsp/bot/v1/verify', (route) => route.abort())

    const nav = await navigateUntilChallenged(page)
    expect(nav.challenged, '导航后应出现 Bot 挑战页').toBe(true)

    // 自动求解 → 提交失败 → 手动态：状态文案可读（role=status 播报）
    await expect(page.locator('#wdsp-manual')).toBeVisible({ timeout: 30000 })
    await expect(page.locator('#wdsp-status')).toHaveText('需要手动操作')
    await expect(page.locator('#wdsp-reason')).toContainText('网络异常')
    const ariaSnapshot = await page.locator('body').ariaSnapshot()
    writeFileSync(join(REPORT_DIR, 'group-a11y-keyboard.aria-snapshot.yml'), ariaSnapshot)

    // 焦点位置：产品行为 showManual() 自动聚焦重试按钮，键盘用户无需寻焦
    const focusedId = await page.evaluate(() => (document.activeElement as HTMLElement | null)?.id ?? '')
    expect(focusedId, '手动重试态焦点应自动落在重试按钮').toBe('wdsp-retry')

    // 仅键盘：Tab 使焦点离开页面唯一可见控件，Shift+Tab 返回重试按钮（焦点循环可预测）。
    // 焦点可见性在键盘模态下断言（:focus-visible 启发式：键盘导航后 UA 焦点环才绘制，
    // 程序化 focus 不绘制属浏览器标准行为，如实记录两者）。
    const outlineProgrammatic = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement
      const s = getComputedStyle(el)
      return { style: s.outlineStyle, width: s.outlineWidth }
    })
    await page.keyboard.press('Tab')
    const afterTab = await page.evaluate(() => (document.activeElement as HTMLElement | null)?.id ?? '')
    await page.keyboard.press('Shift+Tab')
    const afterShiftTab = await page.evaluate(() => (document.activeElement as HTMLElement | null)?.id ?? '')
    expect(afterShiftTab, 'Shift+Tab 后焦点应回到重试按钮（键盘可达）').toBe('wdsp-retry')
    const outlineKeyboard = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement
      const s = getComputedStyle(el)
      return { style: s.outlineStyle, width: s.outlineWidth }
    })
    expect(
      outlineKeyboard.style !== 'none' && outlineKeyboard.width !== '0px',
      `键盘模态焦点环应可见（outline=${outlineKeyboard.style} ${outlineKeyboard.width}）`,
    ).toBe(true)

    // 解除故障，纯键盘 Enter 触发重试 → 重新求解 → verify 204 → 自动刷新通行
    await page.unroute('**/_wdsp/bot/v1/verify')
    const verifyPromise = page.waitForResponse(
      (r) => r.url().includes('/_wdsp/bot/v1/verify') && r.request().method() === 'POST',
      { timeout: 60000 },
    )
    await page.keyboard.press('Enter')
    const verifyResp = await verifyPromise
    expect(verifyResp.status(), '键盘 Enter 重试后 verify 应返回 204').toBe(204)

    // verify 后页面自动刷新（sessionStorage 一次性标记），持 clearance 直达源站
    await expect(page.getByText('REACHED_ORIGIN')).toBeVisible({ timeout: 30000 })

    const metrics = {
      group: 'a11y-keyboard',
      channel: testInfo.project.name,
      nav_attempts_before_challenge: nav.attempts,
      failure_state_readable: true,
      status_text: '需要手动操作',
      reason_text: '网络异常，请检查连接后重试。',
      focus_on_retry_auto: focusedId === 'wdsp-retry',
      focus_outline_programmatic: outlineProgrammatic,
      focus_outline_keyboard: outlineKeyboard,
      tab_moves_away_from_retry: afterTab !== 'wdsp-retry',
      shift_tab_returns_to_retry: afterShiftTab === 'wdsp-retry',
      verify_status_after_keyboard_retry: verifyResp.status(),
      final_reached_origin: true,
    }
    writeFileSync(
      join(REPORT_DIR, `group-a11y-keyboard.${testInfo.project.name}.result.json`),
      JSON.stringify(metrics, null, 2),
    )
    console.log('[a11y-keyboard] metrics=', JSON.stringify(metrics))
  })
})
