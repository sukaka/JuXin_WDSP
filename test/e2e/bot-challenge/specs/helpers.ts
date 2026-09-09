import type { Page } from '@playwright/test'

/**
 * 挑战流程共享辅助（BOT-004/BOT-006 各 spec 复用；独立于具体 .spec 文件，
 * 避免跨 spec import 导致用例重复注册）。
 */

/** 导航直至挑战页出现（信号判定依赖行为窗口计数；Peek 快照不含本次请求记账，
 * 前两次导航建立观测基线）。403 + 响应体挑战标记为权威判定，不查 DOM（竞态）。 */
export async function navigateUntilChallenged(
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

/** 仅按状态码导航至 403（不读响应体——慢设备/节流下响应体读取与页面自动刷新
 * 竞态会丢资源；挑战 vs WAF 403 的区分由调用方经 verify/clearance 链路证明，
 * 另可选做 DOM 标记的机会性采集）。 */
export async function navigateUntil403(
  page: Page,
  maxAttempts = 6,
): Promise<{ got403: boolean; attempts: number }> {
  for (let i = 1; i <= maxAttempts; i++) {
    const resp = await page.goto('/', { waitUntil: 'domcontentloaded' })
    if (resp?.status() === 403) {
      return { got403: true, attempts: i }
    }
  }
  return { got403: false, attempts: maxAttempts }
}

/** 注册 verify 响应监听（返回状态数组，页内 JS 自动求解可能早于任何断言注册）。 */
export function registerVerifyListener(page: Page): number[] {
  const verifyStatuses: number[] = []
  page.on('response', (r) => {
    if (r.url().includes('/_wdsp/bot/v1/verify') && r.request().method() === 'POST') {
      verifyStatuses.push(r.status())
    }
  })
  return verifyStatuses
}
