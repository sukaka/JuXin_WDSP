import dayjs from 'dayjs'
import type { AppStat, CountPoint, RuleHitStat } from '../../../types'

/**
 * 演示数据（无真实数据时兜底）
 *
 * 仅供演示：当接口查询成功但数据为空、或查询失败时，流量访问屏各数据区
 * 使用本文件数据兜底；一旦接口返回真实数据立即替换，不影响真实数据路径。
 * 请求量按 24 小时昼夜波峰构造（凌晨低谷、午后高峰），应用名统一
 * demo-/test- 前缀，避免冒充真实站点。
 */

const HOURS = 24

/** 最近 24 个整点的时间轴（演示数据，无真实数据时兜底） */
function last24Hours(): string[] {
  const end = dayjs().startOf('hour')
  return Array.from({ length: HOURS }, (_, i) => end.subtract(HOURS - 1 - i, 'hour').toISOString())
}

/** 昼夜波峰系数：凌晨低谷、午后高峰（演示数据，无真实数据时兜底） */
function diurnal(hour: number): number {
  return 0.55 + 0.45 * Math.sin(((hour - 8) / 24) * Math.PI * 2)
}

/** 确定性抖动系数 0.85~1.15，避免轮询刷新时演示数值跳动（演示数据，无真实数据时兜底） */
function jitter(index: number, seed: number): number {
  const m = (((index * 53 + seed * 29) % 31) + 31) % 31
  return 0.85 + m / 100
}

const DEMO_TIMES = last24Hours()

/** 请求趋势与 P95 时延 24h（演示数据，无真实数据时兜底） */
export const DEMO_REQUEST_TREND = {
  times: DEMO_TIMES,
  requests: DEMO_TIMES.map((t, i) =>
    Math.max(0, Math.round(52000 * diurnal(dayjs(t).hour()) * jitter(i, 1))),
  ),
  p95_ms: DEMO_TIMES.map((t, i) => Math.round((96 + 88 * diurnal(dayjs(t).hour())) * jitter(i, 2))),
}

/** CC 防护指标（演示数据，无真实数据时兜底） */
export const DEMO_CC = {
  start: dayjs().subtract(24, 'hour').toISOString(),
  threshold_exceeded: 96,
  requests_rejected: 4873,
}

/** CC 临时封禁趋势 24h（演示数据，无真实数据时兜底） */
export const DEMO_CC_BLOCK_TREND: CountPoint[] = DEMO_TIMES.map((t, i) => ({
  time: t,
  count: Math.round(6 * diurnal(dayjs(t).hour()) * jitter(i, 3)),
}))

/** 访问控制指标（演示数据，无真实数据时兜底） */
export const DEMO_AC = {
  allow_matches: 2134,
  deny_matches: 1247,
  active_temp_blocks: 36,
}

/** 访问控制规则命中 TOP（演示数据，无真实数据时兜底；event_type 与后端枚举一致） */
export const DEMO_AC_RULE_HITS: RuleHitStat[] = [
  { rule_id: 'demo-ac-01', event_type: 'IP_ALLOW_MATCH', hits: 2134 },
  { rule_id: 'demo-ac-02', event_type: 'IP_DENY_MATCH', hits: 1247 },
  { rule_id: 'demo-ac-03', event_type: 'CC_TEMP_BLOCK_CREATED', hits: 96 },
  { rule_id: 'demo-ac-04', event_type: 'TRUSTED_PROXY_INVALID', hits: 42 },
  { rule_id: 'demo-ac-05', event_type: 'FORWARDED_HEADER_INVALID', hits: 18 },
  { rule_id: 'demo-ac-06', event_type: 'FORWARDED_CHAIN_TOO_LONG', hits: 9 },
]

/** 受影响应用 TOP（演示数据，无真实数据时兜底） */
export const DEMO_TOP_APPS: AppStat[] = [
  { code: 'demo-portal', name: 'demo-商城门户', events: 486 },
  { code: 'demo-openapi', name: 'demo-开放API网关', events: 372 },
  { code: 'demo-admin', name: 'demo-管理后台', events: 288 },
  { code: 'demo-mobile', name: 'demo-移动端接口', events: 201 },
  { code: 'test-promo', name: 'test-营销活动页', events: 143 },
  { code: 'demo-oa', name: 'demo-协同办公', events: 96 },
]
