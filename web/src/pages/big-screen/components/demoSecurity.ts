import dayjs from 'dayjs'
import type { KeyValue, RiskEventSummary, SecurityOverviewToday, SourceIPStat } from '../../../types'

/**
 * 演示数据（无真实数据时兜底）
 *
 * 仅供演示：当接口查询成功但数据为空、或查询失败时，安全态势屏各数据区
 * 使用本文件数据兜底；一旦接口返回真实数据立即替换，不影响真实数据路径。
 * 数值按「攻击量级数百到数千、24 小时昼夜波峰」构造，IP 使用 RFC 5737
 * 文档保留段（203.0.113.x / 198.51.100.x / 192.0.2.x），应用名统一
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
  const m = (((index * 37 + seed * 91) % 31) + 31) % 31
  return 0.85 + m / 100
}

/** 按昼夜曲线生成 24 小时序列（演示数据，无真实数据时兜底） */
function waveSeries(base: number, seed: number): number[] {
  return DEMO_TIMES.map((t, i) => Math.max(0, Math.round(base * diurnal(dayjs(t).hour()) * jitter(i, seed))))
}

const DEMO_TIMES = last24Hours()

/** 今日指标（演示数据，无真实数据时兜底） */
export const DEMO_TODAY: SecurityOverviewToday = {
  requests_total: 1286430,
  waf_events: 2864,
  waf_blocks: 1732,
  waf_observes: 1132,
  cc_exceeded: 96,
  ip_deny_matches: 1187,
  temp_blocked_ips: 36,
  unprocessed_high_events: 12,
  protected_apps: 18,
  abnormal_apps: 0,
  abnormal_upstreams: 0,
  expiring_certs: 1,
}

const demoEventsSeries = waveSeries(120, 1)

/** 安全事件 24h 趋势（演示数据，无真实数据时兜底） */
export const DEMO_TREND = {
  times: DEMO_TIMES,
  security_events: demoEventsSeries,
  blocks: demoEventsSeries.map((v, i) => Math.round(v * (0.58 + jitter(i, 2) * 0.08))),
  observes: demoEventsSeries.map((v, i) => Math.max(0, v - Math.round(v * (0.58 + jitter(i, 2) * 0.08)))),
}

/** 风险等级 24h 分布序列（演示数据，无真实数据时兜底） */
export const DEMO_RISK_LEVELS: Record<string, number[]> = {
  HIGH: waveSeries(9, 3),
  MEDIUM: waveSeries(34, 4),
  LOW: waveSeries(58, 5),
  INFO: waveSeries(21, 6),
}

/** 攻击类型 TOP（演示数据，无真实数据时兜底） */
export const DEMO_ATTACK_TYPES: KeyValue[] = [
  { key: 'SQL_INJECTION', value: 486 },
  { key: 'XSS', value: 372 },
  { key: 'SCANNER_DETECTION', value: 288 },
  { key: 'COMMAND_INJECTION', value: 164 },
  { key: 'PROTOCOL_VIOLATION', value: 97 },
]

/** 攻击源 IP TOP（演示数据，无真实数据时兜底；RFC 5737 文档保留段） */
export const DEMO_SOURCE_IPS: SourceIPStat[] = [
  { ip: '203.0.113.17', events: 412, blocks: 388 },
  { ip: '198.51.100.23', events: 356, blocks: 301 },
  { ip: '203.0.113.88', events: 291, blocks: 274 },
  { ip: '192.0.2.146', events: 233, blocks: 198 },
  { ip: '198.51.100.201', events: 187, blocks: 165 },
]

/** 被攻击应用 TOP（演示数据，无真实数据时兜底） */
export const DEMO_TOP_APPS: KeyValue[] = [
  { key: 'demo-商城门户', value: 812 },
  { key: 'demo-开放API网关', value: 634 },
  { key: 'demo-管理后台', value: 477 },
  { key: 'demo-移动端接口', value: 356 },
  { key: 'test-营销活动页', value: 209 },
]

/** 高危未处置事件滚动列表（演示数据，无真实数据时兜底） */
export const DEMO_TICKER_EVENTS: RiskEventSummary[] = [
  { id: 'demo-evt-01', occurred_at: dayjs().subtract(2, 'minute').toISOString(), client_ip: '203.0.113.17', application_name: 'demo-商城门户', attack_type: 'SQL_INJECTION', severity: 'HIGH', request_path: '/api/orders/detail', action: 'BLOCK' },
  { id: 'demo-evt-02', occurred_at: dayjs().subtract(6, 'minute').toISOString(), client_ip: '198.51.100.23', application_name: 'demo-开放API网关', attack_type: 'XSS', severity: 'HIGH', request_path: '/api/comments', action: 'BLOCK' },
  { id: 'demo-evt-03', occurred_at: dayjs().subtract(11, 'minute').toISOString(), client_ip: '203.0.113.88', application_name: 'demo-管理后台', attack_type: 'COMMAND_INJECTION', severity: 'HIGH', request_path: '/admin/system/ping', action: 'BLOCK' },
  { id: 'demo-evt-04', occurred_at: dayjs().subtract(18, 'minute').toISOString(), client_ip: '192.0.2.146', application_name: 'demo-移动端接口', attack_type: 'SCANNER_DETECTION', severity: 'MEDIUM', request_path: '/.git/config', action: 'BLOCK' },
  { id: 'demo-evt-05', occurred_at: dayjs().subtract(26, 'minute').toISOString(), client_ip: '198.51.100.201', application_name: 'demo-商城门户', attack_type: 'LOCAL_FILE_INCLUSION', severity: 'HIGH', request_path: '/static/../../../etc/passwd', action: 'BLOCK' },
  { id: 'demo-evt-06', occurred_at: dayjs().subtract(35, 'minute').toISOString(), client_ip: '203.0.113.17', application_name: 'demo-开放API网关', attack_type: 'SQL_INJECTION', severity: 'HIGH', request_path: '/api/users/login', action: 'BLOCK' },
  { id: 'demo-evt-07', occurred_at: dayjs().subtract(47, 'minute').toISOString(), client_ip: '198.51.100.77', application_name: 'test-营销活动页', attack_type: 'PROTOCOL_VIOLATION', severity: 'MEDIUM', request_path: '/promo/draw', action: 'OBSERVE' },
  { id: 'demo-evt-08', occurred_at: dayjs().subtract(58, 'minute').toISOString(), client_ip: '192.0.2.60', application_name: 'demo-管理后台', attack_type: 'REMOTE_CODE_EXECUTION', severity: 'HIGH', request_path: '/admin/jobs/run', action: 'BLOCK' },
]
