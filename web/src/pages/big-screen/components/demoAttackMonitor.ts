import dayjs from 'dayjs'
import type { AnalyticsTrendData, KeyValue, RuleStat, SourceIPStat, URIStat } from '../../../types'

/**
 * 演示数据（无真实数据时兜底）
 *
 * 仅供演示：当接口查询成功但数据为空、或查询失败时，攻击监控屏侧栏各数据区
 * （KPI、24h 趋势、攻击类型、命中规则、源 IP / URI 排行、实时事件滚动）
 * 使用本文件数据兜底；一旦接口返回真实数据立即替换，不影响真实数据路径。
 * 数值按「攻击量级数百到数千、24 小时昼夜波峰」构造，IP 使用 RFC 5737
 * 文档保留段（203.0.113.x / 198.51.100.x / 192.0.2.x），域名统一
 * demo-/test- 前缀的 example.com 保留域，避免冒充真实站点。
 *
 * 注意：全球攻击路线的演示兜底在 GlobeAttackMap 组件内部完成，本文件不提供 routes。
 */

const HOURS = 24

/** 最近 24 个整点的时间轴（演示数据，无真实数据时兜底） */
function last24Hours(): string[] {
  const end = dayjs().startOf('hour')
  return Array.from({ length: HOURS }, (_, i) => end.subtract(HOURS - 1 - i, 'hour').toISOString())
}

/** 昼夜波峰系数：凌晨低谷、白天至晚间高峰（演示数据，无真实数据时兜底） */
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

const demoEventsSeries = waveSeries(130, 11)
const demoBlocksSeries = demoEventsSeries.map((v, i) => Math.round(v * (0.62 + jitter(i, 12) * 0.1)))

/** 攻击事件 24h 趋势（演示数据，无真实数据时兜底；结构与 AnalyticsTrendData 一致） */
export const DEMO_ATTACK_TREND: AnalyticsTrendData = {
  start: DEMO_TIMES[0],
  end: DEMO_TIMES[HOURS - 1],
  granularity: 'hour',
  times: DEMO_TIMES,
  series: {
    events: demoEventsSeries,
    blocks: demoBlocksSeries,
    observes: demoEventsSeries.map((v, i) => Math.max(0, v - demoBlocksSeries[i])),
  },
}

/** 攻击类型构成（演示数据，无真实数据时兜底；key 与后端攻击类型枚举一致） */
export const DEMO_ATTACK_TYPES: KeyValue[] = [
  { key: 'SQL_INJECTION', value: 486 },
  { key: 'XSS', value: 352 },
  { key: 'SCANNER_DETECTION', value: 264 },
  { key: 'LOCAL_FILE_INCLUSION', value: 148 },
  { key: 'COMMAND_INJECTION', value: 96 },
  { key: 'PROTOCOL_VIOLATION', value: 72 },
]

/** 攻击源 IP TOP8（演示数据，无真实数据时兜底；RFC 5737 文档保留段） */
export const DEMO_ATTACK_IPS: SourceIPStat[] = [
  { ip: '203.0.113.17', events: 286, blocks: 251 },
  { ip: '203.0.113.204', events: 231, blocks: 198 },
  { ip: '198.51.100.77', events: 196, blocks: 140 },
  { ip: '203.0.113.88', events: 164, blocks: 121 },
  { ip: '198.51.100.230', events: 127, blocks: 96 },
  { ip: '192.0.2.146', events: 98, blocks: 61 },
  { ip: '203.0.113.45', events: 83, blocks: 52 },
  { ip: '198.51.100.12', events: 67, blocks: 40 },
]

/** 被攻击 URI TOP8（演示数据，无真实数据时兜底） */
export const DEMO_ATTACK_URIS: URIStat[] = [
  { path: '/api/v1/users/login', events: 214, blocks: 186 },
  { path: '/wp-login.php', events: 187, blocks: 187 },
  { path: '/admin/index.php', events: 156, blocks: 156 },
  { path: '/api/v1/orders', events: 132, blocks: 98 },
  { path: '/api/upload', events: 98, blocks: 74 },
  { path: '/.env', events: 87, blocks: 87 },
  { path: '/console/login', events: 76, blocks: 64 },
  { path: '/api/v1/search', events: 61, blocks: 38 },
]

/** 命中规则 TOP5（演示数据，无真实数据时兜底；rule_id 为真实 CRS 规则编号，name 为 CRS 风格中文名） */
export const DEMO_ATTACK_RULES: (RuleStat & { name: string })[] = [
  { rule_id: 942100, hits: 412, false_positives: 3, name: 'SQL注入攻击检测' },
  { rule_id: 941160, hits: 346, false_positives: 5, name: 'XSS跨站脚本检测' },
  { rule_id: 932100, hits: 187, false_positives: 1, name: '远程命令执行检测' },
  { rule_id: 930120, hits: 143, false_positives: 2, name: '路径穿越与文件包含' },
  { rule_id: 949110, hits: 128, false_positives: 0, name: '异常评分拦截评估' },
]

/** 实时事件滚动条目（演示数据，无真实数据时兜底；字段为 SecurityEventItem 的展示子集） */
export interface DemoAttackEvent {
  id: string
  occurred_at: string
  client_ip: string
  domain: string
  request_path: string
  attack_type: string
  severity: string
  action: string
}

/** 事件模板池：IP 为文档保留段，域名为 demo-/test- 前缀保留域（演示数据，无真实数据时兜底） */
const DEMO_EVENT_POOL: Omit<DemoAttackEvent, 'id' | 'occurred_at'>[] = [
  { client_ip: '203.0.113.17', domain: 'demo-shop.example.com', request_path: '/api/v1/users/login', attack_type: 'SQL_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '198.51.100.77', domain: 'demo-portal.example.com', request_path: '/api/comments', attack_type: 'XSS', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '203.0.113.204', domain: 'test-api.example.com', request_path: '/api/v1/orders', attack_type: 'SQL_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '192.0.2.146', domain: 'demo-shop.example.com', request_path: '/.git/config', attack_type: 'SCANNER_DETECTION', severity: 'MEDIUM', action: 'BLOCK' },
  { client_ip: '203.0.113.88', domain: 'demo-portal.example.com', request_path: '/admin/system/ping', attack_type: 'COMMAND_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '198.51.100.230', domain: 'test-api.example.com', request_path: '/api/v1/files', attack_type: 'LOCAL_FILE_INCLUSION', severity: 'MEDIUM', action: 'BLOCK' },
  { client_ip: '203.0.113.17', domain: 'demo-shop.example.com', request_path: '/api/v1/users/login', attack_type: 'SQL_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '198.51.100.12', domain: 'demo-portal.example.com', request_path: '/promo/draw', attack_type: 'PROTOCOL_VIOLATION', severity: 'LOW', action: 'OBSERVE' },
  { client_ip: '203.0.113.45', domain: 'test-api.example.com', request_path: '/api/v1/search', attack_type: 'XSS', severity: 'MEDIUM', action: 'BLOCK' },
  { client_ip: '192.0.2.60', domain: 'demo-shop.example.com', request_path: '/admin/jobs/run', attack_type: 'REMOTE_CODE_EXECUTION', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '203.0.113.204', domain: 'demo-portal.example.com', request_path: '/wp-login.php', attack_type: 'SCANNER_DETECTION', severity: 'MEDIUM', action: 'BLOCK' },
  { client_ip: '198.51.100.77', domain: 'test-api.example.com', request_path: '/api/v1/orders/export', attack_type: 'INFORMATION_DISCLOSURE', severity: 'MEDIUM', action: 'OBSERVE' },
  { client_ip: '203.0.113.88', domain: 'demo-shop.example.com', request_path: '/static/../../../etc/passwd', attack_type: 'LOCAL_FILE_INCLUSION', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '198.51.100.230', domain: 'demo-portal.example.com', request_path: '/api/comments', attack_type: 'XSS', severity: 'MEDIUM', action: 'BLOCK' },
  { client_ip: '203.0.113.17', domain: 'test-api.example.com', request_path: '/api/v1/users/login', attack_type: 'SQL_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '192.0.2.146', domain: 'demo-shop.example.com', request_path: '/.env', attack_type: 'SCANNER_DETECTION', severity: 'LOW', action: 'BLOCK' },
  { client_ip: '203.0.113.45', domain: 'demo-portal.example.com', request_path: '/api/upload', attack_type: 'COMMAND_INJECTION', severity: 'MEDIUM', action: 'BLOCK' },
  { client_ip: '198.51.100.12', domain: 'test-api.example.com', request_path: '/api/v1/sessions', attack_type: 'SESSION_FIXATION', severity: 'LOW', action: 'OBSERVE' },
  { client_ip: '203.0.113.204', domain: 'demo-shop.example.com', request_path: '/api/v1/users/login', attack_type: 'SQL_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { client_ip: '198.51.100.77', domain: 'demo-portal.example.com', request_path: '/console/login', attack_type: 'SCANNER_DETECTION', severity: 'MEDIUM', action: 'OBSERVE' },
]

/** 实时攻击事件滚动列表（演示数据，无真实数据时兜底；时间相对模块加载时刻，间隔数秒至数分钟） */
export const DEMO_ATTACK_EVENTS: DemoAttackEvent[] = DEMO_EVENT_POOL.map((e, i) => ({
  ...e,
  id: `demo-attack-${String(i + 1).padStart(2, '0')}`,
  occurred_at: dayjs()
    .subtract(8 + i * 47 + (i % 5) * 9, 'second')
    .toISOString(),
}))
