import dayjs from 'dayjs'
import type {
  GatewayTCPStates,
  GatewayTrendApplication,
  GatewayTrendCurrent,
  GatewayTrendPoint,
  GatewayTrendRange,
  GatewayTrendResponse,
  GatewayTrendSummary,
} from '../../../types'

/**
 * 演示数据（无真实数据时兜底）
 *
 * 仅供演示：当接口查询成功且 points 为空时，大屏图表区使用本文件数据兜底并展示演示角标；
 * 顶部 KPI 卡恒保持真实值（不做演示替换），查询失败时绝不静默切换演示数据。
 * 所有应用名统一 demo-/test- 前缀，避免冒充真实站点。
 */

function jitter(index: number, seed: number): number {
  const m = (((index * 47 + seed * 31) % 29) + 29) % 29
  return 0.86 + m / 100
}

function wave(index: number, total: number, phase: number): number {
  const ratio = total > 1 ? index / (total - 1) : 0
  return 0.68 + 0.32 * Math.sin(ratio * Math.PI * 2 + phase)
}

const RANGE_SPECS: Record<GatewayTrendRange, { count: number; stepSeconds: number; intervalSeconds: number }> = {
  '10m': { count: 60, stepSeconds: 10, intervalSeconds: 2 },
  '1h': { count: 60, stepSeconds: 60, intervalSeconds: 30 },
  '6h': { count: 72, stepSeconds: 300, intervalSeconds: 30 },
  '24h': { count: 48, stepSeconds: 1800, intervalSeconds: 30 },
}

export const DEMO_TCP_STATES: GatewayTCPStates = {
  established: 318,
  time_wait: 124,
  close_wait: 9,
  syn_recv: 14,
  fin_wait: 22,
  listen: 12,
  other: 6,
}

export const DEMO_GATEWAY_APPLICATIONS: GatewayTrendApplication[] = [
  {
    app_id: 'demo-app-portal',
    app_code: 'demo-portal',
    app_name: 'demo-商城门户',
    requests_in_flight: 24,
    requests_total: 184220,
    requests_per_second: 168.4,
    bypassed_requests_total: 0,
    bytes_in_total: 412 * 1024 ** 2,
    bytes_out_total: 2680 * 1024 ** 2,
    bytes_in_per_second: 520 * 1024,
    bytes_out_per_second: 3.4 * 1024 ** 2,
    status_4xx_total: 412,
    status_5xx_total: 12,
  },
  {
    app_id: 'demo-app-openapi',
    app_code: 'demo-openapi',
    app_name: 'demo-开放API网关',
    requests_in_flight: 19,
    requests_total: 151890,
    requests_per_second: 142.6,
    bypassed_requests_total: 0,
    bytes_in_total: 690 * 1024 ** 2,
    bytes_out_total: 1520 * 1024 ** 2,
    bytes_in_per_second: 780 * 1024,
    bytes_out_per_second: 1.9 * 1024 ** 2,
    status_4xx_total: 685,
    status_5xx_total: 19,
  },
  {
    app_id: 'demo-app-mobile',
    app_code: 'demo-mobile',
    app_name: 'demo-移动端接口',
    requests_in_flight: 14,
    requests_total: 98410,
    requests_per_second: 96.2,
    bypassed_requests_total: 0,
    bytes_in_total: 245 * 1024 ** 2,
    bytes_out_total: 1120 * 1024 ** 2,
    bytes_in_per_second: 310 * 1024,
    bytes_out_per_second: 1.35 * 1024 ** 2,
    status_4xx_total: 204,
    status_5xx_total: 5,
  },
  {
    app_id: 'demo-app-admin',
    app_code: 'demo-admin',
    app_name: 'demo-管理后台',
    requests_in_flight: 8,
    requests_total: 54120,
    requests_per_second: 58.8,
    bypassed_requests_total: 0,
    bytes_in_total: 126 * 1024 ** 2,
    bytes_out_total: 580 * 1024 ** 2,
    bytes_in_per_second: 165 * 1024,
    bytes_out_per_second: 740 * 1024,
    status_4xx_total: 74,
    status_5xx_total: 2,
  },
  {
    app_id: 'test-app-promo',
    app_code: 'test-promo',
    app_name: 'test-营销活动页',
    requests_in_flight: 6,
    requests_total: 39240,
    requests_per_second: 41.5,
    bypassed_requests_total: 0,
    bytes_in_total: 88 * 1024 ** 2,
    bytes_out_total: 790 * 1024 ** 2,
    bytes_in_per_second: 98 * 1024,
    bytes_out_per_second: 920 * 1024,
    status_4xx_total: 52,
    status_5xx_total: 1,
  },
  {
    app_id: 'demo-app-oa',
    app_code: 'demo-oa',
    app_name: 'demo-协同办公',
    requests_in_flight: 4,
    requests_total: 24680,
    requests_per_second: 27.3,
    bypassed_requests_total: 0,
    bytes_in_total: 64 * 1024 ** 2,
    bytes_out_total: 310 * 1024 ** 2,
    bytes_in_per_second: 72 * 1024,
    bytes_out_per_second: 410 * 1024,
    status_4xx_total: 31,
    status_5xx_total: 0,
  },
]

export function buildDemoGatewayTrend(range: GatewayTrendRange): GatewayTrendResponse {
  const spec = RANGE_SPECS[range]
  const anchor = dayjs().startOf('minute')
  const points: GatewayTrendPoint[] = Array.from({ length: spec.count }, (_, i) => {
    const w = wave(i, spec.count, 0.4)
    const takenAt = anchor.subtract((spec.count - 1 - i) * spec.stepSeconds, 'second').toISOString()
    const tcpActive = Math.round(320 * w * jitter(i, 1))
    const tcpAcc = Number((54 * w * jitter(i, 2)).toFixed(2))
    const qps = Number((495 * w * jitter(i, 3)).toFixed(2))
    const sessionsActive = Math.round(1420 * w * jitter(i, 4))
    const sessionsNew = Number((38 * w * jitter(i, 5)).toFixed(2))
    const bytesIn = Math.round(1.85 * 1024 ** 2 * w * jitter(i, 6))
    const bytesOut = Math.round(8.6 * 1024 ** 2 * w * jitter(i, 7))
    const cpu = Number(Math.min(72, 34 + 22 * w * jitter(i, 8)).toFixed(1))
    const mem = Number(Math.min(76, 48 + 14 * w * jitter(i, 9)).toFixed(1))
    const fd = Number(Math.min(68, 26 + 12 * w * jitter(i, 10)).toFixed(1))
    return {
      taken_at: takenAt,
      cpu_percent: cpu,
      memory_percent: mem,
      load1: Number((1.1 + 0.9 * w).toFixed(2)),
      fd_usage_percent: fd,
      tcp_connections_active: tcpActive,
      tcp_connections_accepted_per_second: tcpAcc,
      bytes_in_per_second: bytesIn,
      bytes_out_per_second: bytesOut,
      http_requests_in_flight: Math.max(8, Math.round(qps * 0.14)),
      http_requests_per_second: qps,
      http_sessions_active: sessionsActive,
      http_sessions_new_per_second: sessionsNew,
      status_2xx_per_second: Number((qps * 0.86).toFixed(2)),
      status_3xx_per_second: Number((qps * 0.08).toFixed(2)),
      status_4xx_per_second: Number((qps * 0.05).toFixed(2)),
      status_5xx_per_second: Number((qps * 0.01).toFixed(2)),
      software_bypass_active: false,
    }
  })

  const last = points[points.length - 1]
  const peakConn = Math.max(...points.map((p) => p.tcp_connections_active))
  const avgConn = points.reduce((sum, p) => sum + p.tcp_connections_active, 0) / points.length

  const summary: GatewayTrendSummary = {
    peak_tcp_connections_active: peakConn,
    avg_tcp_connections_active: Number(avgConn.toFixed(1)),
    peak_tcp_connections_accepted_per_second: Math.max(
      ...points.map((p) => p.tcp_connections_accepted_per_second),
    ),
    peak_http_sessions_active: Math.max(...points.map((p) => p.http_sessions_active)),
    peak_http_sessions_new_per_second: Math.max(...points.map((p) => p.http_sessions_new_per_second)),
    peak_http_requests_per_second: Math.max(...points.map((p) => p.http_requests_per_second)),
    peak_bytes_in_per_second: Math.max(...points.map((p) => p.bytes_in_per_second)),
    peak_bytes_out_per_second: Math.max(...points.map((p) => p.bytes_out_per_second)),
    peak_cpu_percent: Math.max(...points.map((p) => p.cpu_percent ?? 0)),
    peak_memory_percent: Math.max(...points.map((p) => p.memory_percent ?? 0)),
    bypass_active_points: 0,
  }

  const current: GatewayTrendCurrent = {
    status: 'UP',
    latency_ms: 2,
    taken_at: last.taken_at,
    cpu_percent: last.cpu_percent,
    memory_percent: last.memory_percent,
    memory_used_bytes: Math.round(9.4 * 1024 ** 3),
    memory_total_bytes: 16 * 1024 ** 3,
    load1: 1.68,
    load5: 1.52,
    load15: 1.39,
    fd_open: 2140,
    fd_max: 65535,
    fd_usage_percent: last.fd_usage_percent,
    tcp_connections_active: last.tcp_connections_active,
    tcp_connections_accepted_total: 486210,
    tcp_connections_accepted_per_second: last.tcp_connections_accepted_per_second,
    bytes_in_total: 1.62 * 1024 ** 3,
    bytes_out_total: 6.98 * 1024 ** 3,
    bytes_in_per_second: last.bytes_in_per_second,
    bytes_out_per_second: last.bytes_out_per_second,
    http_requests_in_flight: last.http_requests_in_flight,
    http_requests_total: 552560,
    http_requests_per_second: last.http_requests_per_second,
    http_sessions_active: last.http_sessions_active,
    http_sessions_new_total: 42180,
    http_sessions_new_per_second: last.http_sessions_new_per_second,
    http_sessions_overflow_total: 0,
    http_sessions_capacity: 10000,
    status_2xx_total: 476200,
    status_3xx_total: 44120,
    status_4xx_total: 28160,
    status_5xx_total: 4080,
    status_2xx_per_second: last.status_2xx_per_second,
    status_3xx_per_second: last.status_3xx_per_second,
    status_4xx_per_second: last.status_4xx_per_second,
    status_5xx_per_second: last.status_5xx_per_second,
    software_bypass: {
      enabled: true,
      active: false,
      cpu_threshold_percent: 85,
      memory_threshold_percent: 85,
      recovery_cpu_percent: 80,
      recovery_memory_percent: 80,
      min_hold_seconds: 60,
      transitions_total: 0,
      bypassed_requests_total: 0,
    },
    tcp_states: DEMO_TCP_STATES,
  }

  return {
    range,
    source: range === '10m' ? 'gateway_live' : 'database',
    interval_seconds: spec.intervalSeconds,
    generated_at: anchor.toISOString(),
    node: 'gateway-demo',
    current,
    summary,
    points,
    applications: DEMO_GATEWAY_APPLICATIONS,
  }
}
