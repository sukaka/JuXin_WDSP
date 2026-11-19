/* ==================== 业务性能（APM 阶段1：无 Agent 模式）展示与判定工具 ==================== */

import dayjs from 'dayjs'
import type { Dayjs } from 'dayjs'

export type ApmRangeValue = [Dayjs | null, Dayjs | null] | null

/** 快捷区间/自定义区间 → 后端 start_time/end_time（RFC3339）；缺省按最近 1 小时（APM 设计 §17.2 默认时间窗） */
export function resolveApmTimeRange(
  range: string,
  custom?: ApmRangeValue,
): { start_time: string; end_time: string } {
  if (range === 'custom' && custom?.[0] && custom[1]) {
    return { start_time: custom[0].toISOString(), end_time: custom[1].toISOString() }
  }
  const end = dayjs()
  const start =
    range === '7d'
      ? end.subtract(7, 'day')
      : range === '30d'
        ? end.subtract(30, 'day')
        : range === '24h'
          ? end.subtract(24, 'hour')
          : end.subtract(1, 'hour')
  return { start_time: start.toISOString(), end_time: end.toISOString() }
}

/** APM 检索类接口（调用链/SQL/异常/依赖/运行时）后端窗口上限：24 小时（server parseSearchWindow，原始表扫描限窗） */
export const APM_SEARCH_WINDOW_HOURS = 24

/** 自定义区间是否超出给定小时上限（两端未选全时视为未超，选全后再拦截） */
export function isCustomRangeOverCap(custom: ApmRangeValue, hours: number): boolean {
  if (!custom?.[0] || !custom[1]) return false
  return custom[1].diff(custom[0], 'millisecond') > hours * 3600_000
}

/** 毫秒时延展示，空值/非法值返回占位符 */
export function formatMs(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '-'
  return `${value} ms`
}

/** 错误率（0-1 小数）→ 百分比展示 */
export function formatPercent(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '-'
  return `${(value * 100).toFixed(2)}%`
}

/** 端点特殊桶：路径无法归一化的未归类聚合 */
export const APM_ENDPOINT_UNCLASSIFIED = '__UNCLASSIFIED__'
/** 端点特殊桶：超出 Top-N 护栏的聚合 */
export const APM_ENDPOINT_OTHER = '__OTHER__'

/** WAF 动作展示（与 D9 waf_action 口径一致；空串按 ALLOW 放行展示） */
export const APM_WAF_ACTION_META: Record<string, { color: string; label: string }> = {
  BLOCK: { color: 'red', label: '阻断' },
  OBSERVE: { color: 'orange', label: '观察' },
  ALLOW: { color: 'default', label: '放行' },
  PASS: { color: 'default', label: '放行' },
  LOG: { color: 'blue', label: '仅记录' },
  REJECT: { color: 'red', label: '拒绝' },
  TEMP_BLOCK: { color: 'magenta', label: '临时封禁' },
}

/** 查询 WAF 动作展示元数据（支持大小写与空串默认放行，未知动作原样回退） */
export function getApmWafActionMeta(action?: string | null): { color: string; label: string } {
  const trimmed = (action ?? '').trim()
  if (!trimmed) return APM_WAF_ACTION_META.ALLOW
  const upper = trimmed.toUpperCase()
  return APM_WAF_ACTION_META[upper] ?? { color: 'default', label: trimmed }
}

/** trace_id 格式：32 位十六进制（W3C Trace Context） */
export const APM_TRACE_ID_PATTERN = /^[0-9a-f]{32}$/i

/** Trace 数据来源展示（APM 设计 §17.2：任何图表/视图都显示当前数据来源） */
export const APM_TRACE_DATA_SOURCE_META: Record<string, { color: string; label: string }> = {
  agentless: { color: 'blue', label: '无 Agent' },
  otel: { color: 'green', label: 'Agent' },
  mixed: { color: 'purple', label: '混合' },
}

/** Agent 状态五态展示（apm.agents.manage 清单） */
export const APM_AGENT_STATUS_META: Record<string, { color: string; label: string }> = {
  ENROLLING: { color: 'gold', label: '注册中' },
  CONNECTED_BASELINE: { color: 'green', label: '已连接·基线' },
  DIAGNOSING: { color: 'purple', label: '诊断中' },
  OFFLINE: { color: 'default', label: '离线' },
  REVOKED: { color: 'red', label: '已撤销' },
}

/** 依赖目标类型展示（/apm-dependencies 的 target_type 词表） */
export const APM_DEPENDENCY_TARGET_TYPE_META: Record<string, { color: string; label: string }> = {
  service: { color: 'blue', label: '服务' },
  db: { color: 'purple', label: '数据库' },
  messaging: { color: 'orange', label: '消息队列' },
  external: { color: 'default', label: '外部服务' },
}

/** SLO 指标类型展示（/apm-slos 的 metric_type 词表） */
export const APM_SLO_METRIC_TYPE_META: Record<string, { color: string; label: string }> = {
  availability: { color: 'green', label: '可用性' },
  latency_p95: { color: 'geekblue', label: 'P95 时延' },
}

/** SLO 状态三态展示（OK=达标 / AT_RISK=有风险 / BREACHED=已违约） */
export const APM_SLO_STATUS_META: Record<string, { color: string; label: string }> = {
  OK: { color: 'green', label: '达标' },
  AT_RISK: { color: 'orange', label: '有风险' },
  BREACHED: { color: 'red', label: '已违约' },
}

/** SLO 目标/当前值展示：availability 为 0-1 比例（百分比），latency_p95 为毫秒阈值（原样 + ms） */
export function formatSloValue(metricType: string, value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '-'
  return metricType === 'latency_p95' ? formatMs(value) : formatPercent(value)
}

/** 相对时间展示（如 Agent 最后心跳）；空值/非法值/未来时间返回占位或"刚刚" */
export function formatRelativeTime(value?: string | null): string {
  if (!value) return '-'
  const d = dayjs(value)
  if (!d.isValid()) return '-'
  const diffSec = dayjs().diff(d, 'second')
  if (diffSec < 0) return '刚刚'
  if (diffSec < 60) return `${diffSec} 秒前`
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin} 分钟前`
  const diffHour = Math.floor(diffMin / 60)
  if (diffHour < 24) return `${diffHour} 小时前`
  const diffDay = Math.floor(diffHour / 24)
  if (diffDay < 30) return `${diffDay} 天前`
  return d.format('YYYY-MM-DD')
}

/* ==================== APM 阶段4：深度诊断中心 ==================== */

/** 诊断会话状态四态展示（/apm-diagnostics 的 status 词表；KILLED=被全局 kill switch 熔断） */
export const APM_DIAGNOSTIC_STATUS_META: Record<string, { color: string; label: string }> = {
  ACTIVE: { color: 'green', label: '进行中' },
  EXPIRED: { color: 'default', label: '已到期' },
  STOPPED: { color: 'blue', label: '已停止' },
  KILLED: { color: 'red', label: '已熔断' },
}

/** 诊断能力展示（label 用于 Tag，risk 为创建向导逐项披露的一句话风险说明，见设计 §6.3/§21.2） */
export const APM_DIAGNOSTIC_CAPABILITY_META: Record<
  string,
  { color: string; label: string; risk: string }
> = {
  sql_detail: {
    color: 'purple',
    label: 'SQL 明细',
    risk: '采集 SQL 语句细节，可能包含业务敏感数据片段',
  },
  function_probe: {
    color: 'geekblue',
    label: '函数探针',
    risk: '对目标方法定向插桩，CPU 开销最高，需精确实例/服务范围',
  },
  thread_block: {
    color: 'orange',
    label: '线程阻塞',
    risk: '周期性线程转储，单次采集开销集中',
  },
  gc_detail: {
    color: 'cyan',
    label: 'GC 明细',
    risk: '开启 GC 详细事件采集，上报数据量明显增大',
  },
  mq_wait: {
    color: 'gold',
    label: '消息等待',
    risk: '采集消息等待/消费明细，span 数量随之增加',
  },
}

/** 剩余时间倒计时展示（ACTIVE 会话按 expires_at 与传入的 now 计算；<=0 视为已到期，非法值返回占位符） */
export function formatDiagnosticCountdown(expiresAt: string | null | undefined, now: number): string {
  if (!expiresAt) return '-'
  const expiry = dayjs(expiresAt)
  if (!expiry.isValid()) return '-'
  const diffSec = Math.floor((expiry.valueOf() - now) / 1000)
  if (diffSec <= 0) return '已到期'
  const hours = Math.floor(diffSec / 3600)
  const minutes = Math.floor((diffSec % 3600) / 60)
  const seconds = diffSec % 60
  if (hours > 0) return `${hours} 小时 ${minutes} 分`
  return `${minutes} 分 ${seconds} 秒`
}

/* ==================== P1-01 A3：availability / correlation 展示与安全事件跳转 ==================== */
/* 词表与 server/internal/apm/types.go 冻结常量一致；旧后端缺字段时页面显示「状态信息不足」，不编造原因 */

/** availability.query_state 展示（状态均配文字标签，不只靠颜色区分） */
export const APM_QUERY_STATE_META: Record<string, { color: string; label: string }> = {
  READY: { color: 'green', label: '数据就绪' },
  EMPTY: { color: 'default', label: '查询成功但无数据' },
  PARTIAL: { color: 'orange', label: '部分数据' },
  UNAVAILABLE: { color: 'red', label: '存储不可用' },
}

/** availability.reason_codes 冻结枚举的中文解释（仅陈述事实，不作超出证据的推断） */
export const APM_REASON_CODE_LABELS: Record<string, string> = {
  STORAGE_NOT_CONFIGURED: '调用链存储未配置',
  STORAGE_UNAVAILABLE: '调用链存储当前不可用',
  ACCESS_LOG_DISABLED: '访问日志已关闭，网关侧观测数据缺失',
  NO_INSTRUMENTATION_CONFIRMED: '已确认应用未接入探针',
  NOT_SAMPLED_CONFIRMED: '已确认该请求未被采样',
  INGESTION_DELAY_CONFIRMED: '数据入库存在延迟',
  OUTSIDE_RETENTION: '查询时间超出数据保留期',
  NO_MATCH: '在现有数据中未找到匹配记录',
  UNKNOWN: '原因未知（证据不足）',
}

/** correlation.state 展示（均配文字标签） */
export const APM_CORRELATION_STATE_META: Record<string, { color: string; label: string }> = {
  MATCHED: { color: 'green', label: '已关联' },
  AMBIGUOUS: { color: 'orange', label: '存在多个候选' },
  PENDING: { color: 'processing', label: '等待入库' },
  NOT_FOUND: { color: 'default', label: '未找到关联' },
  NOT_EXPECTED: { color: 'blue', label: '预期无调用链' },
  UNKNOWN: { color: 'default', label: '关联状态未知' },
}

/** match_basis 匹配依据展示（机器可读值 → 中文） */
export const APM_MATCH_BASIS_LABELS: Record<string, string> = {
  request_id_to_trace_id: '按请求 ID 解析',
  trace_id_direct: '按 Trace ID 精确匹配',
  'otel_traces.trace_id': '数据面 Span 命中',
  'access_logs.trace_id': '网关访问记录解析（数据面未确认）',
}

/** SQL/异常接口 match_mode 展示：window_aggregate 必须如实标注为「同时间窗候选」，不得写成已定位根因 */
export const APM_MATCH_MODE_META: Record<string, { color: string; label: string }> = {
  trace_exact: { color: 'green', label: '已按 Trace 精确定位' },
  window_aggregate: { color: 'orange', label: '同时间窗候选，未精确定位' },
}

/** 入库等待预算：最多自动等待 30 秒（任务书 §5-2），之后改手动刷新；不得无限轮询 */
export const APM_INGEST_WAIT_BUDGET_MS = 30_000
/** 入库等待的自动重试间隔 */
export const APM_INGEST_RETRY_INTERVAL_MS = 5_000

/**
 * 是否处于「等待入库」状态：关联判定 PENDING，或有证据表明入库延迟（INGESTION_DELAY_CONFIRMED）。
 * 仅这两个有依据的信号触发；UNKNOWN/NO_MATCH 不触发自动等待。
 */
export function isApmIngestionPending(source: {
  correlation?: { state?: string } | null
  availability?: { reason_codes?: string[] } | null
}): boolean {
  if (source.correlation?.state === 'PENDING') return true
  return (source.availability?.reason_codes ?? []).includes('INGESTION_DELAY_CONFIRMED')
}

/**
 * 有界等待决策：距等待开始 elapsedMs 后，下一次自动重试的延迟（毫秒）；
 * 返回 null 表示预算已用尽，停止自动重试（交由用户手动刷新）。
 */
export function nextApmIngestRetryDelay(elapsedMs: number): number | null {
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) return APM_INGEST_RETRY_INTERVAL_MS
  const remaining = APM_INGEST_WAIT_BUDGET_MS - elapsedMs
  if (remaining <= 0) return null
  return Math.min(APM_INGEST_RETRY_INTERVAL_MS, remaining)
}

/** 入库滞后估计展示（estimated_lag_ms 为表级水位估计，非请求级精确延迟） */
export function formatLagMs(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '未知'
  if (value < 1000) return `${value} 毫秒`
  const seconds = Math.round(value / 1000)
  if (seconds < 60) return `约 ${seconds} 秒`
  return `约 ${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`
}

/** application_id URL 参数校验（UUID；后端对非法值返回 400，前端先拦截并提示） */
export const APM_APPLICATION_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** 返回链接白名单：仅允许站内已知路由（任务书 §5-1，不接受任意外部跳转） */
export const APM_RETURN_PATH_WHITELIST: { prefix: string; label: string }[] = [
  { prefix: '/security-events', label: '返回安全事件' },
  { prefix: '/access-logs', label: '返回访问日志' },
  { prefix: '/apm-overview', label: '返回性能总览' },
  { prefix: '/apm-traces', label: '返回调用链检索' },
]

/**
 * 校验 from 返回参数：命中白名单返回 { path, label }，否则返回 null。
 * 拒绝协议相对地址（//）、带 scheme 的 URL、控制字符，防开放重定向（APMD-012）。
 */
export function sanitizeApmReturnPath(
  raw: string | null | undefined,
): { path: string; label: string } | null {
  if (!raw) return null
  const v = raw.trim()
  if (!v.startsWith('/') || v.startsWith('//')) return null
  if (/[\r\n]/.test(v) || /[a-zA-Z][a-zA-Z0-9+.-]*:/.test(v)) return null
  const hit = APM_RETURN_PATH_WHITELIST.find(
    (w) =>
      v === w.prefix ||
      v.startsWith(`${w.prefix}?`) ||
      v.startsWith(`${w.prefix}#`) ||
      v.startsWith(`${w.prefix}/`),
  )
  return hit ? { path: v, label: hit.label } : null
}

/** 事件 → 调用链检索的默认时间窗：事件时间前后各 5 分钟（任务书 §5-1 建议默认值） */
export const APM_EVENT_WINDOW_MINUTES = 5

/**
 * 构造安全事件 → 调用链检索的跳转链接：携带 request_id、application_id（事件上有的话）、
 * 事件时间 ±5 分钟的 start_time/end_time 与站内返回地址；无 request_id 或事件时间非法时返回 null。
 */
export function buildEventApmTraceHref(event: {
  request_id?: string | null
  application_id?: string | null
  occurred_at?: string | null
}): string | null {
  const requestId = event.request_id?.trim()
  if (!requestId) return null
  const occurred = dayjs(event.occurred_at ?? '')
  if (!occurred.isValid()) return null
  const params = new URLSearchParams()
  params.set('request_id', requestId)
  const appId = event.application_id?.trim()
  if (appId) params.set('application_id', appId)
  params.set('start_time', occurred.subtract(APM_EVENT_WINDOW_MINUTES, 'minute').toISOString())
  params.set('end_time', occurred.add(APM_EVENT_WINDOW_MINUTES, 'minute').toISOString())
  params.set('from', '/security-events')
  return `/apm-traces?${params.toString()}`
}

/**
 * 解析 URL 上的 start_time/end_time（RFC3339）：两者都缺省返回 null（不限定窗口）；
 * 只给其一、格式非法、start 不早于 end、窗口超 24h（trace-search 上限）均视为非法，返回错误文案。
 */
export function parseApmUrlTimeWindow(
  startRaw: string | null,
  endRaw: string | null,
): { start_time: string; end_time: string } | { error: string } | null {
  const sv = startRaw?.trim() ?? ''
  const ev = endRaw?.trim() ?? ''
  if (!sv && !ev) return null
  if (!sv || !ev) return { error: 'URL 时间参数起止时间需同时提供，已忽略该时间窗' }
  const start = dayjs(sv)
  const end = dayjs(ev)
  if (!start.isValid() || !end.isValid()) {
    return { error: 'URL 时间参数格式非法（需 RFC3339），已忽略该时间窗' }
  }
  if (!start.isBefore(end)) {
    return { error: 'URL 时间参数开始时间必须早于结束时间，已忽略该时间窗' }
  }
  if (end.diff(start, 'millisecond') > APM_SEARCH_WINDOW_HOURS * 3600_000) {
    return { error: `URL 时间窗超过 ${APM_SEARCH_WINDOW_HOURS} 小时上限，已忽略该时间窗` }
  }
  return { start_time: start.toISOString(), end_time: end.toISOString() }
}

/** 异常消息/堆栈等纯文本的前端展示上限（后端已截断，前端兜底再限长；一律按纯文本渲染） */
export const APM_PLAIN_TEXT_MAX_LENGTH = 8192

/** 纯文本限长：超出 max 时截断并追加可见标记；非字符串/空值原样返回空串由调用方展示占位 */
export function capApmPlainText(text: string | null | undefined, max = APM_PLAIN_TEXT_MAX_LENGTH): string {
  if (!text) return ''
  if (text.length <= max) return text
  return `${text.slice(0, max)}…（已截断，共 ${text.length} 字符）`
}
