import dayjs from 'dayjs'

/* ==================== WDSP 流量采集 Agent 展示工具（契约 docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md） ==================== */

/** Agent 状态展示（§5 派生：DISABLED/OFFLINE 优先，否则取心跳上报状态） */
export const TRAFFIC_AGENT_STATUS_META: Record<string, { color: string; label: string }> = {
  ONLINE: { color: 'green', label: '在线' },
  OFFLINE: { color: 'default', label: '离线' },
  DEGRADED: { color: 'orange', label: '降级' },
  ERROR: { color: 'red', label: '异常' },
  DISABLED: { color: 'default', label: '已禁用' },
}

/** TLS 可见性展示（§3.4；ENCRYPTED 需提示加密流量无法完整分析；DECRYPTED 为 v2 增量——
 * 需可信终止点证据，不能由外部 Header 单独决定） */
export const TLS_VISIBILITY_META: Record<string, { color: string; label: string; tooltip?: string }> = {
  PLAINTEXT: { color: 'green', label: '明文' },
  ENCRYPTED: { color: 'orange', label: '加密', tooltip: '加密流量无法完整分析' },
  DECRYPTED: {
    color: 'cyan',
    label: '已解密',
    tooltip: 'TLS 终止点后观测（部署拓扑断言的可信终止点，非外部 Header 决定）',
  },
  UNKNOWN: { color: 'default', label: '未知' },
}

/** 事件类型展示（§3.4） */
export const FLOW_EVENT_TYPE_META: Record<string, { color: string; label: string }> = {
  request: { color: 'blue', label: '请求' },
  flow_end: { color: 'default', label: '流结束' },
}

/** K8s 端点方向（src / dst）展示 */
export const K8S_SIDE_LABELS: Record<string, string> = {
  src: '源端',
  dst: '目标端',
}

/** K8s 端点方向中文格式化（未知原样返回） */
export function formatK8sSide(side?: string | null): string {
  if (!side) return '-'
  return K8S_SIDE_LABELS[side] ?? side
}

/* ==================== Phase 2：健康评分（PHASE2 契约 §4 原因码 → 展示文案） ==================== */

/** 健康评分扣分原因码展示（机读码由服务端 ComputeHealth 输出；未知码原样展示） */
export const HEALTH_REASON_META: Record<string, string> = {
  agent_disabled: 'Agent 已禁用',
  agent_offline: 'Agent 离线',
  status_error: '自报状态异常',
  status_degraded: '自报状态降级',
  cpu_over_limit: 'CPU 超过阈值',
  cpu_high: 'CPU 偏高（>80% 阈值）',
  memory_over_limit: '内存超过阈值',
  memory_high: '内存偏高（>80% 阈值）',
  drop_rate_critical: '丢包率严重（>10%）',
  drop_rate_high: '丢包率偏高（>1%）',
  queue_overflow: '队列积压严重（>5000）',
  queue_high: '队列积压（>1000）',
  buffer_near_full: '磁盘缓存接近上限（>90%）',
  buffer_high: '磁盘缓存偏高（>75%）',
  clock_drift: '时钟偏移超阈（>5s）',
  clock_skew: '时钟偏移偏大（>2s）',
  config_not_synced: '配置未同步',
}

/** 健康分分档着色：≥80 绿 / 60–79 黄 / 40–59 橙 / <40 红（0 分禁用态灰） */
export function healthScoreColor(score?: number | null): string {
  if (score === null || score === undefined || !Number.isFinite(score)) return 'default'
  if (score <= 0) return 'default'
  if (score >= 80) return '#52c41a'
  if (score >= 60) return '#faad14'
  if (score >= 40) return '#fa8c16'
  return '#f5222d'
}

/** 扣分原因码数组 → 中文文案数组（未知码原样保留，便于排查新增档位） */
export function healthReasonLabels(reasons?: string[] | null): string[] {
  if (!reasons || reasons.length === 0) return []
  return reasons.map((r) => HEALTH_REASON_META[r] ?? r)
}

/** 时钟偏移毫秒展示（正=Agent 时钟偏慢，负=偏快），空值返回占位符 */
export function formatClockOffset(ms?: number | null): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '-'
  const abs = Math.abs(ms)
  const text = abs >= 1000 ? `${(abs / 1000).toFixed(1)}s` : `${abs}ms`
  return ms >= 0 ? `+${text}（偏慢）` : `-${text}（偏快）`
}

/** 字节速率（bytes/s）→ Mbps 展示，空值/非法值返回占位符 */
export function formatMbps(bps?: number | null): string {
  if (bps === null || bps === undefined || !Number.isFinite(bps) || bps < 0) return '-'
  return ((bps * 8) / 1_000_000).toFixed(2)
}

/** 速率计数（pps/drop/s）展示，空值/非法值返回占位符 */
export function formatRate(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '-'
  return String(Math.round(value))
}

/* ==================== Phase 3：HTTP Sensor（PHASE3 契约 §3/§4/§9） ==================== */

/** HTTP 状态码分档着色（§9：2xx 绿 / 3xx 蓝 / 4xx 橙 / 5xx 红 / 无响应灰） */
export function httpStatusColor(status?: number | null): string {
  if (status === null || status === undefined || !Number.isFinite(status)) return 'default'
  if (status >= 200 && status < 300) return 'green'
  if (status >= 300 && status < 400) return 'blue'
  if (status >= 400 && status < 500) return 'orange'
  if (status >= 500 && status < 600) return 'red'
  return 'default'
}

/** Body 未采集原因码展示（§4 硬红线；未知码原样展示便于排查新增码） */
export const BODY_SKIPPED_REASON_META: Record<string, string> = {
  content_type: '内容类型不在采集白名单',
  encoding: '压缩编码无法解压',
}

/* ==================== P1-03 G4a：HTTP 事件 v2 展示（v2 契约 §2/§5；任务书 §4.3） ==================== */

/** 采集来源类型展示（NGINX_MIRROR/ENVOY_TAP 由 G2/G3 适配器产生） */
export const SOURCE_TYPE_META: Record<string, { color: string; label: string; tooltip?: string }> = {
  PASSIVE_HTTP1: { color: 'blue', label: '被动 HTTP/1' },
  NGINX_MIRROR: {
    color: 'purple',
    label: 'Nginx 镜像',
    tooltip: 'TLS 终止后请求镜像：仅请求可见，原业务响应与延迟不可见',
  },
  ENVOY_TAP: { color: 'geekblue', label: 'Envoy Tap' },
}

/** 请求/响应关联状态展示（v2 契约 §2；COMPLETE 之外必须有原因） */
export const ASSOC_STATE_META: Record<string, { color: string; label: string }> = {
  COMPLETE: { color: 'green', label: '完整配对' },
  REQUEST_ONLY: { color: 'orange', label: '仅请求' },
  PARTIAL: { color: 'orange', label: '部分数据' },
  UNCORRELATED: { color: 'red', label: '未关联' },
}

/** 关联原因码展示（v2 契约 §2；未知码原样展示） */
export const ASSOC_REASON_META: Record<string, string> = {
  SOURCE_REQUEST_ONLY: '来源仅提供请求（单向源）',
  TIMEOUT: '响应等待超时',
  DISCONNECT: '来源连接中断',
  TRUNCATED: '数据被截断',
  CORRELATION_MISS: '流关联失败',
}

/** 资产来源关联状态展示（v2 契约 §5；事件入库 ≠ 资产关联成功） */
export const ASSET_LINK_STATE_META: Record<string, { color: string; label: string; tooltip?: string }> = {
  LINKED: { color: 'green', label: '已关联' },
  UNASSIGNED: {
    color: 'orange',
    label: '未绑定',
    tooltip: '记录未声明来源绑定，待管理面确认；不随意归入同名路径资产',
  },
  QUOTA_REJECTED: { color: 'red', label: '配额拒绝', tooltip: '授权端点配额超限，新端点未落库' },
  FAILED: { color: 'red', label: '关联失败' },
  SKIPPED_NON_API: {
    color: 'default',
    label: '已过滤(非API)',
    tooltip: '命中静态资源或非 API 过滤规则，仅留存来源记录，不写入 API 资产表',
  },
}

/** gRPC 流状态展示（v2 契约 §2.2；取消与未结束如实表示） */
export const GRPC_STREAM_STATE_META: Record<string, { color: string; label: string }> = {
  OPEN: { color: 'processing', label: '流进行中' },
  CLOSED: { color: 'green', label: '流已关闭' },
  CANCELLED: { color: 'orange', label: '已取消' },
  UNKNOWN: { color: 'default', label: '未知' },
}

/** HTTP 版本展示（UNKNOWN=无法确认，不从 User-Agent 推断） */
export function httpVersionLabel(v?: string | null): string {
  if (v === null || v === undefined || v === '') return '-'
  if (v === 'UNKNOWN') return '未知'
  return `HTTP/${v}`
}

/** HTTP 事件 schema 版本展示（v1=旧采集无来源/协议观测信息） */
export function httpSchemaLabel(v?: number | null): string {
  if (v === 2) return 'v2'
  return 'v1'
}

/** Agent HTTP 事件能力集是否包含 v2（v2 契约 §3；不支持时页面显示「需升级」，不假报启用） */
export function supportsHttpEventV2(schemas?: number[] | null): boolean {
  return Array.isArray(schemas) && schemas.includes(2)
}

/** 采集→入库延迟（秒）；任一缺失返回 null（v1 行无此口径） */
export function ingestionDelaySec(
  collectionTs?: number | null,
  ingestionTs?: number | null,
): number | null {
  if (
    collectionTs === null || collectionTs === undefined ||
    ingestionTs === null || ingestionTs === undefined ||
    !Number.isFinite(collectionTs) || !Number.isFinite(ingestionTs)
  ) {
    return null
  }
  const d = ingestionTs - collectionTs
  return d >= 0 ? d : null
}

/** 缓存补传判定阈值（秒）：采集→入库延迟超过该值视为可能经磁盘缓存补传 */
export const REPLAY_DELAY_THRESHOLD_SEC = 30

/** Unix 秒时间戳 → 本地时间展示，空值/非法值返回占位符 */
export function formatUnixTime(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '-'
  return dayjs.unix(value).format('YYYY-MM-DD HH:mm:ss')
}

/** Unix 秒时间戳 → 相对时间展示（如「5 秒前」），空值/非法值/未来时间返回占位或"刚刚" */
export function formatUnixRelativeTime(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '-'
  const diffSec = dayjs().diff(dayjs.unix(value), 'second')
  if (diffSec < 0) return '刚刚'
  if (diffSec < 60) return `${diffSec} 秒前`
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin} 分钟前`
  const diffHour = Math.floor(diffMin / 60)
  if (diffHour < 24) return `${diffHour} 小时前`
  const diffDay = Math.floor(diffHour / 24)
  if (diffDay < 30) return `${diffDay} 天前`
  return dayjs.unix(value).format('YYYY-MM-DD')
}
