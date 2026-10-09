/* ==================== 阶段6：态势/报告/监控告警/备份恢复/升级交付 展示元数据与判定工具 ==================== */

/** 趋势快捷时间范围 */
export const TREND_RANGE_OPTIONS: { value: string; label: string }[] = [
  { value: '1h', label: '最近1小时' },
  { value: '24h', label: '最近24小时' },
  { value: '7d', label: '最近7天' },
  { value: '30d', label: '最近30天' },
]

/** 检索类快捷时间范围（APM 调用链/SQL/异常/依赖/运行时）：后端原始表扫描限窗 ≤24 小时
 * （server/internal/apm/handler.go parseSearchWindow），不提供 7d/30d 档位 */
export const SEARCH_RANGE_OPTIONS: { value: string; label: string }[] = TREND_RANGE_OPTIONS.slice(0, 2)

/** 报告类型 */
export const REPORT_TYPE_META: Record<string, { color: string; label: string }> = {
  DAILY: { color: 'blue', label: '日报' },
  WEEKLY: { color: 'geekblue', label: '周报' },
  MONTHLY: { color: 'purple', label: '月报' },
  CUSTOM: { color: 'orange', label: '自定义' },
}

/** 报告内容范围 */
export const CONTENT_SCOPE_META: Record<string, { color: string; label: string }> = {
  WAF_API: { color: 'green', label: 'Web + API' },
  WAF: { color: 'blue', label: '仅 Web 防护' },
  API: { color: 'magenta', label: '仅 API 防护' },
}

/** 报告任务状态 */
export const REPORT_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '排队中' },
  COLLECTING: { color: 'blue', label: '数据采集中' },
  AGGREGATING: { color: 'geekblue', label: '数据聚合中' },
  RENDERING: { color: 'cyan', label: '报告渲染中' },
  SUCCESS: { color: 'green', label: '生成成功' },
  FAILED: { color: 'red', label: '生成失败' },
  CANCELLED: { color: 'default', label: '已取消' },
}

/** 报告格式 */
export const REPORT_FORMAT_META: Record<string, { color: string; label: string }> = {
  html: { color: 'blue', label: '网页' },
  pdf: { color: 'red', label: 'PDF 文档' },
  docx: { color: 'geekblue', label: 'Word 文档' },
}

/** 报告模板可开关章节（与报告结构对应，key 为后端约定标识） */
export const REPORT_SECTION_OPTIONS: { value: string; label: string }[] = [
  { value: 'summary', label: '管理摘要' },
  { value: 'traffic', label: '请求流量' },
  { value: 'security_events', label: '安全事件总览' },
  { value: 'risk_levels', label: '风险等级' },
  { value: 'attack_types', label: '攻击类型' },
  { value: 'source_ips', label: '攻击源IP' },
  { value: 'applications', label: '被攻击应用' },
  { value: 'rules', label: '命中规则' },
  { value: 'cc', label: '频率与 CC 防护' },
  { value: 'access_control', label: '黑白名单' },
  { value: 'disposition', label: '事件处置' },
  { value: 'upstreams', label: '源站健康' },
  { value: 'certificates', label: '证书状态' },
  { value: 'runtime', label: '系统运行' },
  { value: 'conclusion', label: '结论和建议' },
]

/** 系统告警等级 */
export const ALERT_SEVERITY_META: Record<string, { color: string; label: string }> = {
  CRITICAL: { color: 'red', label: '严重' },
  HIGH: { color: 'volcano', label: '高危' },
  MEDIUM: { color: 'orange', label: '中危' },
  LOW: { color: 'gold', label: '低危' },
  INFO: { color: 'blue', label: '提示' },
}

/** 系统告警状态 */
export const ALERT_STATUS_META: Record<string, { color: string; label: string }> = {
  OPEN: { color: 'red', label: '未处理' },
  ACKNOWLEDGED: { color: 'orange', label: '已确认' },
  RESOLVED: { color: 'green', label: '已解决' },
  IGNORED: { color: 'default', label: '已忽略' },
}

/** 系统告警类型 */
export const ALERT_TYPE_META: Record<string, { color: string; label: string }> = {
  GATEWAY_DOWN: { color: 'red', label: '网关不可用' },
  MANAGEMENT_API_DOWN: { color: 'red', label: '管理 API 不可用' },
  DATABASE_UNAVAILABLE: { color: 'red', label: '数据库不可用' },
  VALKEY_UNAVAILABLE: { color: 'red', label: '缓存服务不可用' },
  EVENT_COLLECTOR_LAG: { color: 'orange', label: '事件采集积压' },
  EVENT_PARSE_FAILURE_RATE_HIGH: { color: 'orange', label: '事件解析失败率高' },
  SOURCE_UNHEALTHY: { color: 'volcano', label: '源站不健康' },
  CERTIFICATE_EXPIRING: { color: 'gold', label: '证书即将到期' },
  CERTIFICATE_EXPIRED: { color: 'red', label: '证书已过期' },
  CONFIG_PUBLISH_FAILED: { color: 'volcano', label: '配置发布失败' },
  CONFIG_HASH_MISMATCH: { color: 'orange', label: '配置哈希不一致' },
  DISK_SPACE_LOW: { color: 'orange', label: '磁盘空间不足' },
  DATABASE_CAPACITY_HIGH: { color: 'orange', label: '数据库容量高' },
  FD_USAGE_HIGH: { color: 'orange', label: '文件句柄使用率高' },
  BACKUP_FAILED: { color: 'volcano', label: '备份失败' },
  RESTORE_VALIDATION_FAILED: { color: 'volcano', label: '恢复校验失败' },
  REPORT_FAILED: { color: 'orange', label: '报告生成失败' },
  UPGRADE_FAILED: { color: 'red', label: '升级失败' },
  AUDIT_INTEGRITY_FAILED: { color: 'red', label: '审计完整性失败' },
}

/** 监控组件展示名 */
export const COMPONENT_NAME_META: Record<string, string> = {
  GATEWAY: '防护网关',
  CORAZA: 'WAF 引擎',
  GUARD: '访问控制模块',
  API: '管理 API',
  POSTGRES: '数据库',
  VALKEY: '缓存服务',
  EVENT_COLLECTOR: '事件采集器',
  UPSTREAM: '源站',
  CERTIFICATE: '证书',
  DISK: '磁盘',
}

/** 组件健康状态（与后端 runtimehealth 状态枚举一致） */
export const COMPONENT_STATUS_META: Record<string, { color: string; label: string }> = {
  UP: { color: 'green', label: '正常' },
  DEGRADED: { color: 'orange', label: '降级' },
  DOWN: { color: 'red', label: '故障' },
  UNKNOWN: { color: 'default', label: '未知' },
}

/** 备份类型 */
export const BACKUP_TYPE_META: Record<string, { color: string; label: string }> = {
  FULL: { color: 'purple', label: '全量备份' },
  CONFIG_ONLY: { color: 'blue', label: '配置备份' },
}

/** 备份任务状态 */
export const BACKUP_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '排队中' },
  RUNNING: { color: 'blue', label: '备份中' },
  VERIFYING: { color: 'cyan', label: '校验中' },
  SUCCESS: { color: 'green', label: '备份成功' },
  FAILED: { color: 'red', label: '备份失败' },
  CANCELLED: { color: 'default', label: '已取消' },
}

/** 备份验证状态 */
export const BACKUP_VERIFY_STATUS_META: Record<string, { color: string; label: string }> = {
  UNVERIFIED: { color: 'default', label: '未验证' },
  PASSED: { color: 'green', label: '验证通过' },
  FAILED: { color: 'red', label: '验证失败' },
}

/** 恢复范围 */
export const RESTORE_SCOPE_META: Record<string, { color: string; label: string }> = {
  FULL: { color: 'purple', label: '全系统恢复' },
  CONFIG: { color: 'blue', label: '配置恢复' },
  DATABASE: { color: 'geekblue', label: '数据库恢复' },
  CERTIFICATE: { color: 'cyan', label: '证书恢复' },
}

/** 恢复任务状态（与后端 restores 状态机一致） */
export const RESTORE_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '排队中' },
  VALIDATING: { color: 'blue', label: '备份校验中' },
  ISOLATED_RESTORE: { color: 'geekblue', label: '隔离恢复中' },
  VERIFYING: { color: 'cyan', label: '完整性校验中' },
  AWAITING_CONFIRM: { color: 'gold', label: '待确认' },
  RESTORING: { color: 'blue', label: '正式恢复中' },
  SUCCESS: { color: 'green', label: '恢复成功' },
  FAILED: { color: 'red', label: '恢复失败' },
  CANCELLED: { color: 'default', label: '已取消' },
}

/** 升级任务状态（与后端 upgrades 状态机一致） */
export const UPGRADE_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '排队中' },
  SCHEDULED: { color: 'blue', label: '定时中' },
  PRECHECK: { color: 'blue', label: '升级前检查' },
  BACKUP: { color: 'cyan', label: '升级前备份' },
  APPLYING: { color: 'geekblue', label: '应用升级' },
  MIGRATING: { color: 'geekblue', label: '数据库迁移' },
  VERIFYING: { color: 'gold', label: '升级后验证' },
  RUNNING: { color: 'blue', label: '升级中' },
  SUCCESS: { color: 'green', label: '升级成功' },
  FAILED: { color: 'red', label: '升级失败' },
  ROLLING_BACK: { color: 'orange', label: '回滚中' },
  ROLLED_BACK: { color: 'orange', label: '已回滚' },
  CANCELLED: { color: 'default', label: '已取消' },
}

/** 升级包状态 */
export const UPGRADE_PACKAGE_STATUS_META: Record<string, { color: string; label: string }> = {
  REGISTERED: { color: 'default', label: '已登记' },
  VERIFIED: { color: 'green', label: '校验通过' },
  REJECTED: { color: 'red', label: '校验未通过' },
}

/** 预检/交付检查结果 */
export const CHECK_RESULT_META: Record<string, { color: string; label: string }> = {
  PASS: { color: 'green', label: '通过' },
  WARNING: { color: 'orange', label: '警告' },
  FAIL: { color: 'red', label: '失败' },
  NOT_APPLICABLE: { color: 'default', label: '不适用' },
}

/** 风险提示等级（复用告警等级配色语义） */
export const RISK_SEVERITY_META = ALERT_SEVERITY_META

/** 报告任务是否终态（终态停止轮询） */
export function isTerminalReportStatus(status: string): boolean {
  return status === 'SUCCESS' || status === 'FAILED' || status === 'CANCELLED'
}

/** 备份任务是否终态 */
export function isTerminalBackupStatus(status: string): boolean {
  return status === 'SUCCESS' || status === 'FAILED' || status === 'CANCELLED'
}

/** 恢复任务是否终态 */
export function isTerminalRestoreStatus(status: string): boolean {
  return status === 'SUCCESS' || status === 'FAILED' || status === 'CANCELLED'
}

/** 升级任务是否终态（SCHEDULED 定时中为非终态，到点后转为执行态，需继续轮询） */
export function isTerminalUpgradeStatus(status: string): boolean {
  return status === 'SUCCESS' || status === 'FAILED' || status === 'ROLLED_BACK' || status === 'CANCELLED'
}

/** 汇总预检/检查项整体结果：任一 FAIL → FAIL，否则任一 WARNING → WARNING，全 PASS → PASS */
export function summarizeCheckResult(items: { result: string }[]): string {
  if (items.some((i) => i.result === 'FAIL')) return 'FAIL'
  if (items.some((i) => i.result === 'WARNING')) return 'WARNING'
  return 'PASS'
}

/** 交付检查任务是否终态 */
export function isTerminalDeliveryStatus(status: string): boolean {
  return status === 'SUCCESS' || status === 'FAILED' || status === 'COMPLETED'
}

/** 运行时长人性化展示（秒数或后端字符串原样展示） */
export function formatUptime(uptime?: string | number | null): string {
  if (uptime === null || uptime === undefined || uptime === '') return '-'
  if (typeof uptime === 'string') return uptime
  if (!Number.isFinite(uptime) || uptime < 0) return '-'
  const days = Math.floor(uptime / 86400)
  const hours = Math.floor((uptime % 86400) / 3600)
  const minutes = Math.floor((uptime % 3600) / 60)
  if (days > 0) return `${days} 天 ${hours} 小时`
  if (hours > 0) return `${hours} 小时 ${minutes} 分钟`
  return `${minutes} 分钟`
}
