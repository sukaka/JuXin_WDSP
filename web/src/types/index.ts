// 与后端 /api/v1 契约对应的类型定义

/** 统一响应信封 */
export interface ApiEnvelope<T> {
  code: string
  message: string
  data: T
  request_id?: string
  details?: unknown
}

/** 分页数据结构 */
export interface PageResult<T> {
  items: T[]
  page: number
  page_size: number
  total: number
}

export interface RoleRef {
  code: string
  name: string
}

/** 当前登录用户（/auth/login、/auth/me 返回的 user 对象） */
export interface CurrentUser {
  id: string
  username: string
  display_name: string
  status: string
  roles: RoleRef[]
  permissions: string[]
  must_change_password: boolean
  last_login_at?: string | null
  last_login_ip?: string | null
}

export interface LoginResult {
  user: CurrentUser
  csrf_token: string
  password_expiring?: boolean
  password_expires_at?: string | null
}

export type MeResult = LoginResult

export interface CaptchaData {
  enabled: boolean
  captcha_id?: string
  image?: string
  expires_in?: number
}

/** 用户管理列表项 / 个人资料（平铺结构） */
export interface UserItem {
  id: string
  username: string
  display_name: string
  status: string
  must_change_password: boolean
  password_expires_at?: string | null
  locked_until?: string | null
  last_login_at?: string | null
  last_login_ip?: string | null
  roles: RoleRef[]
  created_at: string
  updated_at: string
  version: number
}

export interface ProfileData extends UserItem {
  permissions: string[]
}

export interface SessionItem {
  id: string
  session_hash: string
  source_ip: string
  user_agent_summary: string
  created_at: string
  last_seen_at: string
  expires_at: string
  revoked_at?: string | null
  revoke_reason?: string | null
  is_current: boolean
}

export interface RoleItem {
  id: string
  code: string
  name: string
  description: string
  is_builtin: boolean
}

export interface PermissionItem {
  id: string
  code: string
  name: string
  module: string
  description: string
}

export interface RoleDetail {
  role: RoleItem
  permissions: PermissionItem[]
  user_count: number
}

export interface LoginLogEntry {
  id: string
  occurred_at: string
  username: string
  user_id?: string | null
  source_ip: string
  connection_ip?: string | null
  user_agent_summary?: string | null
  event_type: string
  result: string
  failure_code?: string | null
  request_id?: string | null
}

export interface AuditEntry {
  id: string
  occurred_at: string
  username: string
  source_ip: string
  module: string
  action: string
  object_type?: string | null
  object_id?: string | null
  object_name?: string | null
  before_summary?: unknown
  after_summary?: unknown
  result: string
  failure_reason?: string | null
  risk_level: string
  request_id?: string | null
}

export interface VerifyChainResult {
  valid: boolean
  mismatch_count: number
  mismatch_ids: string[]
}

export interface SettingItem {
  id: string
  setting_group: string
  setting_key: string
  setting_value: string
  value_type: string
  is_sensitive: boolean
  description: string
  updated_at: string
  version: number
}

export interface HealthStatus {
  status: string
  postgres: boolean
  valkey: boolean
}

/* ==================== 阶段3：应用接入 / 源站 / 证书 / 配置发布 ==================== */

/** 防护模式 */
export type ProtectionMode = 'OFF' | 'OBSERVE' | 'PROTECT'

/** 应用状态 */
export type ApplicationStatus = 'DRAFT' | 'ACTIVE' | 'DISABLED' | 'ERROR' | 'DELETED'

/** 部署状态 */
export type DeploymentStatus =
  | 'NOT_PUBLISHED'
  | 'PUBLISHING'
  | 'PUBLISHED'
  | 'PUBLISH_FAILED'
  | 'ROLLING_BACK'
  | 'ROLLBACK_FAILED'

/** Web 应用列表项 */
export interface ApplicationItem {
  id: string
  code: string
  name: string
  description: string
  business_owner: string
  technical_owner: string
  status: ApplicationStatus
  protection_mode: ProtectionMode
  deployment_status: DeploymentStatus
  health_status: string
  current_version_id?: string | null
  last_publish_at?: string | null
  last_publish_result: string
  domain_count: number
  upstream_count: number
  created_at: string
  updated_at: string
  version: number
}

/** 应用详情（含域名与源站） */
export interface ApplicationDetail extends ApplicationItem {
  domains: DomainItem[]
  upstreams: UpstreamItem[]
}

/** 应用域名 */
export interface DomainItem {
  id: string
  application_id: string
  hostname: string
  normalized_hostname: string
  domain_type: 'EXACT' | 'WILDCARD'
  is_primary: boolean
  http_enabled: boolean
  https_enabled: boolean
  http_port?: number | null
  https_port?: number | null
  redirect_http_to_https: boolean
  status: string
  created_at: string
  updated_at: string
}

/** 源站 */
export interface UpstreamItem {
  id: string
  application_id: string
  name: string
  scheme: 'http' | 'https'
  host: string
  normalized_host: string
  port: number
  weight: number
  priority: number
  status: 'ACTIVE' | 'DISABLED'
  health_check_enabled: boolean
  health_check_path: string
  health_check_method: string
  health_check_interval_seconds: number
  health_check_timeout_seconds: number
  expected_status_codes: string
  connect_timeout_ms: number
  response_header_timeout_ms: number
  tls_server_name: string
  tls_verify: boolean
  max_retries: number
  created_at: string
  updated_at: string
  version: number
}

/** 源站连通性测试结果（HTTP 200 返回，成败看 error_code） */
export interface UpstreamTestResult {
  dns_result: '' | 'ok' | 'failed'
  resolved_addresses?: string[] | null
  tcp_connected: boolean
  tls_handshake: boolean
  tls_verify_result: string
  http_status: number
  response_time_ms: number
  error_code: string
  error_message: string
}

/** 证书状态 */
export type CertificateStatus = 'VALID' | 'EXPIRING' | 'EXPIRED' | 'INVALID' | 'KEY_MISMATCH'

/** HTTPS 证书列表项 */
export interface CertificateItem {
  id: string
  name: string
  certificate_type: string
  common_name: string
  subject: string
  issuer: string
  serial_number: string
  not_before?: string | null
  not_after?: string | null
  fingerprint_sha256: string
  public_key_algorithm: string
  public_key_bits: number
  signature_algorithm: string
  san_domains: string[]
  status: CertificateStatus
  usage_count: number
  created_at: string
  updated_at: string
  version: number
}

/** 证书详情（含绑定应用 ID 列表，不含私钥） */
export interface CertificateDetail extends CertificateItem {
  application_ids: string[]
}

/** 业务摘要（preview 响应中为对象；version/diff 中为同结构的 JSON 字符串） */
export interface BusinessSnapshot {
  apps: { code: string; mode: string; domains: number; upstreams: number }[]
}

/** 发布任务 */
export interface PublishTaskItem {
  id: string
  task_type: 'PUBLISH' | 'ROLLBACK'
  status: string
  requested_by?: string | null
  requested_at: string
  started_at?: string | null
  finished_at?: string | null
  target_version_id?: string | null
  current_step: string
  progress: number
  result_summary: string
  failure_code: string
  failure_message: string
  request_id: string
}

/** 配置版本 */
export interface ConfigVersionItem {
  id: string
  version_number: string
  configuration_hash: string
  /** JSON 字符串，内容为 BusinessSnapshot */
  business_snapshot: string
  change_summary: string
  previous_version_id?: string | null
  publish_task_id?: string | null
  publish_result: '' | 'SUCCESS' | 'FAILED' | 'VERIFY_FAILED'
  is_current: boolean
  created_by?: string | null
  created_at: string
  published_at?: string | null
}

/** 网关运行状态 */
export interface GatewayStatusData {
  gateway_up: boolean
  gateway_error: string
  current_version: string
  current_hash: string
  last_publish_result: string
  /** 格式为 "YYYY-MM-DD HH:mm:ss"，无发布记录时为空字符串 */
  last_publish_at: string
  application_count: number
  domain_count: number
  upstream_count: number
}

/* ==================== 阶段4：防护策略 / WAF规则 / 自定义规则 / 例外 / 安全事件 ==================== */

/** 防护策略列表项 */
export interface ProtectionPolicyItem {
  id: string
  code: string
  name: string
  description: string
  is_builtin: boolean
  status: string
  protection_mode: ProtectionMode
  paranoia_level: number
  inbound_anomaly_threshold: number
  outbound_anomaly_threshold: number
  request_body_access: boolean
  response_body_access: boolean
  blocking_status_code: number
  usage_count: number
  created_at: string
  updated_at: string
  version: number
}

/** 防护策略详情（含绑定应用 ID 列表） */
export interface ProtectionPolicyDetail extends ProtectionPolicyItem {
  application_ids: string[]
}

/**
 * WAF 规则（CRS 元数据）。
 * 注意：后端将 jsonb 标签以 []byte 放入 map 序列化，tags 实际为 base64 编码的 JSON 字符串，
 * 需用 utils/stage4.parseWafRuleTags 解码后展示。
 */
export interface WafRuleItem {
  id: string
  rule_id: number
  rule_source: string
  file_name: string
  name: string
  message: string
  severity: string
  phase: number
  tags: string[] | string | null
  attack_type: string
  default_state: string
  crs_version: string
}

/** 规则分类统计项 */
export interface WafRuleCategory {
  attack_type: string
  count: number
}

/** CRS 规则同步报告 */
export interface WafRuleSyncReport {
  total_parsed: number
  total_in_db: number
  added: number
  updated: number
  unchanged: number
  missing: number
  parse_failed: number
  conflicts: number
  failed_rules: string[]
}

/** 自定义规则动作 */
export type CustomRuleAction = 'LOG' | 'OBSERVE' | 'BLOCK'

/** 自定义规则 */
export interface CustomRuleItem {
  id: string
  rule_id: number
  name: string
  description: string
  attack_type: string
  severity: string
  phase: number
  operator: string
  operator_value: string
  target_variables: string[]
  action: CustomRuleAction
  tags: string[]
  status: string
  scope_type: string
  scope_ids: string[]
  generated_rule: string
  version: number
}

/** 自定义规则校验结果 */
export interface CustomRuleValidateResult {
  valid: boolean
  error?: string
  generated_rule?: string
}

/** 例外策略动作 */
export type ExceptionAction =
  | 'REMOVE_RULE'
  | 'REMOVE_RULE_TAG'
  | 'REMOVE_VAR_DETECTION'
  | 'ADJUST_SCORE'
  | 'LOG_ONLY'

/** 例外策略 */
export interface ExceptionItem {
  id: string
  name: string
  description: string
  scope_type: string
  application_id?: string | null
  policy_id?: string | null
  domain: string
  uri_exact: string
  uri_prefix: string
  uri_regex: string
  methods: string[] | null
  source_ips: string[] | null
  param_names: string[] | null
  cookie_names: string[] | null
  header_names: string[] | null
  rule_ids: number[] | null
  rule_tags: string[] | null
  attack_types: string[] | null
  content_types: string[] | null
  exception_action: ExceptionAction
  action_target: string
  is_temporary: boolean
  effective_from?: string | null
  effective_until?: string | null
  status: string
  risk_acknowledged: boolean
  reason: string
  version: number
}

/** 例外策略详情（含宽泛判定） */
export interface ExceptionDetail {
  exception: ExceptionItem
  is_broad: boolean
}

/** 安全事件列表项 */
export interface SecurityEventItem {
  id: string
  request_id: string
  occurred_at: string
  application_id?: string | null
  application_name_snapshot: string
  domain: string
  gateway_node_id: string
  client_ip: string
  client_port: number
  request_method: string
  request_uri: string
  request_path: string
  query_summary: string
  http_version: string
  content_type: string
  user_agent_summary: string
  referer_summary: string
  attack_type: string
  severity: string
  anomaly_score: number
  action: string
  response_status: number
  rule_match_count: number
  disposition_status: string
  disposition_result: string
  raw_log_reference: string
}

/** 事件规则匹配（matched_data 已脱敏，渲染时必须按纯文本转义显示） */
export interface SecurityEventMatch {
  rule_id: number
  rule_name: string
  severity: string
  message: string
  matched_variable: string
  matched_data: string
  tags: string[]
  phase: number
}

/** 事件备注 */
export interface SecurityEventNote {
  username: string
  note: string
  created_at: string
}

/** 事件处置记录 */
export interface SecurityEventActionRecord {
  action_type: string
  operator_name: string
  detail: string
  related_ref_id: string
  created_at: string
}

/** 安全事件详情 */
export interface SecurityEventDetail {
  event: SecurityEventItem
  matches: SecurityEventMatch[] | null
  notes: SecurityEventNote[] | null
  actions: SecurityEventActionRecord[] | null
  related: SecurityEventItem[] | null
}

/** 从事件创建例外草稿的结果 */
export interface CreateExceptionFromEventResult {
  exception_id: string
  message: string
}

/* ==================== 阶段5：访问控制（可信代理 / 保护地址 / IP黑白名单 / CC防护 / 临时封禁 / 访问控制事件） ==================== */

/** 可信代理 */
export interface TrustedProxyItem {
  id: string
  name: string
  cidr: string
  ip_version: 'IPV4' | 'IPV6'
  header_type: 'X_FORWARDED_FOR' | 'X_REAL_IP' | 'FORWARDED' | 'CUSTOM'
  custom_header_name: string
  priority: number
  status: 'ENABLED' | 'DISABLED'
  scope: 'GLOBAL' | 'NODE'
  node_name: string
  description: string
  created_at: string
  updated_at: string
  version: number
}

/** 可信代理详情响应 */
export interface TrustedProxyDetail {
  proxy: TrustedProxyItem
}

/** 命中测试中被命中的库内启用代理 */
export interface TrustedProxyTestMatchedProxy {
  id: string
  name: string
  cidr: string
  scope: string
  node_name: string
}

/** 单个测试 IP 的命中结果 */
export interface TrustedProxyTestIPResult {
  ip: string
  valid: boolean
  matched: boolean
  matched_proxies: TrustedProxyTestMatchedProxy[]
}

/** 可信代理命中测试响应 */
export interface TrustedProxyTestResult {
  cidr: string
  results: TrustedProxyTestIPResult[]
}

/** 保护地址 */
export interface ProtectedAddressItem {
  id: string
  name: string
  address: string
  cidr: string
  address_type:
    | 'GATEWAY'
    | 'MANAGEMENT'
    | 'UPSTREAM'
    | 'DATABASE'
    | 'CACHE'
    | 'TRUSTED_PROXY'
    | 'LOOPBACK'
    | 'LINK_LOCAL'
    | 'CUSTOM'
  source_type: 'SYSTEM' | 'MANUAL'
  description: string
  status: string
  created_at: string
  updated_at: string
}

/** 保护地址详情响应 */
export interface ProtectedAddressDetail {
  address: ProtectedAddressItem
}

/** 保护地址刷新结果 */
export interface ProtectedAddressRefreshResult {
  added: number
  skipped: number
}

/** IP 黑白名单规则 */
export interface AccessRuleItem {
  id: string
  name: string
  rule_type: 'ALLOW' | 'DENY'
  scope_type: 'GLOBAL' | 'APPLICATION'
  application_id?: string | null
  address: string
  ip_version: 'IPV4' | 'IPV6'
  priority: number
  status: 'DRAFT' | 'ACTIVE' | 'DISABLED' | 'EXPIRED' | 'DELETED'
  validity_type: 'PERMANENT' | 'TEMPORARY'
  effective_from?: string | null
  effective_until?: string | null
  reason: string
  source_type: 'MANUAL' | 'SECURITY_EVENT' | 'IMPORT' | 'AUTO_BLOCK' | 'SYSTEM'
  source_event_id?: string | null
  hit_count: number
  last_hit_at?: string | null
  created_at: string
  updated_at: string
  version: number
}

/** IP 黑白名单详情响应 */
export interface AccessRuleDetail {
  rule: AccessRuleItem
}

/** 规则校验结果（不落库） */
export interface AccessRuleValidateResult {
  valid: boolean
  errors: string[]
}

/** 导入行级错误 */
export interface AccessRuleImportRowError {
  line: number
  content: string
  error: string
  code: 'INVALID' | 'PROTECTED' | 'APP_NOT_FOUND' | 'CONFLICT' | string
}

/** 导入预览行 */
export interface AccessRuleImportPreviewRow {
  line: number
  address: string
  rule_type: string
  scope_type: string
  application_id?: string | null
  effective_until?: string | null
  reason: string
}

/** 导入/预览结果 */
export interface AccessRuleImportResult {
  total: number
  valid: number
  invalid: number
  errors: AccessRuleImportRowError[]
  preview?: AccessRuleImportPreviewRow[]
  imported?: number
}

/** CC 防护（限速）策略 */
export interface RateLimitPolicyItem {
  id: string
  name: string
  description: string
  scope_type: 'GLOBAL' | 'APPLICATION' | 'URI'
  application_id?: string | null
  uri_match_type: 'ALL' | 'EXACT' | 'PREFIX' | 'REGEX'
  uri_pattern: string
  dimension: 'CLIENT_IP' | 'APPLICATION' | 'CLIENT_IP_AND_URI' | 'CLIENT_IP_AND_APPLICATION'
  algorithm: 'TOKEN_BUCKET' | 'SLIDING_WINDOW'
  requests_limit: number
  window_seconds: number
  burst_capacity: number
  action: 'LOG' | 'OBSERVE' | 'REJECT' | 'TEMP_BLOCK'
  block_duration_seconds: number
  status: 'ACTIVE' | 'DISABLED'
  observe_only: boolean
  priority: number
  effective_from?: string | null
  effective_until?: string | null
  created_at: string
  updated_at: string
  version: number
}

/** 策略字段级校验错误 */
export interface RateLimitFieldError {
  field: string
  message: string
}

/** 策略校验结果 */
export interface RateLimitValidateResult {
  valid: boolean
  errors: RateLimitFieldError[]
}

/** CC 策略模拟测试结果 */
export interface RateLimitTestResult {
  algorithm: string
  dimension: string
  dimension_note: string
  requests: number
  allowed: number
  rejected: number
  /** 第几个请求被首次拒绝（1起），0 表示无拒绝 */
  first_reject_at: number
  retry_after_seconds: number
}

/** 临时封禁记录 */
export interface TemporaryBlockItem {
  id: string
  client_ip: string
  application_id?: string | null
  trigger_type: 'CC_AUTO' | 'MANUAL'
  trigger_policy_id?: string | null
  trigger_event_ids?: string[] | null
  block_started_at: string
  block_expires_at: string
  status: 'ACTIVE' | 'EXPIRED' | 'MANUALLY_RELEASED' | 'CANCELLED'
  hit_count: number
  release_type?: 'AUTO_EXPIRE' | 'MANUAL' | 'CONVERTED' | ''
  released_at?: string | null
  created_at: string
}

/** 临时封禁详情响应 */
export interface TemporaryBlockDetail {
  block: TemporaryBlockItem
}

/** 转永久封禁结果 */
export interface TemporaryBlockConvertResult {
  rule_id: string
  message: string
}

/** 访问控制事件 */
export interface AccessControlEventItem {
  id: string
  request_id: string
  occurred_at: string
  application_id?: string | null
  application_code: string
  client_ip: string
  connection_ip: string
  domain: string
  request_method: string
  request_path: string
  event_type: string
  action: string
  policy_id?: string | null
  access_rule_id?: string | null
  current_count?: number | null
  limit_value?: number | null
  window_seconds?: number | null
  block_expires_at?: string | null
  response_status?: number | null
  gateway_node_id: string
  message: string
  created_at: string
}

/** 访问控制事件详情响应 */
export interface AccessControlEventDetail {
  event: AccessControlEventItem
}


/* ==================== 阶段6：安全态势 / 统计分析 / 报告 / 监控告警 / 备份恢复 / 升级交付 ==================== */

/** 通用排行键值项（后端 dashboards/analytics KV） */
export interface KeyValue {
  key: string
  value: number
}

/** 源 IP 排行项 */
export interface SourceIPStat {
  ip: string
  events: number
  blocks: number
}

/** URI 排行项 */
export interface URIStat {
  path: string
  events: number
  blocks: number
}

/** 应用排行项 */
export interface AppStat {
  code: string
  name: string
  events: number
}

/** 规则命中排行项 */
export interface RuleStat {
  rule_id: number
  hits: number
  false_positives: number
}

/** 时间点计数（CC/访问控制临时封禁趋势） */
export interface CountPoint {
  time: string
  count: number
}

/** 安全总览-今日指标 */
export interface SecurityOverviewToday {
  requests_total: number
  waf_events: number
  waf_blocks: number
  waf_observes: number
  cc_exceeded: number
  ip_deny_matches: number
  temp_blocked_ips: number
  unprocessed_high_events: number
  protected_apps: number
  abnormal_apps: number
  abnormal_upstreams: number
  expiring_certs: number
}

/** 安全总览-趋势（times 与各序列等长对齐） */
export interface SecurityTrendData {
  start: string
  end: string
  step_seconds: number
  times?: string[] | null
  requests?: number[] | null
  security_events?: number[] | null
  blocks?: number[] | null
  observes?: number[] | null
  cc_exceeded?: number[] | null
  ip_deny?: number[] | null
  risk_levels?: Record<string, number[]> | null
  disposition?: Record<string, number[]> | null
}

/** 安全总览-排行 */
export interface SecurityOverviewTop {
  attack_types?: KeyValue[] | null
  source_ips?: SourceIPStat[] | null
  applications?: KeyValue[] | null
  rules?: KeyValue[] | null
  uris?: URIStat[] | null
}

/** 高危未处置事件摘要 */
export interface RiskEventSummary {
  id: string
  occurred_at: string
  client_ip: string
  application_name: string
  attack_type: string
  severity: string
  request_path: string
  action: string
}

/** 发布失败任务摘要 */
export interface PublishTaskSummary {
  id: string
  task_type: string
  status: string
  requested_at: string
  failure_message: string
}

/** 异常组件（最新快照非 UP） */
export interface ComponentIssue {
  component: string
  status: string
  message: string
  taken_at: string
}

/** 聚合任务最新状态 */
export interface AggregationJobStatus {
  job_type: string
  status: string
  started_at: string
  rows_written: number
}

/** 事件采集延迟与聚合任务状态 */
export interface CollectorLag {
  lag_seconds?: number | null
  measured_at?: string | null
  recent_job_failures: number
  jobs?: AggregationJobStatus[] | null
}

/** 安全总览-风险区 */
export interface SecurityRiskData {
  high_unprocessed_events?: RiskEventSummary[] | null
  failed_publish_tasks?: PublishTaskSummary[] | null
  gateway_issues?: ComponentIssue[] | null
  collector_lag?: CollectorLag | null
}

/** 安全总览响应 */
export interface SecurityOverviewData {
  generated_at: string
  range: string
  today?: SecurityOverviewToday | null
  trends?: SecurityTrendData | null
  top?: SecurityOverviewTop | null
  risks?: SecurityRiskData | null
}

/** 组件健康快照 */
export interface RuntimeComponent {
  component: string
  status: string
  latency_ms?: number | null
  metrics?: Record<string, unknown> | null
  message?: string
  taken_at?: string
}

/** 网关运行状态 */
export interface GatewayRuntime {
  status: string
  uptime_seconds?: number | null
  snapshot_at?: string | null
}

/** 发布统计（近 window_days 天） */
export interface PublishOverviewStats {
  window_days: number
  total: number
  success: number
  failed: number
  success_rate: number
  avg_duration_seconds: number
}

/** 报告任务统计（近 window_days 天） */
export interface ReportOverviewStats {
  window_days: number
  total: number
  success: number
  failed: number
  success_rate: number
}

/** 运行总览-存储用量 */
export interface RuntimeStorageStats {
  pg_database_size_bytes: number
  valkey_used_memory_bytes?: number | null
  valkey_error?: string
  disk_path?: string
  disk_total_bytes?: number | null
  disk_free_bytes?: number | null
  disk_error?: string
}

/** 运行总览响应 */
export interface RuntimeOverviewData {
  generated_at: string
  components?: RuntimeComponent[] | null
  gateway?: GatewayRuntime | null
  publish?: PublishOverviewStats | null
  reports?: ReportOverviewStats | null
  storage?: RuntimeStorageStats | null
}

/** 最近审计摘要 */
export interface AuditSummaryItem {
  id: string
  occurred_at: string
  username: string
  module: string
  action: string
  object_name: string
  result: string
  risk_level: string
}

/** 处置状态分布项 */
export interface StatusCountItem {
  status: string
  count: number
}

/** 操作类型统计项 */
export interface ActionCountItem {
  action: string
  count: number
}

/** 审计态势响应 */
export interface AuditOverviewData {
  generated_at: string
  today_dispositions: number
  unprocessed_events: number
  today_audits: number
  recent_audits?: AuditSummaryItem[] | null
  disposition_distribution?: StatusCountItem[] | null
  action_stats?: ActionCountItem[] | null
}

/** 统计分析-趋势（times 与 series 各序列等长对齐） */
export interface AnalyticsTrendData {
  start: string
  end: string
  granularity: string
  times?: string[] | null
  series?: Record<string, number[]> | null
}

/** 排行/分布响应包装 */
export interface CountList<T = KeyValue> {
  items?: T[] | null
}

/** CC 防护概览 */
export interface CcOverviewData {
  start: string
  end: string
  threshold_exceeded: number
  requests_rejected: number
  temp_blocks_created: number
  temp_blocks_expired: number
  temp_blocks_released: number
  ip_allow_matches: number
  ip_deny_matches: number
  global_rule_events: number
  app_rule_events: number
  invalid_proxy_headers: number
  engine_errors: number
  temp_block_trend?: CountPoint[] | null
}

/** 访问控制规则命中项 */
export interface RuleHitStat {
  rule_id: string
  event_type: string
  hits: number
}

/** 访问控制规则状态分布项 */
export interface RuleStatusStat {
  rule_type: string
  status: string
  count: number
}

/** 访问控制概览 */
export interface AccessControlOverviewData {
  start: string
  end: string
  allow_matches: number
  deny_matches: number
  rule_hits?: RuleHitStat[] | null
  rule_status?: RuleStatusStat[] | null
  active_temp_blocks: number
  temp_block_trend?: CountPoint[] | null
}

/** 处置人统计项 */
export interface HandlerStat {
  username: string
  count: number
}

/** 事件处置统计概览 */
export interface DispositionOverviewData {
  start: string
  end: string
  status_distribution?: StatusCountItem[] | null
  avg_disposition_seconds: number
  handlers?: HandlerStat[] | null
}

/* ---------- 报告 ---------- */

/** 报告类型 */
export type ReportType = 'DAILY' | 'WEEKLY' | 'MONTHLY' | 'CUSTOM'

/** 报告任务状态 */
export type ReportJobStatus =
  | 'PENDING'
  | 'COLLECTING'
  | 'AGGREGATING'
  | 'RENDERING'
  | 'SUCCESS'
  | 'FAILED'
  | 'CANCELLED'

/** 报告任务 */
export interface ReportJobItem {
  id: string
  report_no?: string
  report_type: ReportType
  time_range_start: string
  time_range_end: string
  application_ids?: string[] | null
  template_id?: string | null
  status: ReportJobStatus
  progress: number
  /** 创建人用户 ID（UUID），本人判定与当前用户 id 比对 */
  requested_by?: string | null
  requested_at: string
  started_at?: string | null
  finished_at?: string | null
  file_reference?: string
  file_hash?: string
  file_format: 'html' | 'pdf'
  file_size?: number | null
  failure_code?: string
  failure_message?: string
  request_id?: string
}

/** 报告模板（sections 为章节开关 map） */
export interface ReportTemplateItem {
  id: string
  name: string
  is_builtin: boolean
  company_name: string
  product_name: string
  logo_text: string
  header_text: string
  footer_text: string
  report_no_format: string
  prepared_by: string
  reviewed_by: string
  description: string
  sections: Record<string, boolean> | null
  created_by?: string | null
  created_at: string
  updated_at: string
  version: number
}

/** 报告归档记录（report_archives 表 + 关联报告信息） */
export interface ReportArchiveItem {
  id: string
  report_job_id: string
  report_no?: string
  report_type?: string
  file_format?: string
  file_hash?: string
  file_size?: number | null
  archived_by?: string | null
  archived_at: string
  note?: string
}

/* ---------- 监控与告警 ---------- */

/** 系统健康汇总（GET /system-health） */
export interface SystemHealthData {
  status: string
  status_counts?: Record<string, number> | null
  components?: RuntimeComponent[] | null
  missing_components?: string[] | null
  checked_at?: string
}

/** 存储容量（GET /system-health/storage） */
export interface StorageOverview {
  postgres_size_bytes: number
  db_connections?: number
  partitions?: { name: string; size_bytes: number }[] | null
  valkey_used_memory_bytes: number
  valkey_max_memory_bytes: number
  disk_total_bytes: number
  disk_free_bytes: number
  reports_size_bytes: number
  reports_file_count?: number
  backups_size_bytes: number
  backups_file_count?: number
  collected_at?: string
}

/** 系统告警 */
export interface SystemAlertItem {
  id: string
  alert_type: string
  severity: string
  component: string
  title: string
  message?: string
  status: string
  first_seen_at?: string | null
  last_seen_at?: string | null
  occurrence_count: number
  acknowledged_by?: string | null
  acknowledged_at?: string | null
  resolved_by?: string | null
  resolved_at?: string | null
  resolve_type?: string | null
  created_at: string
}

/** 告警备注 */
export interface SystemAlertNote {
  id?: string
  alert_id?: string
  note: string
  created_by?: string | null
  username: string
  created_at: string
}

/** 告警详情（含备注时间线） */
export interface SystemAlertDetail {
  alert: SystemAlertItem
  notes?: SystemAlertNote[] | null
}

/* ---------- 备份与恢复 ---------- */

/** 备份任务 */
export interface BackupJobItem {
  id: string
  backup_type: 'FULL' | 'CONFIG_ONLY'
  status: string
  include_logs?: boolean
  file_reference?: string
  file_size?: number | null
  file_hash?: string
  requested_by?: string | null
  requested_at: string
  started_at?: string | null
  finished_at?: string | null
  /** 完整性验证结果（手动/自动验证通过后置真） */
  verified: boolean
  verified_at?: string | null
  failure_code?: string
  failure_message?: string
  request_id?: string
}

/** 备份验证结果摘要 */
export interface BackupVerifyResult {
  manifest?: unknown
  checked_at?: string
  tables_ok?: number
  total_rows?: number
  file_intact?: boolean
}

/** 恢复预览-表级项 */
export interface RestoreTablePreview {
  name: string
  group: string
  backup_rows: number
  restored_rows?: number
  match: boolean
  in_scope: boolean
}

/** 恢复校验预览 */
export interface RestorePreviewData {
  backup_id: string
  backup_type: string
  scope?: string
  backup_time?: string | null
  schema_version?: number
  current_schema_version?: number
  compatible: boolean
  tables?: RestoreTablePreview[] | null
  total_rows: number
  note?: string
}

/** 恢复任务 */
export interface RestoreJobItem {
  id: string
  backup_job_id?: string | null
  restore_scope: string
  status: string
  preview?: unknown
  confirmed_by?: string | null
  confirmed_at?: string | null
  requested_by?: string | null
  requested_at: string
  started_at?: string | null
  finished_at?: string | null
  failure_code?: string
  failure_message?: string
  request_id?: string
}

/* ---------- 升级与交付（后端并行开发中，按任务书契约定义） ---------- */

/** 升级包 */
export interface UpgradePackageItem {
  id: string
  file_name: string
  version_from: string
  version_to: string
  file_hash: string
  file_size: number
  status?: string
  created_at: string
}

/** 升级预检单项 */
export interface UpgradePrecheckItem {
  name: string
  result: 'PASS' | 'WARNING' | 'FAIL'
  critical?: boolean
  message?: string
}

/** 升级预检结果 */
export interface UpgradePrecheckResult {
  package_id?: string
  overall_result: string
  items?: UpgradePrecheckItem[] | null
}

/** 升级任务 */
export interface UpgradeJobItem {
  id: string
  package_id: string
  version_from?: string
  version_to?: string
  status: string
  current_step?: string
  progress?: number
  failure_code?: string
  failure_message?: string
  requested_by?: string | null
  started_at?: string | null
  finished_at?: string | null
  created_at: string
  request_id?: string
}

/** 交付检查结果项 */
export interface DeliveryCheckResultItem {
  item: string
  category?: string
  result: 'PASS' | 'WARNING' | 'FAIL' | 'NOT_APPLICABLE'
  critical?: boolean
  message?: string
}

/** 交付检查任务 */
export interface DeliveryCheckItem {
  id: string
  status: string
  overall_result?: string
  pass_count?: number
  warning_count?: number
  fail_count?: number
  total_count?: number
  triggered_by?: string | null
  started_at?: string | null
  finished_at?: string | null
  created_at: string
}

/** 交付检查详情（含逐项结果） */
export interface DeliveryCheckDetail {
  check: DeliveryCheckItem
  results?: DeliveryCheckResultItem[] | null
}
