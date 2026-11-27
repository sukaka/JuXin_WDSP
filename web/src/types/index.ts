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
  /** 是否已开启双因子认证（TOTP）；缺省按未开启处理 */
  totp_enabled?: boolean
  last_login_at?: string | null
  last_login_ip?: string | null
}

export interface LoginResult {
  user: CurrentUser
  csrf_token: string
  password_expiring?: boolean
  password_expires_at?: string | null
}

/** 登录第二步挑战（密码校验通过且已开启双因子时 /auth/login 返回） */
export interface TotpChallenge {
  challenge_token: string
}

/** /auth/login 响应：密码直接通过，或进入双因子第二步验证 */
export type LoginResponse =
  | { code: 'SUCCESS'; data: LoginResult }
  | { code: 'TOTP_REQUIRED'; data: TotpChallenge }

/** TOTP 自助开启返回的密钥与恢复码（明文仅本次响应可见，需立即保存） */
export interface TotpSetupData {
  secret: string
  otpauth_url: string
  recovery_codes: string[]
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
  /** 是否已开启双因子认证（TOTP） */
  totp_enabled?: boolean
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
  /** 权限码对应的中文名称与模块（服务端随资料返回） */
  permission_details?: { code: string; name: string; module: string }[]
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
  setting_value: string | number | boolean
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

/** APM 性能监控设置（GET /apm/settings）；DSN 原文任何情况下不下发，仅用 clickhouse_dsn_set 标记 */
export interface ApmSettings {
  enabled: boolean
  enabled_source: 'ui' | 'env'
  clickhouse_dsn_set: boolean
  clickhouse_dsn_source: 'ui' | 'env' | ''
  ch_connected: boolean
}

/* ==================== 阶段3：应用接入 / 源站 / 证书 / 配置发布 ==================== */

/** 防护模式（BYPASS 为数据透传：跳过全部检测，仅用于排障/应急） */
export type ProtectionMode = 'OFF' | 'OBSERVE' | 'PROTECT' | 'BYPASS'

/** 应用状态 */
export type ApplicationStatus =
  'DRAFT' | 'ACTIVE' | 'DISABLED' | 'ERROR' | 'DELETED'

/**
 * 部署模式（REVERSE_PROXY 反向代理为默认；ROUTED 路由牵引 / MIRROR 镜像旁路 / TRANSPARENT 透明串接，
 * 见 docs/NETWORK_MODES_DESIGN.md §4）
 */
export type DeploymentMode =
  'REVERSE_PROXY' | 'ROUTED' | 'MIRROR' | 'TRANSPARENT'

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
  /** 缺省按 REVERSE_PROXY（反向代理）处理 */
  deployment_mode?: DeploymentMode
  deployment_status: DeploymentStatus
  health_status: string
  current_version_id?: string | null
  last_publish_at?: string | null
  last_publish_result: string
  /** 主活动域名（按 is_primary 优先、最早创建次之；无活动域名时为空串） */
  primary_domain?: string
  domain_count: number
  upstream_count: number
  /** API 准入模式（docs/API_ADMISSION_CONTROL_DESIGN.md §3.1；缺省按 OFF 处理） */
  api_admission_mode?: ApiAdmissionMode
  /** 自动 SSL 站点开关与运行态摘要 */
  auto_ssl_enabled?: boolean
  auto_ssl_challenge_type?: string
  auto_ssl_renew_before_days?: number | null
  auto_ssl_last_status?: string
  auto_ssl_last_error?: string
  auto_ssl_fail_count?: number
  auto_ssl_next_retry_at?: string | null
  auto_ssl_last_attempt_at?: string | null
  created_at: string
  updated_at: string
  version: number
}

/** 应用级默认绑定的防护策略摘要 */
export interface ApplicationProtectionPolicySummary {
  id: string
  code: string
  name: string
  protection_mode: ProtectionMode
  paranoia_level: number
}

/** 应用详情（含域名与源站） */
export interface ApplicationDetail extends ApplicationItem {
  domains: DomainItem[]
  upstreams: UpstreamItem[]
  /** 应用级默认绑定的防护策略（未绑定时为 null） */
  protection_policy?: ApplicationProtectionPolicySummary | null
}

/* ==================== API 准入防护（docs/API_ADMISSION_CONTROL_DESIGN.md §5） ==================== */

/** API 准入模式（应用级）：OFF 不判定 / OBSERVE 只观测 / PROTECT 未确认即 403 */
export type ApiAdmissionMode = 'OFF' | 'OBSERVE' | 'PROTECT'

/** 窗口内仍有命中的未确认端点（覆盖率报告 unconfirmed_hot 元素；无 id，按 endpoint_key 关联资产） */
export interface ApiAdmissionHotEndpoint {
  endpoint_key: string
  http_method: string
  normalized_path: string
  asset_status: string
  hits: number
  last_seen_at?: string | null
}

/** API 准入覆盖率报告（GET /api-security/admission/coverage） */
export interface ApiAdmissionCoverage {
  application_id: string
  mode: ApiAdmissionMode
  hits_window_hours: number
  /** 各生命周期状态端点计数 */
  endpoints: {
    confirmed: number
    discovered: number
    ignored: number
    deprecated: number
    zombie: number
  }
  /** confirmed / (confirmed + discovered) */
  confirm_rate: number
  /** 窗口内仍有命中的未确认端点（按命中降序，切 PROTECT 会被拒绝） */
  unconfirmed_hot: ApiAdmissionHotEndpoint[]
  /** 窗口内 PROTECT 准入拦截次数（OBSERVE 期为 0） */
  blocked: number
}

/** 准入拦截列表项（GET /api-security/admission/denied 的 items 元素；无 id，按 endpoint_key 关联资产） */
export interface ApiAdmissionDeniedItem {
  endpoint_key: string
  http_method: string
  normalized_path: string
  asset_status: string
  denied_count: number
  last_denied_at?: string | null
  /** 样本客户端 IP（服务端可能返回 null，api 层归一化为空数组） */
  sample_client_ips: string[]
  first_seen_at?: string | null
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
  /** 域名级绑定的防护策略 ID（null/空表示继承应用级策略） */
  policy_id?: string | null
  policy_code?: string
  policy_name?: string
  policy_mode?: ProtectionMode | string
  status: string
  created_at: string
  updated_at: string
}

/** 源站实时健康状态 */
export type UpstreamHealthStatus = 'HEALTHY' | 'UNHEALTHY' | 'UNKNOWN' | 'DISABLED'

/** 源站 */
export interface UpstreamItem {
  id: string
  application_id: string
  name: string
  scheme: 'http' | 'https' | 'h2c' | 'tlcp'
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
  /** 实时健康状态（只读，来自最近一次健康探测记录） */
  health_status?: UpstreamHealthStatus | string
  /** 最近一次健康探测时间 */
  last_health_check_at?: string | null
  /** 最近一次健康探测返回的 HTTP 状态码 */
  last_response_status?: number | null
  /** 最近一次健康探测耗时（毫秒） */
  last_response_time_ms?: number | null
  /** 最近一次健康探测失败错误码 */
  last_health_error_code?: string
  /** 最近一次健康探测失败详情 */
  last_health_error?: string
  /** 连续健康次数 */
  consecutive_successes?: number
  /** 连续失败次数 */
  consecutive_failures?: number
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
export type CertificateStatus =
  'VALID' | 'EXPIRING' | 'EXPIRED' | 'INVALID' | 'KEY_MISMATCH' | 'REPLACED'

export type CertificateManagedBy = 'MANUAL' | 'ACME'
export type AcmeProvider = 'LETSENCRYPT' | 'LETSENCRYPT_STAGING' | 'CUSTOM'
export type AcmeKeyType = 'EC256' | 'EC384' | 'RSA2048'
export type AcmeTriggerType =
  | 'AUTO_INIT'
  | 'AUTO_RENEW'
  | 'AUTO_DOMAIN_SYNC'
  | 'MANUAL_ISSUE'
  | 'MANUAL_RENEW'
export type AcmeOrderStatus =
  | 'PENDING'
  | 'PREPARING'
  | 'VALIDATING'
  | 'FINALIZING'
  | 'ISSUED'
  | 'PUBLISHING'
  | 'SUCCEEDED'
  | 'PUBLISH_FAILED'
  | 'FAILED'

/** 证书协议类型：国际通用单证 / 国密 SM2 双证（TLCP 1.1） */
export type CertificateProtocolType = 'INTERNATIONAL' | 'SM_TLCP'

/** HTTPS 证书列表项 */
export interface CertificateItem {
  id: string
  name: string
  certificate_type: string
  protocol_type?: CertificateProtocolType
  common_name: string
  subject: string
  issuer: string
  serial_number: string
  not_before?: string | null
  not_after?: string | null
  effective_not_after?: string | null
  fingerprint_sha256: string
  public_key_algorithm: string
  public_key_bits: number
  signature_algorithm: string
  san_domains: string[]
  /** 国密加密证书元数据（SM_TLCP 专用） */
  enc_common_name?: string
  enc_subject?: string
  enc_issuer?: string
  enc_serial_number?: string
  enc_not_before?: string | null
  enc_not_after?: string | null
  enc_fingerprint_sha256?: string
  status: CertificateStatus
  usage_count: number
  managed_by?: CertificateManagedBy
  acme_provider?: string
  acme_directory_url?: string
  auto_renew?: boolean
  renew_before_days?: number
  replaces_certificate_id?: string | null
  superseded_by?: string | null
  last_renewed_at?: string | null
  created_at: string
  updated_at: string
  version: number
}

/** 应用双槽位证书绑定视图 */
export interface ApplicationCertificateBindings {
  international: CertificateItem | null
  gm: CertificateItem | null
}

/** GET /applications/{id}/certificate 返回体（兼容旧 certificate 字段并附带双槽位） */
export interface ApplicationCertificatesResult {
  certificate: CertificateItem | null
  gm_certificate?: CertificateItem | null
  bindings?: ApplicationCertificateBindings
}

/** 证书详情（含绑定应用 ID 列表，不含私钥） */
export interface CertificateDetail extends CertificateItem {
  application_ids: string[]
}

/** 全局 ACME 自动证书配置（不含 EAB HMAC 明文） */
export interface AcmeConfig {
  enabled: boolean
  provider: AcmeProvider
  directory_url: string
  effective_directory_url: string
  custom_directory_allowlist: string
  email: string
  tos_agreed: boolean
  eab_kid: string
  eab_hmac_configured: boolean
  key_type: AcmeKeyType
  renew_before_days: number
  auto_publish: boolean
  updated_at?: string
  version: number
}

export interface AcmeTestResult {
  reachable: boolean
  directory_url: string
  latency_ms: number
  authz_url?: string
  order_url?: string
  external_account_required: boolean
  message: string
}

export interface AcmeOrderItem {
  id: string
  application_id: string
  app_code?: string
  app_name?: string
  trigger_type: AcmeTriggerType
  provider: string
  directory_url: string
  challenge_type: string
  domains: string[]
  status: AcmeOrderStatus
  certificate_id?: string | null
  previous_certificate_id?: string | null
  publish_task_id?: string | null
  error_code: string
  error_message: string
  request_id: string
  started_at?: string | null
  finished_at?: string | null
  created_at: string
  updated_at: string
}

export interface AppAutoSslWarning {
  code: string
  level: 'error' | 'warning' | 'info'
  message: string
}

export interface AppAutoSslStatus {
  application_id: string
  enabled: boolean
  challenge_type: string
  renew_before_days: number | null
  effective_renew_before_days: number
  global_acme_enabled: boolean
  global_provider: string
  auto_publish: boolean
  https_domains: string[]
  last_status: string
  last_error: string
  fail_count: number
  next_retry_at?: string | null
  last_attempt_at?: string | null
  has_active_order: boolean
  latest_order?: AcmeOrderItem | null
  ready: boolean
  warnings: AppAutoSslWarning[]
}

/** 业务摘要（preview 响应中为对象；version/diff 中为同结构的 JSON 字符串） */
export interface BusinessSnapshot {
  apps: {
    code: string
    mode: string
    deployment_mode?: DeploymentMode | string
    domains: number
    upstreams: number
  }[]
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
  /** 发布后流量验证结果（阶段5 §十七；'' = 历史版本未执行冒烟） */
  validation_result?: '' | 'SMOKE_PASS' | 'SMOKE_FAIL' | 'SMOKE_SKIPPED'
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
  domain_usage_count?: number
  created_at: string
  updated_at: string
  version: number
}

/** 防护策略绑定的域名摘要 */
export interface ProtectionPolicyBoundDomain {
  id: string
  application_id: string
  application_code: string
  application_name: string
  hostname: string
}

/** 防护策略详情（含绑定应用 ID 与域名列表） */
export interface ProtectionPolicyDetail extends ProtectionPolicyItem {
  application_ids: string[] | null
  domains?: ProtectionPolicyBoundDomain[] | null
}

/** 防护策略生效规则统计摘要 */
export interface ProtectionPolicyContentSummary {
  total_rules: number
  active_rules: number
  disabled_by_override: number
  skipped_by_pl: number
  mode_off_rules: number
  custom_rules_count: number
  global_exceptions_count: number
  overrides_count: number
}

/** 防护策略关联的规则覆盖项 */
export interface ProtectionPolicyOverrideItem {
  id: string
  rule_id: number
  scope_type: string
  action: string
  reason: string
  effective_active: boolean
}

/** 防护策略生效的自定义规则项 */
export interface ProtectionPolicyCustomRuleItem {
  rule_id: number
  name: string
  attack_type: string
  severity: string
  phase: number
  action: string
  generated_rule: string
}

/** 防护策略生效的全局 WAF 例外项 */
export interface ProtectionPolicyExceptionItem {
  exception_id: string
  rule_id: number
  scope_type: string
  exception_version: number
  seclang: string
}

/** 防护策略下规则库单条规则的生效视图 */
export interface ProtectionPolicyEffectiveRuleItem {
  rule_id: number
  name: string
  attack_type: string
  severity: string
  phase: number
  rule_source: string
  file_name: string
  paranoia_level: number
  effective_status: 'ACTIVE' | 'DISABLED_BY_OVERRIDE' | 'SKIPPED_BY_PL' | 'MODE_OFF' | string
  raw_rule: string
}

/** 防护策略加载的规则文件顺序阶段 */
export interface ProtectionPolicyRuleFileStage {
  order: number
  path: string
  description: string
}

/** 防护策略实际生效内容响应（GET /protection-policies/{id}/content） */
export interface ProtectionPolicyContent {
  policy_id: string
  policy_code: string
  policy_name: string
  protection_mode: string
  sec_rule_engine: string
  paranoia_level: number
  inbound_anomaly_threshold: number
  outbound_anomaly_threshold: number
  generated_directives: string
  loaded_rule_files: ProtectionPolicyRuleFileStage[]
  summary: ProtectionPolicyContentSummary
  overrides: ProtectionPolicyOverrideItem[]
  custom_rules: ProtectionPolicyCustomRuleItem[]
  global_exceptions: ProtectionPolicyExceptionItem[]
  rules: ProtectionPolicyEffectiveRuleItem[]
  rules_total: number
  page: number
  page_size: number
}

/** WAF 规则功能类别 */
export type WafRuleType =
  | 'DETECTION'
  | 'OBSERVE'
  | 'BLOCKING_EVALUATION'
  | 'EXCLUSION'
  | 'PREPROCESSING'
  | 'INTERNAL'

/** WAF 规则说明来源：人工维护 / 内置规则库 / 规则文件自动解析 / 元数据自动生成 */
export type WafRuleDetailSource = 'CUSTOM' | 'BUILTIN' | 'PARSED' | 'AUTO'

/** 管理员维护的规则中文说明覆盖记录 */
export interface WafRuleDescriptionOverride {
  summary: string
  detection_logic: string
  risk_impact: string
  tuning_advice: string
  updated_by_name?: string
  updated_at?: string | null
}

/** 管理员编辑规则中文说明请求体（留空字段自动沿用系统默认说明） */
export interface WafRuleDescriptionPayload {
  summary?: string
  detection_logic?: string
  risk_impact?: string
  tuning_advice?: string
}

/** WAF 规则结构化中文详细说明（GET /waf-rules/{rule_id} 返回） */
export interface WafRuleDetailInfo {
  rule_type: WafRuleType | string
  rule_type_label: string
  source?: WafRuleDetailSource | string
  source_label?: string
  customized?: boolean
  summary: string
  detection_logic: string
  risk_impact: string
  tuning_advice: string
  phase_description: string
  paranoia_level: string
  action_behavior: string
  targets: string[]
  references: string[]
  custom_fields?: WafRuleDescriptionOverride | null
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
  /** 规则中文详细说明摘要 */
  description?: string
  /** 结构化中文规则详细说明（详情接口返回） */
  detail?: WafRuleDetailInfo
  /** 底层原始 SecLang 规则原文（含正则表达式与链式子规则，详情接口返回） */
  raw_rule?: string
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
  /** CNNVD 编号数组（CNNVD 兼容性 P1，缺省 []） */
  cnnvd_ids: string[]
  /** CVE 编号数组（CNNVD 兼容性 P1，缺省 []） */
  cve_ids: string[]
  status: string
  scope_type: string
  scope_ids: string[]
  generated_rule: string
  version: number
}

/** 漏洞档案基础条目（POST /waf/vuln-refs 返回，不含交叉计数） */
export interface VulnRef {
  id: string
  cnnvd_id: string
  cve_id: string
  title: string
  severity: string
  published_at: string | null
  /** CNNVD 官方条目链接（可空） */
  url: string
  created_at: string
  updated_at: string
}

/** 漏洞档案条目（CNNVD 兼容性 P1，vuln_refs 表，含交叉计数） */
export interface VulnRefItem extends VulnRef {
  rule_count: number
  event_count_30d: number
}

/** 漏洞档案关联规则（交叉查询：编号 → 规则） */
export interface VulnRefRule {
  rule_id: number
  rule_source: string
  rule_name: string
  description: string
  enabled: boolean
}

/** 漏洞档案样例事件（近 30 天命中样例） */
export interface VulnRefSampleEvent {
  id: string
  occurred_at: string
  attack_type: string
  client_ip: string
  request_path: string
  action: string
}

/** 漏洞档案详情（GET /waf/vuln-refs/{cnnvd_id}：条目 + 关联规则 + 近 30 天事件） */
export interface VulnRefDetail {
  ref: VulnRefItem
  rules: VulnRefRule[] | null
  event_count_30d: number
  sample_events: VulnRefSampleEvent[] | null
}

/** 自定义规则校验结果 */
export interface CustomRuleValidateResult {
  valid: boolean
  error?: string
  generated_rule?: string
}

/**
 * 例外策略动作（P0-04 动作矩阵，S4 §3）：
 * WAF 引擎新启用仅允许 REMOVE_RULE / REMOVE_RULE_TAG / REMOVE_VAR_DETECTION；
 * LOG_ONLY / ADJUST_SCORE 仅历史记录可读（NEEDS_REVIEW），拒绝新启用；
 * API 引擎仅 OBSERVE_RULE。
 */
export type ExceptionAction =
  | 'REMOVE_RULE'
  | 'REMOVE_RULE_TAG'
  | 'REMOVE_VAR_DETECTION'
  | 'ADJUST_SCORE'
  | 'LOG_ONLY'
  | 'OBSERVE_RULE'

/** 例外目标引擎（迁移 000130 exception_policies.target_engine） */
export type ExceptionTargetEngine = 'WAF' | 'API'

/** API 规则引用（api_rule_refs 元素；S4 §3 detector_id 受支持注册表：api_schema / api_parser） */
export interface ApiExceptionRuleRef {
  detector_id: string
  rule_id: string
  model_version?: string | null
}

/** 例外校验状态（迁移 000130 validation_status；NEEDS_REVIEW 禁止启用） */
export type ExceptionValidationStatus = 'VALID' | 'NEEDS_REVIEW'

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
  /** 目标引擎（迁移 000130；缺省按 WAF 处理，兼容旧后端不返回该字段） */
  target_engine?: ExceptionTargetEngine
  /** API 规则引用（target_engine=API 时非空；旧记录/旧后端可空） */
  api_rule_refs?: ApiExceptionRuleRef[] | null
  /** 规则标签启用时展开冻结的规则 ID 集（迁移 000130 resolved_rule_ids） */
  resolved_rule_ids?: number[] | null
  /** 来源安全事件（从事件创建的草稿携带） */
  source_event_id?: string | null
  /** 校验状态（迁移 000130；NEEDS_REVIEW 禁止启用，须先修改达标） */
  validation_status?: ExceptionValidationStatus
  /** 编译指纹（预览/发布前重验，防预览后草稿被改） */
  compiled_fingerprint?: string | null
  /** 不支持项原因列表（NEEDS_REVIEW 记录逐条说明缺什么，S4 §4/§8） */
  unsupported_reasons?: string[] | null
}

/** 例外策略详情（含宽泛判定与编译后的实际下发内容） */
export interface ExceptionDetail {
  exception: ExceptionItem
  is_broad: boolean
  /** WAF 引擎生成的两规则标记法 SecLang 原文 */
  generated_seclang?: string
  /** API 引擎下发网关 api_exceptions 段的 JSON 对象 */
  compiled_api_exception?: Record<string, unknown> | null
  /** 尚不可编译时的明确原因说明 */
  compile_error?: string
}

/* ---------- P0-04：例外预览（POST /api/v1/exceptions/{id}/preview，契约 S4 §8，已冻结逐字字段） ---------- */

/** 预览字段级错误 */
export interface ExceptionPreviewFieldError {
  field: string
  message: string
}

/** 预览规范化范围（normalized_scope） */
export interface ExceptionPreviewNormalizedScope {
  domain?: string
  uri_exact?: string
  uri_prefix?: string
  uri_regex?: string
  methods?: string[] | null
  source_ips?: string[] | null
  content_types?: string[] | null
  effective_from?: string | null
  effective_until?: string | null
}

/** 预览解析后的规则引用（WAF：rule_id 数值；API：detector_id + rule_id 字符串） */
export interface ExceptionPreviewRuleRef {
  engine: string
  rule_id?: number | string
  detector_id?: string
  model_version?: string | null
}

/** 预览不支持项与迁移预览 */
export interface ExceptionPreviewUnsupported {
  field_or_action: string
  migration_preview?: string
}

/**
 * 例外影响预览结果（S4 §8 契约，逐字字段）。
 * 预览不启用、不发布、不回放真实请求；estimated_match_count / historical_sample_coverage
 * 为 null 表示历史日志字段不足「无法估算」，前端禁止显示 0 影响。
 */
export interface ExceptionPreviewResult {
  validation_status: ExceptionValidationStatus
  field_errors: ExceptionPreviewFieldError[]
  normalized_scope: ExceptionPreviewNormalizedScope
  resolved_rule_refs: ExceptionPreviewRuleRef[]
  effective_window: {
    from?: string | null
    until?: string | null
    half_open: boolean
  }
  unsupported: ExceptionPreviewUnsupported[]
  protected_modules_unchanged: string[]
  compiled_fingerprint: string
  /** WAF 引擎预览生成的两规则标记法 SecLang 原文 */
  generated_seclang?: string
  /** API 引擎预览生成的 api_exceptions 下发 JSON */
  compiled_api_exception?: Record<string, unknown> | null
  /** 尚不可编译时的明确原因说明 */
  compile_error?: string
  required_publish_targets: string[]
  historical_sample_coverage?: number | null
  estimated_match_count: number | null
}

/* ---------- P0-04：最终处置记录（final_decision JSON，契约 S4 §2，schema_version=1，已冻结逐字字段） ---------- */

/** 模块规则/策略/模型标识及版本（rule_refs ≤ 64，超出由后端显式截断） */
export interface FinalDecisionRuleRef {
  module?: string
  rule_id?: string
  version?: string | null
}

/** 节点实际生效配置指纹（发布批次/策略/规则包/例外版本；不取当前最新草稿） */
export interface FinalDecisionEffectiveConfig {
  config_fingerprint?: string | null
  api_policy_version?: string | null
  exception_versions?: Record<string, number> | null
}

/** Finding 有界计数摘要 */
export interface FinalDecisionFindings {
  observed?: number
  enforced?: number
  excepted?: number
  skipped?: number
}

/** 执行过程步骤（steps ≤ 32；后端截断时追加 module=TRUNCATED 条目） */
export interface FinalDecisionStep {
  module?: string
  result?: 'EXECUTED' | 'OBSERVED' | 'EXCEPTED' | 'SKIPPED' | string
  detail?: string | null
}

/** 命中的例外（ID、版本、目标规则、范围摘要、起止时间与实际匹配） */
export interface FinalDecisionMatchedException {
  exception_id?: string
  version?: number
  target?: string
  rule_refs?: string[]
  scope_summary?: string
  effective_from?: string | null
  effective_until?: string | null
}

/** 身份验证引用（P0-03 状态与可信主体指纹，历史可空；不含原始 Token/明文声明） */
export interface FinalDecisionIdentityVerification {
  status?: string
  verified_principal_id?: string
}

/**
 * 最终处置记录（security_events.final_decision / api_runtime_events.final_decision /
 * access_control_events.details.final_decision；历史事件不回填，为 null）。
 * 归因纪律：只记录已执行事实；API ALLOW 是中间决策，不等于最终放行；
 * 观察命中不进 security_action。
 */
export interface FinalDecision {
  schema_version?: number
  request_id?: string
  application_id?: string
  gateway_node?: string
  completion_status?:
    | 'COMPLETED'
    | 'ABORTED'
    | 'ERROR'
    | 'PENDING_CORRELATION'
    | 'UNKNOWN'
    | string
  security_action?:
    | 'NONE'
    | 'BLOCK'
    | 'TEMP_BLOCK'
    | 'RATE_LIMIT'
    | 'MASK_RESPONSE'
    | 'CHALLENGE'
    | string
  executor_module?:
    | 'PROTECTED_ADDRESS'
    | 'MANUAL_BAN'
    | 'IP_BLACKLIST'
    | 'L7_ACL'
    | 'AUTO_BAN'
    | 'RISK_POLICY'
    | 'LICENSE_QUOTA'
    | 'CC'
    | 'BOT'
    | 'JWT'
    | 'API'
    | 'WAF'
    | 'NONE'
    | 'UNKNOWN'
    | string
  response_source?: 'GATEWAY' | 'ORIGIN' | 'UNKNOWN' | string
  http_status?: number
  response_committed?: boolean
  reason_codes?: string[]
  rule_refs?: FinalDecisionRuleRef[]
  effective_config?: FinalDecisionEffectiveConfig | null
  findings?: FinalDecisionFindings | null
  steps?: FinalDecisionStep[]
  matched_exceptions?: FinalDecisionMatchedException[]
  identity_verification?: FinalDecisionIdentityVerification | null
  evidence_refs?: string[]
  finalized_at?: string
}

/**
 * 事件 JWT 验证信息（WDSP P0-03 §5；契约 server/internal/jwttrust/result.go，
 * 事件落库线格式为网关 dynamic_security/events.JWTVerification）。
 * 集成落库前历史事件无此字段，前端按可选对象做空态（「当时未记录」）。
 * 脱敏纪律：不含原始 Token、完整 payload、明文 sub/tenant；
 * verified_principal_id/verified_tenant_id 为应用隔离/加盐 HMAC 指纹；UNVERIFIED 不代表非法用户。
 */
export interface JwtVerificationInfo {
  status: string
  reason_code: string
  /** 策略版本（溯源）：安全事件契约为数值；api_runtime_events 落库（events.JWTVerification）为字符串版本戳，两种形态均容忍 */
  policy_version?: number | string
  issuer_config_id?: string
  keyset_version?: string
  verified_principal_id?: string
  /** 可信租户指纹（加盐 HMAC，非明文 tenant；仅 VERIFIED 且配置 tenant_claim 验证成功时非空） */
  verified_tenant_id?: string
  evaluated_at?: string
}

/** IP 归属地与运营商信息（后端统一 GeoIP 引擎 ip2region + DB-IP/MMDB 实时补齐） */
export interface IPGeoInfo {
  ip: string
  scope: 'PUBLIC' | 'INTERNAL' | 'INVALID' | string
  country_code?: string
  country?: string
  province?: string
  city?: string
  isp?: string
  label: string
  latitude?: number
  longitude?: number
  source?: string
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
  client_ip_geo?: IPGeoInfo | null
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
  /** 请求/响应头体留痕（仅详情接口返回；敏感头已掩码，体超 64KB 截断） */
  request_headers?: Record<string, string[]> | null
  request_body?: string
  request_body_truncated?: boolean
  response_headers?: Record<string, string[]> | null
  response_body?: string
  response_body_truncated?: boolean
  /** JWT 验证信息（WDSP P0-03；仅启用 JWT 信任策略且集成落库后的事件携带，历史事件为空） */
  jwt_verification?: JwtVerificationInfo | null
  /** 最终处置记录（WDSP P0-04 S4 §2；历史事件不回填为 null，前端显示「无最终处置记录（旧数据）」） */
  final_decision?: FinalDecision | null
}

/** 事件规则匹配（matched_data 已脱敏，渲染时必须按纯文本转义显示） */
export interface SecurityEventMatch {
  rule_id: number
  rule_name: string
  rule_source?: string
  rule_version?: string
  severity: string
  message: string
  matched_variable: string
  matched_data: string
  tags: string[]
  phase: number
  /** 命中规则标注的 CNNVD 编号（CNNVD 兼容性 P1，查询时现值；缺省 []，旧后端不返回） */
  cnnvd_ids?: string[] | null
  /** 命中规则标注的 CVE 编号（缺省 []，旧后端不返回） */
  cve_ids?: string[] | null
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

/** 相关事件关联口径：attack_session=同一攻击会话；same_source_ip=同来源IP前后24小时；none=无关联线索 */
export type RelatedEventMode = 'attack_session' | 'same_source_ip' | 'none'

/** 安全事件详情 */
export interface SecurityEventDetail {
  event: SecurityEventItem
  matches: SecurityEventMatch[] | null
  notes: SecurityEventNote[] | null
  actions: SecurityEventActionRecord[] | null
  related: SecurityEventItem[] | null
  related_mode?: RelatedEventMode | null
  related_session_id?: string | null
}

/** 规则版本按日效果统计 */
export interface WafRuleEffectStatistics {
  date: string
  rule_id: number
  rule_key: string
  rule_name: string
  rule_source: string
  rule_version: string
  hits: number
  blocks: number
  unresolved: number
  confirmed_attacks: number
  false_positives: number
  reviewed: number
  confirmation_rate: number | null
  fp_rate: number | null
  protect_recommendation: boolean
  protect_recommendation_reason?: string
}

export type WafRuleEffectStatisticsPage = PageResult<WafRuleEffectStatistics>

/** 从事件创建例外草稿的结果 */
export interface CreateExceptionFromEventResult {
  exception_id: string
  message: string
}

/* ==================== 全量访问日志 ==================== */

/** 访问日志列表项（不含请求/响应头体留痕） */
export interface AccessLogItem {
  id: string
  occurred_at: string
  request_id: string
  application_id?: string | null
  domain: string
  gateway_node_id: string
  client_ip: string
  client_ip_geo?: IPGeoInfo | null
  client_port: number
  request_method: string
  request_uri: string
  request_path: string
  query_summary: string
  http_version: string
  content_type: string
  user_agent_summary: string
  referer_summary: string
  response_status: number
  bytes_in: number
  bytes_out: number
  duration_ms: number
  /** 实际 WAF 动作（如 ALLOW/BLOCK）；无明确归因时不得标为阻断 */
  waf_action: string
  /** 可选 TLS/国密握手上下文（旧记录或缺省为空） */
  tls_protocol?: string
  tls_cipher_suite?: string
  tls_is_gm?: boolean
  tls_ja3?: string
  client_hello_version?: string
}

/* ==================== SSL/HTTPS 加密会话分析 ==================== */

export type TLSSessionAction =
  | 'ALLOWED'
  | 'BLOCKED_LEGACY_SSL'
  | 'BLOCKED_PROTOCOL_POLICY'
  | 'HANDSHAKE_FAILED'

export type TLSSessionProtocol =
  | 'SSLv2'
  | 'SSLv2/v3'
  | 'SSLv3'
  | 'TLS1.0'
  | 'TLS1.1'
  | 'TLS1.2'
  | 'TLS1.3'
  | 'TLCP1.1'
  | 'UNKNOWN'

/** SSL/HTTPS 加密会话握手记录 */
export interface TLSSessionItem {
  id: string
  occurred_at: string
  gateway_node_id: string
  application_id?: string | null
  sni: string
  client_ip: string
  client_port: number
  server_port: number
  detected_protocol: string
  negotiated_protocol: string
  cipher_suite: string
  is_gm: boolean
  ja3_hash: string
  alpn: string
  action: string
  error_reason: string
}

export interface TLSSessionProtocolStat {
  protocol: string
  count: number
  is_gm: boolean
  is_legacy: boolean
}

export interface TLSSessionCipherStat {
  cipher_suite: string
  count: number
  is_gm: boolean
}

/** SSL/HTTPS 加密会话汇总统计（GET /tls-sessions/summary） */
export interface TLSSessionSummary {
  total_handshakes: number
  allowed_count: number
  gm_count: number
  intl_count: number
  legacy_ssl_blocked_count: number
  policy_blocked_count: number
  handshake_failed_count: number
  by_protocol: TLSSessionProtocolStat[]
  by_cipher_suite: TLSSessionCipherStat[]
}

/** 访问日志详情（额外含Trace、真实TTFB与脱敏头体留痕；未采集字段保持空值） */
export interface AccessLogDetail extends AccessLogItem {
  trace_id?: string
  span_id?: string
  endpoint_key?: string
  path_template?: string
  ttfb_ms?: number | null
  request_headers?: Record<string, string[]> | null
  request_body?: string
  request_body_truncated?: boolean
  response_headers?: Record<string, string[]> | null
  response_body?: string
  response_body_truncated?: boolean
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
  /** 正式导入返回：导入规则统一落 DRAFT 草稿状态 */
  status?: string
}

/** 事件→黑名单预填：近 24h 同 IP 命中规则统计 */
export interface BlacklistPrefillHitRule {
  rule_id: number
  rule_name: string
  hits: number
}

/** 共享出口/代理迹象（无任何身份数据时后端整体省略该字段） */
export interface BlacklistPrefillSharedEgress {
  identity_count: number
  suspected: boolean
}

/** 同地址已存在的黑名单规则（提示避免重复封禁） */
export interface BlacklistPrefillExistingRule {
  id: string
  name: string
  status: AccessRuleItem['status']
  validity_type: 'PERMANENT' | 'TEMPORARY'
  effective_until?: string | null
}

/** 事件→黑名单预填数据（阶段5 §十一；均为建议值，需管理员确认后才创建） */
export interface BlacklistPrefill {
  event_id: string
  address: string
  rule_type: 'DENY'
  suggested_name: string
  suggested_reason: string
  application_id?: string | null
  application_name: string
  attack_type: string
  severity: string
  related_event_count_24h: number
  last_attack_at?: string | null
  hit_rules: BlacklistPrefillHitRule[]
  suggested_duration_hours: number
  protected_hit: boolean
  protected_name?: string
  shared_egress_hint?: BlacklistPrefillSharedEgress | null
  existing_deny_rule?: BlacklistPrefillExistingRule | null
}

/** 预填接口响应 */
export interface BlacklistPrefillResult {
  prefill: BlacklistPrefill
}

/** URL 白名单规则 */
export interface URLWhitelistRuleItem {
  id: string
  name: string
  scope_type: 'GLOBAL' | 'APPLICATION'
  application_id?: string | null
  match_type: 'EXACT' | 'PREFIX' | 'REGEX'
  uri_pattern: string
  methods: string[]
  priority: number
  status: 'DRAFT' | 'ACTIVE' | 'DISABLED' | 'EXPIRED' | 'DELETED'
  validity_type: 'PERMANENT' | 'TEMPORARY'
  effective_from?: string | null
  effective_until?: string | null
  reason: string
  source_type: 'MANUAL' | 'SECURITY_EVENT'
  source_event_id?: string | null
  hit_count: number
  last_hit_at?: string | null
  created_by?: string | null
  created_at: string
  updated_by?: string | null
  updated_at: string
  version: number
}

/** URL 白名单规则详情响应 */
export interface URLWhitelistRuleDetail {
  rule: URLWhitelistRuleItem
}

/** 同路径已存在的 URL 白名单简要信息 */
export interface WhitelistPrefillExistingURL {
  id: string
  name: string
  match_type: 'EXACT' | 'PREFIX' | 'REGEX'
  uri_pattern: string
  status: URLWhitelistRuleItem['status']
}

/** 事件→白名单预填数据（支持 IP 白名单 / URL 白名单 + 可选同步创建精确 WAF 例外） */
export interface WhitelistPrefill {
  event_id: string
  address: string
  request_path: string
  request_method: string
  domain: string
  application_id?: string | null
  application_name: string
  attack_type: string
  severity: string
  related_event_count_24h: number
  last_attack_at?: string | null
  hit_rules: BlacklistPrefillHitRule[]
  event_rule_ids: number[]
  can_create_waf_exception: boolean
  suggested_ip_name: string
  suggested_url_name: string
  suggested_reason: string
  shared_egress_hint?: BlacklistPrefillSharedEgress | null
  existing_allow_rule?: BlacklistPrefillExistingRule | null
  existing_deny_rule?: BlacklistPrefillExistingRule | null
  existing_url_whitelist?: WhitelistPrefillExistingURL | null
}

/** 白名单预填接口响应 */
export interface WhitelistPrefillResult {
  prefill: WhitelistPrefill
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
  dimension:
    | 'CLIENT_IP'
    | 'APPLICATION'
    | 'CLIENT_IP_AND_URI'
    | 'CLIENT_IP_AND_APPLICATION'
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
  /** HTTP 协议版本（HTTP/1.1 / HTTP/2.0 / HTTP/3；空 = 旧版网关未上报） */
  proto?: string | null
  created_at: string
}

/** 访问控制事件详情响应 */
export interface AccessControlEventDetail {
  event: AccessControlEventItem
}

/* ==================== L7 访问控制（契约见 docs：l7-rules REST / guardconfig l7_rules 载荷） ==================== */

/** L7 条件类型 */
export type L7ConditionType =
  | 'uri'
  | 'host'
  | 'method'
  | 'header'
  | 'cookie'
  | 'query'
  | 'client_ip'
  | 'request_body'
  | 'response_header'
  | 'response_body'

/** L7 条件运算符（method/client_ip 用 values 数组，等价 in） */
export type L7ConditionOp =
  'eq' | 'ne' | 'prefix' | 'contains' | 'regex' | 'exists' | 'not_exists' | 'in'

/** L7 访问控制条件（uri/host 无 name；exists/not_exists 无 value；method/client_ip 用 values） */
export interface L7RuleCondition {
  type: L7ConditionType
  name?: string
  op?: L7ConditionOp
  value?: string
  values?: string[]
}

/** L7 规则动作 */
export type L7RuleAction = 'block' | 'allow' | 'redirect' | 'custom_page'

/** L7 动作配置（按动作取对应字段，未用字段置空/默认值） */
export interface L7RuleActionConfig {
  status?: number
  message?: string
  redirect_url?: string
  redirect_status?: number
  preserve_path_query?: boolean
  content_type?: string
  body?: string
}

/** L7 访问控制规则 */
export interface L7RuleItem {
  id: string
  name: string
  priority: number
  enabled: boolean
  conditions: L7RuleCondition[]
  action: L7RuleAction
  action_config: L7RuleActionConfig
  /** 近 24 小时命中数 */
  hit_count_24h: number
  created_by?: string | null
  updated_by?: string | null
  created_at: string
  updated_at: string
}

/** L7 规则详情响应 */
export interface L7RuleDetail {
  rule: L7RuleItem
}

/** L7 规则测试器入参 */
export interface L7RuleTestRequest {
  uri: string
  host?: string
  method: string
  headers: Record<string, string>
  cookies: Record<string, string>
  query: Record<string, string>
  client_ip: string
  request_body?: string
  response_headers?: Record<string, string>
  response_body?: string
}

/** L7 规则测试器结果（不产生真实流量、不写事件） */
export interface L7RuleTestResult {
  matched: boolean
  rule_id?: string
  rule_name?: string
  action?: L7RuleAction | ''
  reason?: string
  redirect_status?: number
  redirect_location?: string
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
  /** 请求方法分布（仅 request-trend 返回，值降序最多 20 项） */
  method_distribution?: KeyValue[] | null
  /** 请求 Content-Type 主类型分布（仅 request-trend 返回，值降序最多 20 项） */
  content_type_distribution?: KeyValue[] | null
  /** 客户端 IP 识别来源分布（仅 request-trend 返回；空值归入"(未知)"，值降序最多 20 项） */
  client_ip_source_distribution?: KeyValue[] | null
  /** 可信代理来源分布（仅 request-trend 返回；未经过可信代理归入"(直连)"，值降序最多 20 项） */
  trusted_proxy_distribution?: KeyValue[] | null
}

/** 排行/分布响应包装 */
export interface CountList<T = KeyValue> {
  items?: T[] | null
}

/** 网站访问趋势-时间序列点 */
export interface SiteAccessTrendPoint {
  t: string
  requests: number
}

/** 网站访问趋势-应用项（按应用聚合，含零流量应用，按 total_requests 降序） */
export interface SiteAccessTrendItem {
  application_id: string
  app_code: string
  app_name: string
  total_requests: number
  series?: SiteAccessTrendPoint[] | null
}

/** 网站访问趋势响应（时间跨度上限 7 天） */
export interface SiteAccessTrendsData {
  start: string
  end: string
  granularity: string
  items?: SiteAccessTrendItem[] | null
}

/** 网站访问趋势-域名项（指定应用下按域名聚合） */
export interface DomainAccessTrendItem {
  domain: string
  total_requests: number
  series?: SiteAccessTrendPoint[] | null
}

/** 网站访问趋势-域名钻取响应 */
export interface SiteAccessTrendDomainsData {
  start: string
  end: string
  granularity: string
  items?: DomainAccessTrendItem[] | null
}

/** 站点流量-时间序列桶（unique_ips/blocked_requests 在日聚合口径下为 null） */
export interface SiteTrafficPoint {
  t: string
  requests: number
  bytes_in: number
  bytes_out: number
  unique_ips: number | null
  blocked_requests: number | null
}

/** 站点流量-汇总（unique_ips/blocked_requests 在日聚合口径下为 null） */
export interface SiteTrafficSummary {
  total_requests: number
  total_bytes_in: number
  total_bytes_out: number
  unique_ips: number | null
  blocked_requests: number | null
  peak_bucket_requests: number
}

/** 站点流量-应用项 */
export interface SiteTrafficItem {
  application_id: string
  app_code: string
  app_name: string
  total_requests: number
  total_bytes_in: number
  total_bytes_out: number
  unique_ips: number | null
  blocked_requests: number | null
  series?: SiteTrafficPoint[] | null
}

/** 站点流量响应（跨度 ≤7 天取 access_logs 实时聚合，>7 天取 site_traffic_daily 按日聚合） */
export interface SiteTrafficData {
  start: string
  end: string
  granularity: 'minute' | 'hour' | 'day'
  source: 'access_logs' | 'site_traffic_daily'
  summary?: SiteTrafficSummary | null
  items?: SiteTrafficItem[] | null
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

/** 报告类型（固定 日/周/月/自定义；API_* 为阶段8 遗留专项类型，仅兼容历史任务） */
export type ReportType = 'DAILY' | 'WEEKLY' | 'MONTHLY' | 'CUSTOM'

/** 报告内容范围：仅 Web 防护 / 仅 API 防护 / 全部（默认） */
export type ReportContentScope = 'WAF' | 'API' | 'WAF_API'

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
  content_scope?: ReportContentScope
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
  file_format: 'html' | 'pdf' | 'docx'
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
  archive_id: string
  report_job_id: string
  report_no?: string
  report_type?: string
  status?: string
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

/** 网关趋势查询时间窗口 */
export type GatewayTrendRange = '10m' | '1h' | '6h' | '24h'

/** 网关趋势数据源 */
export type GatewayTrendSource = 'gateway_live' | 'database' | 'database_fallback'

/** 网关 TCP 连接状态细分 */
export interface GatewayTCPStates {
  established: number
  time_wait: number
  close_wait: number
  syn_recv: number
  fin_wait: number
  listen: number
  other: number
}

/** 网关软件旁路状态 */
export interface GatewaySoftwareBypassState {
  enabled: boolean
  active: boolean
  reason?: string
  cpu_threshold_percent?: number
  memory_threshold_percent?: number
  recovery_cpu_percent?: number
  recovery_memory_percent?: number
  min_hold_seconds?: number
  activated_at?: string | null
  transitions_total?: number
  bypassed_requests_total?: number
}

/** 网关当前实时指标快照 */
export interface GatewayTrendCurrent {
  status: string
  latency_ms?: number | null
  taken_at?: string
  cpu_percent?: number | null
  memory_percent?: number | null
  memory_used_bytes?: number | null
  memory_total_bytes?: number | null
  load1?: number | null
  load5?: number | null
  load15?: number | null
  fd_open?: number | null
  fd_max?: number | null
  fd_usage_percent?: number | null
  tcp_connections_active: number
  tcp_connections_accepted_total: number
  tcp_connections_accepted_per_second: number
  bytes_in_total: number
  bytes_out_total: number
  bytes_in_per_second: number
  bytes_out_per_second: number
  http_requests_in_flight: number
  http_requests_total: number
  http_requests_per_second: number
  http_sessions_active: number
  http_sessions_new_total: number
  http_sessions_new_per_second: number
  http_sessions_overflow_total: number
  http_sessions_capacity?: number
  status_2xx_total: number
  status_3xx_total: number
  status_4xx_total: number
  status_5xx_total: number
  status_2xx_per_second: number
  status_3xx_per_second: number
  status_4xx_per_second: number
  status_5xx_per_second: number
  software_bypass?: GatewaySoftwareBypassState | null
  tcp_states?: GatewayTCPStates | null
  resource_sample_error?: string
}

/** 网关趋势区间统计摘要 */
export interface GatewayTrendSummary {
  peak_tcp_connections_active: number
  avg_tcp_connections_active: number
  peak_tcp_connections_accepted_per_second: number
  peak_http_sessions_active: number
  peak_http_sessions_new_per_second: number
  peak_http_requests_per_second: number
  peak_bytes_in_per_second: number
  peak_bytes_out_per_second: number
  peak_cpu_percent?: number | null
  peak_memory_percent?: number | null
  bypass_active_points: number
}

/** 网关趋势单个时间采样点 */
export interface GatewayTrendPoint {
  taken_at: string
  cpu_percent?: number | null
  memory_percent?: number | null
  load1?: number | null
  fd_usage_percent?: number | null
  tcp_connections_active: number
  tcp_connections_accepted_per_second: number
  bytes_in_per_second: number
  bytes_out_per_second: number
  http_requests_in_flight: number
  http_requests_per_second: number
  http_sessions_active: number
  http_sessions_new_per_second: number
  status_2xx_per_second: number
  status_3xx_per_second: number
  status_4xx_per_second: number
  status_5xx_per_second: number
  software_bypass_active: boolean
}

/** 按应用实时负载明细 */
export interface GatewayTrendApplication {
  app_id: string
  app_code?: string
  app_name?: string
  requests_in_flight: number
  requests_total: number
  requests_per_second: number
  bypassed_requests_total: number
  bytes_in_total: number
  bytes_out_total: number
  bytes_in_per_second: number
  bytes_out_per_second: number
  status_4xx_total: number
  status_5xx_total: number
}

/** 网关实时与历史趋势响应（GET /system-health/gateway-trend） */
export interface GatewayTrendResponse {
  range: GatewayTrendRange
  source: GatewayTrendSource
  interval_seconds: number
  generated_at: string
  node?: string
  current?: GatewayTrendCurrent | null
  summary?: GatewayTrendSummary | null
  points: GatewayTrendPoint[]
  applications: GatewayTrendApplication[]
}

/** 节点物理网口（GET /gateway/interfaces；WDSP 阶段A 网口管理） */
export interface NodeInterfaceItem {
  ifname: string
  mac: string
  /** 网口绑定的全局单播 IPv4/IPv6 地址列表（CIDR 形式，IPv4 优先） */
  ip_addresses?: string[]
  pci_path?: string
  driver?: string
  /** 介质类型：TP 电口 / FIBRE 光口 / UNKNOWN 未知 */
  media_type: 'TP' | 'FIBRE' | 'UNKNOWN'
  /** 链路速率（Mb/s），DOWN 为 0 */
  link_speed?: number
  operstate?: string
  sort_order: number
  /** 用途标记：MANAGEMENT 管理 / TRAFFIC 业务 / MIRROR 镜像；空为未分配 */
  role?: string
  /** 最近一次采集是否在线；false 表示已离线（曾为该节点上报过） */
  present: boolean
}

/** 单个网关节点的网口清单 */
export interface NodeInterfacesNode {
  node_name: string
  interfaces?: NodeInterfaceItem[] | null
}

/** 网口清单响应（GET /gateway/interfaces） */
export interface NodeInterfacesData {
  nodes?: NodeInterfacesNode[] | null
}

/** 网口排序保存项（PUT /gateway/interfaces/order） */
export interface NodeInterfaceOrderItem {
  ifname: string
  sort_order: number
  role?: string
}

/** 网口排序保存请求体 */
export interface NodeInterfaceOrderPayload {
  node_name: string
  items: NodeInterfaceOrderItem[]
}

/** 端口联动（Link-Pair）配置：网桥两个成员口互为配对，一口链路故障时联动 down 配对口，
 * 引导上游设备切换链路（docs/HA_ACTIVE_STANDBY_DESIGN.md §6） */
export interface NetworkLinkPairConfig {
  enabled: boolean
  /** carrier 持续丢失认定故障的毫秒数（0=服务端落缺省 1000，区间 200~10000） */
  hold_down_ms: number
  /** carrier 持续恢复认定故障消除的毫秒数（0=服务端落缺省 5000，区间 1000~60000） */
  hold_up_ms: number
  /** 每小时联动次数上限（0=服务端落缺省 20，区间 1~200；超限进入抑制态） */
  max_flaps_per_hour: number
}

/** 期望网桥（name 桥名，ports 成员口列表；透明串接/桥接场景） */
export interface NetworkBridgeConfig {
  name: string
  ports: string[]
  /** 端口联动配置（可选；不填或 enabled=false = 不启用） */
  link_pair?: NetworkLinkPairConfig | null
}

/** 期望静态路由（dst 目的网段 CIDR，via 下一跳网关；路由牵引场景） */
export interface NetworkRouteConfig {
  dst: string
  via: string
}

/** 网络期望配置：网桥 + 内核三层转发 + 静态路由（PUT 全量替换语义） */
export interface NetworkDesiredConfig {
  bridges: NetworkBridgeConfig[]
  ip_forward: boolean
  routes: NetworkRouteConfig[]
}

/** 网桥执行状态（state: ok/error，message 为失败原因等补充信息） */
export interface NetworkBridgeStatus {
  name: string
  state: string
  message?: string
}

/** 静态路由执行状态 */
export interface NetworkRouteStatus {
  dst: string
  via?: string
  state: string
  message?: string
}

/** 端口联动运行状态（netmgrd 联动监控器上报） */
export interface NetworkLinkPairStatus {
  bridge: string
  /** 状态机取值：BOTH_UP 正常 / PROPAGATED_DOWN 已联动 down / SUPPRESSED 频率超限抑制 */
  state: string
  /** 故障口（carrier 丢失的一方） */
  down_port?: string
  /** 被联动 down 的配对口 */
  propagated_port?: string
  /** 配对口是否系联动 down（区别于运维手工 down） */
  propagated_by_linkpair?: boolean
  /** 近 1 小时联动次数 */
  flap_count_hour?: number
  last_event_at?: string
  message?: string
}

/** 透明串接牵引运行状态（netmgrd network-status.json transparent 字段，未启用/未初始化时省略） */
export interface NetworkTransparentStatus {
  /** 运行状态：INACTIVE 未启用 / ACTIVE 牵引生效 / DEGRADED 已降级 */
  state: 'INACTIVE' | 'ACTIVE' | 'DEGRADED' | string
  enabled?: boolean
  redirect_active?: boolean
  listen_port?: number
  ports?: number[] | null
  bridges?: string[] | null
  tproxyd_healthy?: boolean
  caddy_healthy?: boolean
  bridge_nf_ready?: boolean
  message?: string
  updated_at?: string
}

/** 节点网络配置执行状态（边车 network-status.json 上报；null 表示节点尚未上报） */
export interface NetworkConfigStatus {
  applied_at?: string
  ok: boolean
  bridges?: NetworkBridgeStatus[] | null
  /** 内核三层转发执行结果：ok/error/skipped */
  ip_forward?: string
  routes?: NetworkRouteStatus[] | null
  /** 启用端口联动的桥的运行状态（未启用联动时缺省） */
  link_pairs?: NetworkLinkPairStatus[] | null
  /** 透明串接牵引运行状态（netmgrd 可选上报） */
  transparent?: NetworkTransparentStatus | null
  message?: string
}

/** 网络配置响应（GET /gateway/network-config） */
export interface NetworkConfigData {
  desired?: Partial<NetworkDesiredConfig> | null
  status?: NetworkConfigStatus | null
  /** 本网关默认节点名（可选；非默认节点未启用远端协同时仅支持只读查看） */
  default_node?: string
  /** 当前查询节点是否可编辑并下发（本机默认节点或已启用 hasyncd 协同代理的远端节点） */
  remote_editable?: boolean
}

/** 网络工具诊断动作（POST /network-tools/jobs 的 action 取值） */
export type NetworkToolAction =
  'ping' | 'tcp_probe' | 'traceroute' | 'dns_query' | 'capture'

/** 网络工具任务状态（PENDING/RUNNING 为非终态，前端据此轮询） */
export type NetworkToolJobStatus =
  'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'STOPPED' | 'TIMEOUT'

/** 抓包任务解析后的单个数据包（GET /network-tools/jobs/{id} 的 capture_packets 元素） */
export interface NetworkToolCapturePacket {
  no: number
  ts: string
  src: string
  dst: string
  sport?: number | null
  dport?: number | null
  proto: string
  flags: string
  length: number
  preview: string
}

/** 网络工具诊断任务（GET /network-tools/jobs；params 回显创建时的动作参数） */
export interface NetworkToolJob {
  id: string
  node: string
  action: NetworkToolAction
  target: string
  params: Record<string, unknown>
  status: NetworkToolJobStatus
  result_text: string
  exit_code?: number | null
  duration_ms?: number | null
  capture_size?: number | null
  /** 解析后的数据包列表（仅 capture 任务详情返回；非抓包或未解析为 null） */
  capture_packets?: NetworkToolCapturePacket[] | null
  failure_message: string
  created_at: string
  started_at?: string | null
  finished_at?: string | null
}

/** 主备组成员 */
export interface HaGroupMember {
  node_id: string
  node_name: string
  priority: number
}

/** 主备高可用组（VIP 漂移；docs/HA_ACTIVE_STANDBY_DESIGN.md §8） */
export interface HaGroup {
  id: string
  name: string
  /** ENABLED/DISABLED */
  state: string
  vrid: number
  iface: string
  vips: string[]
  preempt: boolean
  advert_int_ms: number
  unicast: boolean
  unicast_peers: string[]
  /** Keepalived track_interface 监控的关联接口列表 */
  track_interfaces?: string[]
  has_auth_pass: boolean
  members: HaGroupMember[]
  version: number
  created_at?: string
  updated_at?: string
}

/** 主备组创建/修改请求体（auth_pass：undefined=不变更；''=清除；其他=设置） */
export interface HaGroupUpsert {
  name: string
  state: string
  vrid: number
  iface: string
  vips: string[]
  preempt: boolean
  advert_int_ms: number
  unicast: boolean
  unicast_peers: string[]
  track_interfaces?: string[]
  auth_pass?: string
  members: { node_id: string; priority: number }[]
  version?: number
}

/** havipd 漂移/状态迁移事件 */
export interface HaVipEvent {
  at: string
  from: string
  to: string
  detail?: string
}

/** havipd 运行状态（ha-vip-status.json 透传；null = 节点未上报） */
export interface HaVipStatus {
  group: string
  node: string
  /** MASTER/BACKUP/FAULT/DISABLED/STOPPED */
  state: string
  keepalived_running: boolean
  vips_present: string[]
  priority: number
  last_transition_at?: string
  applied_at?: string
  message?: string
  events?: HaVipEvent[]
}

/** 单节点汇聚后的 HA VIP 运行状态快照（server/internal/hagroups.NodeRuntimeStatus） */
export interface HaNodeRuntimeStatus {
  node_name: string
  status?: HaVipStatus | null
  updated_at?: string | null
  fresh: boolean
  /** "local" | "remote" */
  source?: string
}

/** 单节点边车配置同步结果（server/internal/hagroups.SyncResult） */
export interface HaSyncResult {
  node_name: string
  /** "local" | "remote" */
  scope: string
  /** "SUCCESS" | "FAILED" */
  status: string
  error?: string
}

/** 主备高可用持久化历史事件（GET /ha/events；server/internal/hagroups.HaEvent） */
export interface HaEvent {
  id: number
  group_id?: string
  group_name: string
  node_name: string
  /** FAILBACK | SYNC_FAILED | SPLIT_BRAIN | VIP_TRANSITION | LINK_PAIR_CHANGE */
  event_type: string
  detail: Record<string, unknown>
  occurred_at: string
}

/** 主备组列表响应 */
export interface HaGroupListData {
  items?: HaGroup[]
  status?: HaVipStatus | null
  node_statuses?: Record<string, HaNodeRuntimeStatus>
  split_brain?: boolean
}

/** 主备组详情响应 */
export interface HaGroupDetailData {
  group?: HaGroup
  status?: HaVipStatus | null
  node_statuses?: Record<string, HaNodeRuntimeStatus>
  split_brain?: boolean
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
  acknowledged_by_username?: string | null
  acknowledged_at?: string | null
  resolved_by?: string | null
  resolved_by_username?: string | null
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

/** 告警维护窗口（阶段6 §11.5）：窗口内匹配告警评估抑制，suppressed_count 记录抑制次数 */
export interface SystemAlertMaintenanceWindow {
  id: string
  name: string
  description?: string
  scope: 'ALL' | 'CUSTOM'
  alert_types?: string[] | null
  components?: string[] | null
  recurrence: 'ONCE' | 'DAILY'
  starts_at: string
  ends_at: string
  daily_start_minute?: number | null
  daily_end_minute?: number | null
  enabled: boolean
  suppressed_count: number
  last_suppressed_at?: string | null
  created_by?: string | null
  created_at: string
}

/** 创建维护窗口请求 */
export interface SystemAlertMaintenanceWindowCreateInput {
  name: string
  description?: string
  scope?: 'ALL' | 'CUSTOM'
  alert_types?: string[]
  components?: string[]
  recurrence?: 'ONCE' | 'DAILY'
  starts_at: string
  ends_at: string
  daily_start_minute?: number
  daily_end_minute?: number
}

/* ---------- 告警通知 ---------- */

/** 通知渠道类型 */
export type NotificationChannelType =
  'wecom' | 'feishu' | 'smtp' | 'syslog' | 'sms'

/** 通知级别 */
export type NotificationSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

/** 通知渠道（密值字段读返回 ********，编辑时原样提交表示不修改） */
export interface NotificationChannel {
  id: string
  name: string
  type: NotificationChannelType
  enabled: boolean
  min_severity: NotificationSeverity
  /** 订阅的告警类别 code；空数组 = 全部类别 */
  categories: string[]
  config: Record<string, unknown>
  created_at: string
  updated_at: string
}

/** 通知元数据类别 */
export interface NotificationMetaCategory {
  code: string
  name: string
  alert_types: string[]
}

/** 通知元数据（GET /notification-meta） */
export interface NotificationMeta {
  categories: NotificationMetaCategory[]
  severities: NotificationSeverity[]
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
  manifest?: unknown
  status: string
  uploaded_by?: string | null
  uploaded_at: string
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

/** 升级集群模式（LOCAL 单机 / HA_ROLLING 主备先备后主滚动升级） */
export type UpgradeClusterMode = 'LOCAL' | 'HA_ROLLING'

/** HA 集群滚动升级逐节点执行明细（server/internal/upgrades.NodeExecution） */
export interface UpgradeNodeExecution {
  id: string
  job_id: string
  node_id?: string | null
  node_name: string
  role: 'STANDBY' | 'PRIMARY' | string
  seq: number
  status: 'PENDING' | 'TRANSFERRING' | 'APPLYING' | 'VERIFYING' | 'SUCCESS' | 'FAILED' | 'SKIPPED' | string
  from_version: string
  to_version: string
  error_code: string
  error_message: string
  started_at?: string | null
  finished_at?: string | null
  created_at: string
  updated_at: string
}

/** HA 集群滚动升级节点视图项（GET /upgrades/nodes items 元素） */
export interface UpgradeClusterNode {
  node_id: string
  node_name: string
  role: 'PRIMARY' | 'STANDBY' | string
  sync_agent_addr: string
  sync_enabled: boolean
  reported_version: string
  version_aligned: boolean
  reachable: boolean
  caddy_reachable: boolean
  hostctl_ready: boolean
  upgrade_ready: boolean
  error?: string
}

/** HA 集群滚动升级节点总览（GET /upgrades/nodes） */
export interface UpgradeClusterNodesResult {
  items: UpgradeClusterNode[]
  current_version: string
  split_brain: boolean
  cluster_ready: boolean
}

/** 升级任务 */
export interface UpgradeJobItem {
  id: string
  package_id: string | null
  status: string
  cluster_mode?: UpgradeClusterMode | string
  precheck?: unknown
  backup_job_id?: string | null
  requested_by?: string | null
  requested_at: string
  /** 定时升级的计划开始时间（RFC3339）；仅 SCHEDULED 状态任务携带，立即升级为 null */
  scheduled_at?: string | null
  started_at?: string | null
  finished_at?: string | null
  failure_code?: string
  failure_message?: string
  request_id?: string
  node_executions?: UpgradeNodeExecution[]
}

/** 交付检查结果项 */
export interface DeliveryCheckResultItem {
  item_key: string
  item_name: string
  category?: string
  result: 'PASS' | 'WARNING' | 'FAIL' | 'NOT_APPLICABLE'
  critical?: boolean
  message?: string
  details?: Record<string, unknown> | null
}

/** 交付检查任务 */
export interface DeliveryCheckItem {
  id: string
  overall_result: 'PENDING' | 'PASS' | 'WARNING' | 'FAIL' | string
  total: number
  pass_count: number
  warning_count: number
  fail_count: number
  requested_by?: string | null
  started_at: string
  finished_at?: string | null
}

/** 交付检查详情（含逐项结果） */
export interface DeliveryCheckDetail {
  check: DeliveryCheckItem
  results?: DeliveryCheckResultItem[] | null
}

/** 攻击修复建议（处置知识库） */
export interface EventRemediation {
  attack_type: string
  attack_label: string
  analyze_steps: string[]
  fix_suggestions: string[]
  hardening: string[]
}

/** 修复建议接口返回 */
export interface EventRemediationResult {
  remediation: EventRemediation
  event: {
    id: string
    attack_type: string
    request_uri: string
    rule_ids: number[]
  }
}

/** 自定义头修改规则（请求/返回通用） */
export interface CustomHeaderRule {
  name: string
  method: 'set' | 'add' | 'delete'
  value: string
}

/** 应用级 HTTP 头合规与代理配置（每应用一份）。
 *  下划线请求头由网关内核（Caddy 2.11+，GHSA-f59h-q822-g45g）入口强制丢弃，
 *  始终生效、不可配置，故无对应字段。 */
export interface AppHeaderConfig {
  server_action: 'keep' | 'hide' | 'replace'
  server_value: string
  x_author_action: 'keep' | 'hide' | 'replace'
  x_author_value: string
  x_powered_by_action: 'keep' | 'hide' | 'replace'
  x_powered_by_value: string
  x_frame_options: 'default' | 'inherit' | 'deny' | 'sameorigin' | 'allow_from'
  x_frame_options_url: string
  x_xss_protection: boolean
  vary_user_agent: boolean
  hsts_enabled: boolean
  hsts_max_age: number
  csp_mode: 'off' | 'preset' | 'custom'
  csp_value: string
  response_buffering: boolean
  xff_overwrite: boolean
  host_strip_port: boolean
  accept_encoding_off: boolean
  response_compression_enabled: boolean
  response_compression_encodings: 'zstd,gzip' | 'gzip' | 'zstd'
  redirect_port_rewrite: boolean
  custom_request_rules: CustomHeaderRule[]
  custom_response_rules: CustomHeaderRule[]
}

/** 头合规配置查询返回：configured=false 时 config 为默认值（尚未落库） */
export interface AppHeaderConfigResult {
  configured: boolean
  config: AppHeaderConfig
  version?: number
}

/** 路径粒度转发规则 */
export interface AppPathRoute {
  id: string
  application_id: string
  path_prefix: string
  upstream_scheme: 'http' | 'https' | 'tlcp'
  upstream_host: string
  upstream_port: number
  strip_prefix: boolean
  priority: number
  status: 'ENABLED' | 'DISABLED'
  description: string
  created_at: string
  updated_at: string
  version: number
}

/** 应用级 TLS/国密协议自识别、TLS/HTTP 协议降级与加密会话分析配置 */
export type TLSProtocolMode = 'AUTO_DETECT' | 'INTERNATIONAL_ONLY' | 'GM_ONLY'
export type AllowedTLSVersion = 'TLCP1.1' | 'TLS1.0' | 'TLS1.1' | 'TLS1.2' | 'TLS1.3'
export type LegacySSLAnalysisVersion = 'SSLv2' | 'SSLv2_v3' | 'SSLv3'
export type AppHTTPVersion = 'HTTP/1.0' | 'HTTP/1.1' | 'HTTP/2'
export type UpstreamHTTPVersion = 'AUTO' | 'HTTP/1.0' | 'HTTP/1.1' | 'HTTP/2'
export type UpstreamTLSMinVersion = 'TLS1.0' | 'TLS1.1' | 'TLS1.2' | 'TLS1.3'

export interface AppTLSConfig {
  tls_protocol_mode: TLSProtocolMode
  allowed_tls_versions: AllowedTLSVersion[]
  legacy_ssl_analysis_versions: LegacySSLAnalysisVersion[]
  http_versions: AppHTTPVersion[]
  upstream_http_version: UpstreamHTTPVersion
  upstream_tls_min_version: UpstreamTLSMinVersion
  session_analysis_enabled: boolean
}

export interface AppTLSConfigResult {
  config: AppTLSConfig
  configured: boolean
  version: number
  updated_at?: string
  message?: string
}

/* ==================== 产品侧离线授权（.lic 导入与门控） ==================== */

/** 授权产品形态（'' = 未授权/无有效授权） */
export type LicenseProduct = 'waf' | 'wdsp' | 'api' | ''

/** 授权配额（0 = 不限制；与 server/internal/license Quotas JSON tag 一致） */
export interface LicenseQuotas {
  max_applications: number
  max_api_endpoints: number
  max_qps: number
}

/** 配额当前用量（装配层可选返回；缺失时前端只显示上限） */
export interface LicenseUsage {
  applications: number
  api_endpoints: number
}

/**
 * 授权与实际防护的分维度状态。
 * 这些状态不能由单一的 valid 字段互相推断，缺失时前端必须保持未知。
 */
export type LicenseProtectionForm =
  'STANDARD_OFFLINE' | 'CONFIDENTIAL_COMPUTING' | 'UNKNOWN'

export type LicenseCommercialAuthorization =
  | 'AUTHORIZED'
  | 'NOT_IMPORTED'
  | 'EXPIRED'
  | 'DEVICE_MISMATCH'
  | 'INVALID'
  | 'UNKNOWN'

export type LicenseArtifactIntegrity =
  'VERIFIED' | 'PENDING_MIGRATION' | 'UNVERIFIABLE' | 'FAILED' | 'UNKNOWN'

export type LicenseGatewayProtection =
  'PROTECTED' | 'BYPASS' | 'UNAVAILABLE' | 'PRESERVE_EXISTING' | 'UNKNOWN'

export type LicenseConfidentialComputing =
  'DISABLED' | 'VERIFIED' | 'FAILED' | 'UNSUPPORTED' | 'UNAVAILABLE' | 'UNKNOWN'

export type LicenseRecovery =
  | 'NONE'
  | 'IMPORT_LICENSE'
  | 'REVALIDATE_PACKAGE'
  | 'KEEP_LAST_CONFIG'
  | 'SUPPORT_REQUIRED'
  | 'UNKNOWN'

export type LicenseIntegrityStatus =
  | 'NOT_IMPORTED'
  | 'VERIFIED'
  | 'ORIGINAL_MISSING'
  | 'ENCRYPTION_UNAVAILABLE'
  | 'DECRYPTION_FAILED'
  | 'SIGNATURE_INVALID'
  | 'DB_INCONSISTENT'
  | 'EXPIRED'
  | 'DEVICE_MISMATCH'
  | 'DATABASE_UNAVAILABLE'

export interface LicenseProtectionState {
  schema_version: string
  protection_form: LicenseProtectionForm
  commercial_authorization: LicenseCommercialAuthorization
  artifact_integrity: LicenseArtifactIntegrity
  gateway_protection: LicenseGatewayProtection
  confidential_computing: LicenseConfidentialComputing
  recovery: LicenseRecovery
  reason?: string
}

/** 授权状态（GET /api/v1/license/status 与导入成功响应的 data；字段同 server/internal/license State） */
export interface LicenseState {
  valid: boolean
  /** 生效产品形态；无有效授权时 '' */
  product: LicenseProduct
  quotas: LicenseQuotas
  features: string[]
  /** 到期时间（RFC3339）；null = 永久或无授权 */
  expires_at: string | null
  license_id: string
  customer: string
  license_type: 'FORMAL' | 'TRIAL' | ''
  /** 无效原因（中文）；有效时 '' */
  reason: string
  /** 签名授权原文与数据库缓存的复核状态 */
  integrity_status?: LicenseIntegrityStatus
  /** 本机指纹（sha256:...；未采集时 ''） */
  host_fingerprint: string
  /** 当前用量（可选，装配层补齐后返回） */
  usage?: LicenseUsage
  /** 授权、产物完整性、实际防护和机密计算的分维度状态（后端未提供时保持未知） */
  protection_state?: LicenseProtectionState
}

/** 授权记录状态（licenses.status 词表） */
export type LicenseRecordStatus =
  'ACTIVE' | 'EXPIRED' | 'FINGERPRINT_MISMATCH' | 'SUPERSEDED' | 'INVALID'

/** 授权导入历史项（GET /api/v1/license/history 的 items；字段同 server/internal/license Record，
 *  payload/signature/raw_file 敏感原文后端不出参） */
export interface LicenseHistoryItem {
  id: string
  license_id: string
  license_type: 'FORMAL' | 'TRIAL'
  product: 'waf' | 'wdsp' | 'api'
  customer: string
  status: LicenseRecordStatus
  /** 导入操作人用户 ID；null = 系统 */
  imported_by: string | null
  imported_at: string
  /** 到期日；null = 永久授权 */
  expires_at: string | null
  perpetual: boolean
  machine_fingerprint: string
  quotas: LicenseQuotas
  features: string[]
  created_at: string
}

/** 定时报告周期类型（定时计划仅支持日/周/月，不支持 CUSTOM） */
export type ReportScheduleType = 'DAILY' | 'WEEKLY' | 'MONTHLY'

/** 定时报告计划 */
export interface ReportScheduleItem {
  id: string
  name: string
  report_type: ReportScheduleType
  api_report_type?: string
  content_scope?: ReportContentScope
  application_ids?: string[] | null
  template_id?: string | null
  file_format: 'html' | 'pdf' | 'docx'
  include_api_assets?: boolean
  page_orientation?: 'P' | 'L'
  time_of_day: string
  day_of_week: number
  day_of_month: number
  send_email: boolean
  emails?: string[] | null
  enabled: boolean
  next_run_at?: string | null
  last_run_at?: string | null
  last_job_id?: string | null
  last_email_status?: string
  last_email_error?: string
  created_by?: string | null
  created_at: string
  updated_at: string
}

/* ==================== 业务性能（APM：无 Agent + Agent 模式） ==================== */

/** 观测模式：agentless=无 Agent（网关访问日志与分钟聚合管道产出）；agent=已接入语言 Agent（OTel span） */
export type ApmObservationMode = 'agentless' | 'agent'

/** 时延分位数（毫秒） */
export interface ApmLatency {
  p50: number
  p95: number
  p99: number
}

/** 趋势桶（GET /api/v1/apm/overview 与 /apm/services/{id} 的 trend 元素） */
export interface ApmTrendBucket {
  bucket_start: string
  requests: number
  errors: number
  blocked: number
  p95: number
}

/** Top 应用行（GET /api/v1/apm/overview 的 top_slow_applications/top_error_applications 元素） */
export interface ApmTopApplicationItem {
  application_id: string
  app: string
  name: string
  requests: number
  error_rate: number
  p95: number
}

/** Top 慢端点行（GET /api/v1/apm/overview 的 top_slow_endpoints 元素） */
export interface ApmTopEndpointItem {
  app: string
  endpoint: string
  requests: number
  error_rate: number
  p95: number
}

/** 业务性能总览（GET /api/v1/apm/overview 的 data） */
export interface ApmOverview {
  /** 数据来源标识；阶段1 固定为 agentless（无 Agent） */
  data_source: string
  /** 全量访问日志开关；false 时端点级数据不可用（应用级 RED 不受影响） */
  access_log_enabled: boolean
  start_time: string
  end_time: string
  requests_total: number
  error_5xx_total: number
  error_4xx_total: number
  blocked_total: number
  error_rate: number
  latency: ApmLatency
  trend: ApmTrendBucket[]
  top_slow_applications: ApmTopApplicationItem[]
  top_error_applications: ApmTopApplicationItem[]
  top_slow_endpoints: ApmTopEndpointItem[]
  /** 未归类请求数（路径无法归一化，计入 __UNCLASSIFIED__ 桶） */
  unclassified_requests: number
}

/** 服务（应用）性能行（GET /api/v1/apm/services 的 items 元素） */
export interface ApmServiceItem {
  application_id: string
  app: string
  name: string
  observation_mode: ApmObservationMode
  /** 该服务当前在线 Agent 数（observation_mode=agent 时有意义） */
  agents_online: number
  /** 该服务已注册 Agent 总数 */
  agents_total: number
  requests: number
  error_rate: number
  blocked: number
  p50: number
  p95: number
  p99: number
  last_seen_at: string
}

/** 服务详情（GET /api/v1/apm/services/{id} 的 data） */
export interface ApmServiceDetail {
  application_id: string
  app: string
  name: string
  observation_mode: ApmObservationMode
  requests_total: number
  error_rate: number
  latency: ApmLatency
  trend: ApmTrendBucket[]
  status_classes: { status_class: string; count: number }[]
  actions: { action: string; count: number }[]
  top_endpoints: {
    endpoint: string
    requests: number
    error_rate: number
    p95: number
  }[]
}

/** 端点性能行（GET /api/v1/apm/endpoints 的 list 元素）；
 *  endpoint 可能为特殊桶：__UNCLASSIFIED__（未归类）/ __OTHER__（超出 Top-N 聚合） */
export interface ApmEndpointItem {
  app: string
  application_id: string
  endpoint: string
  method: string
  path_template: string
  requests: number
  error_rate: number
  blocked: number
  p50: number
  p95: number
  p99: number
  last_seen_at: string
}

/** 端点性能分页（GET /api/v1/apm/endpoints 的 data：分页字段 + 访问日志开关） */
export interface ApmEndpointPage {
  list: ApmEndpointItem[]
  total: number
  page: number
  page_size: number
  access_log_enabled: boolean
}

/** Trace 关联访问记录（GET /api/v1/apm/traces/{trace_id} 的 access_logs 元素） */
export interface ApmTraceAccessLog {
  id: string
  occurred_at: string
  request_id: string
  application_id: string | null
  domain: string
  client_ip: string
  request_method: string
  request_uri?: string
  request_path: string
  response_status: number
  duration_ms: number
  ttfb_ms: number | null
  waf_action: string
  span_id?: string | null
  endpoint_key: string | null
  path_template?: string | null
}

/** Trace 关联 WAF 安全事件（GET /api/v1/apm/traces/{trace_id} 的 security_events 元素） */
export interface ApmTraceSecurityEvent {
  id: string
  occurred_at: string
  request_id: string
  application_id?: string | null
  attack_type: string
  severity: string
  action: string
  response_status: number
  request_method: string
  request_uri: string
  rule_match_count: number
  disposition_status: string
}

/* ---------- P1-01 A2：数据质量自述（availability）与关联（correlation） ----------
 * 契约：docs/tasks/wdsp-p1/P1-01_SECURITY_APM_DEMO.md §4.3；词表与 server/internal/apm/types.go 冻结常量一致。
 * 旧后端缺这些字段时（undefined），页面显示「状态信息不足」，不编造原因。 */

/** availability.query_state 词表：READY 有可用数据；EMPTY 成功查询零结果；PARTIAL 部分结果；UNAVAILABLE 存储未配置/不可用 */
export type ApmQueryState = 'READY' | 'EMPTY' | 'PARTIAL' | 'UNAVAILABLE'

/** 数据质量自述（reason_codes/observed_sources 恒为数组；last_*_at/estimated_lag_ms 未知为 null） */
export interface ApmAvailability {
  query_state: ApmQueryState | string
  reason_codes: string[]
  observed_sources: string[]
  last_collected_at: string | null
  last_ingested_at: string | null
  estimated_lag_ms: number | null
  partial: boolean
}

/** 关联候选（一对多时逐候选返回时间/服务/匹配依据，不任取第一条） */
export interface ApmCorrelationCandidate {
  trace_id: string
  occurred_at: string | null
  services: string[]
  match_basis: string
}

/** correlation.state 词表：MATCHED/AMBIGUOUS/PENDING/NOT_FOUND/NOT_EXPECTED/UNKNOWN */
export type ApmCorrelationState =
  'MATCHED' | 'AMBIGUOUS' | 'PENDING' | 'NOT_FOUND' | 'NOT_EXPECTED' | 'UNKNOWN'

/** 关联判定（独立于数据源健康；trace-search 仅 request_id 检索时携带，traces/{id} 恒携带） */
export interface ApmCorrelation {
  state: ApmCorrelationState | string
  match_basis: string
  candidate_count: number
  reason: string
  candidates: ApmCorrelationCandidate[]
}

/** Trace 检索结果（GET /api/v1/apm/traces/{trace_id} 的 data） */
export interface ApmTraceDetail {
  trace_id: string
  access_logs: ApmTraceAccessLog[]
  security_events: ApmTraceSecurityEvent[]
  /** true 表示结果不完整（采样/保留期截断），页面须如实标识 */
  partial: boolean
  note: string
  /** OTel span 列表（Agent 模式）；无 Agent 时为空数组/缺省，页面降级为访问记录视图 */
  otel_spans?: ApmOtelSpan[]
  span_count?: number
  /** true 表示 span 超出返回上限被截断，页面须提示"已截断" */
  truncated?: boolean
  /** 数据来源：agentless=无 Agent；otel=纯 Agent；mixed=混合 */
  data_source?: 'agentless' | 'otel' | 'mixed'
  /** 数据质量自述（P1-01 A2；旧后端缺省为 undefined） */
  availability?: ApmAvailability | null
  /** trace_id 直达关联判定（P1-01 A2，恒携带；旧后端缺省为 undefined） */
  correlation?: ApmCorrelation | null
}

/** OTel span（GET /api/v1/apm/traces/{trace_id} 的 otel_spans 元素；attributes 键值均为字符串） */
export interface ApmOtelSpan {
  span_id: string
  parent_span_id: string
  service_name: string
  operation_name: string
  span_kind: string
  start_time: string
  duration_ms: number
  status_code: string
  attributes: Record<string, string>
}

/** 调用链检索结果行（GET /api/v1/apm/trace-search 的 list 元素） */
export interface ApmTraceSearchItem {
  trace_id: string
  root_service: string
  root_operation: string
  start_time: string
  duration_ms: number
  span_count: number
  error_count: number
  services: string[]
}

/** 调用链检索分页（GET /api/v1/apm/trace-search 的 data；DSN 未配置时 list 为空且 data_source=agentless） */
export interface ApmTraceSearchPage {
  list: ApmTraceSearchItem[]
  total: number
  page: number
  page_size: number
  data_source: string
  /** 降级原因提示/过滤约束说明（P1-01 A2；正常时为空串） */
  message?: string
  /** 数据质量自述（P1-01 A2；旧后端缺省为 undefined） */
  availability?: ApmAvailability | null
  /** 关联判定（P1-01 A2；仅 request_id 检索时携带） */
  correlation?: ApmCorrelation | null
}

/** Agent 状态五态（GET /api/v1/apm/agents 的 status 词表） */
export type ApmAgentStatus =
  'ENROLLING' | 'CONNECTED_BASELINE' | 'DIAGNOSING' | 'OFFLINE' | 'REVOKED'

/** Agent 清单行（GET /api/v1/apm/agents 的 items 元素） */
export interface ApmAgentItem {
  id: string
  service_id?: string
  service_name: string
  instance_id: string
  language: string
  agent_version: string
  sdk_version?: string
  stored_status?: Exclude<ApmAgentStatus, 'OFFLINE'>
  status: ApmAgentStatus
  cert_fingerprint?: string
  last_heartbeat_at: string | null
  cert_not_after: string
  node_info?: Record<string, string>
  registered_at?: string
  revoked_at?: string | null
  revoke_reason?: string
  application_id: string | null
  environment: string
}

/** 一次性注册令牌创建结果（POST /api/v1/apm/agents/enrollment-tokens 的 data；token 原文仅此一次返回） */
export interface ApmEnrollmentTokenResult {
  token_id: string
  /** 令牌原文，仅此一次返回，页面须醒目提示并一次性展示 */
  token: string
  application_id?: string | null
  environment?: string
  allowed_languages?: string[]
  expires_at: string
  note?: string
}

/** Agent 基线策略（GET/PUT /api/v1/apm/policies/{scope}；policy 为 opaque JSON，前端原样编辑） */
export interface ApmPolicyDocument {
  scope: string
  version: number
  issued_at: string
  expires_at: string
  policy: Record<string, unknown>
  signature: string
}

/* ==================== APM 阶段3：SQL / 异常 / 依赖 / 运行时 / SLO ==================== */

/** SQL 指纹聚合行（GET /api/v1/apm/sql 的 list 元素）；
 *  只出指纹不出原始 SQL（APM 设计 §12 数据最小化），sample_trace_ids 用于跳转调用链 */
export interface ApmSqlFingerprintItem {
  sql_fingerprint: string
  db_system: string
  namespace: string
  operation: string
  calls: number
  error_count: number
  avg_ms: number
  p95_ms: number
  sample_trace_ids: string[]
}

/** SQL 指纹分页（GET /api/v1/apm/sql 的 data；data_source=agentless 表示未接入 OTel 数据面） */
export interface ApmSqlPage {
  list: ApmSqlFingerprintItem[]
  total: number
  page: number
  page_size: number
  data_source: string
  /** 后端附言（如数据口径/降级原因），有值时须如实展示 */
  message?: string
  /** 请求侧 trace_id 回显（P1-01 A2；未提供为空串/缺省） */
  trace_id?: string
  /** 定位语义：trace_exact=trace 级精确定位；window_aggregate=窗口聚合（仅为候选） */
  match_mode?: 'trace_exact' | 'window_aggregate' | string
  /** 匹配语义说明（window_aggregate 时如实标注「非特定请求定位」），有值时须如实展示 */
  match_note?: string
  /** 数据质量自述（P1-01 A2；旧后端缺省为 undefined） */
  availability?: ApmAvailability | null
}

/** 异常指纹聚合行（GET /api/v1/apm/exceptions 的 list 元素） */
export interface ApmExceptionItem {
  exception_type: string
  fingerprint: string
  count: number
  first_seen_at: string
  last_seen_at: string
  affected_services: string[]
  sample_trace_ids: string[]
}

/** trace 级异常明细（GET /api/v1/apm/exceptions 的 trace_exceptions 元素，仅 trace_exact 模式）；
 *  exception_message/stacktrace 为后端掩码+截断后的纯文本，前端一律按纯文本渲染并再限长 */
export interface ApmExceptionTraceItem {
  trace_id: string
  span_id: string
  service_name: string
  occurred_at: string
  exception_type: string
  exception_message: string
  stacktrace: string
  fingerprint: string
  message_truncated: boolean
  stacktrace_truncated: boolean
}

/** 异常指纹分页（GET /api/v1/apm/exceptions 的 data） */
export interface ApmExceptionPage {
  list: ApmExceptionItem[]
  total: number
  page: number
  page_size: number
  data_source: string
  /** 降级原因提示（P1-01 A2；正常时为空串） */
  message?: string
  /** 请求侧 trace_id 回显（P1-01 A2；未提供为空串/缺省） */
  trace_id?: string
  /** 定位语义：trace_exact=trace 级精确定位；window_aggregate=窗口聚合（仅为候选） */
  match_mode?: 'trace_exact' | 'window_aggregate' | string
  /** 匹配语义说明，有值时须如实展示 */
  match_note?: string
  /** trace 级精确定位结果（仅 trace_exact 模式；窗口模式为空数组/缺省） */
  trace_exceptions?: ApmExceptionTraceItem[]
  /** 数据质量自述（P1-01 A2；旧后端缺省为 undefined） */
  availability?: ApmAvailability | null
}

/** 依赖目标类型（GET /api/v1/apm/dependencies 的 target_type 词表） */
export type ApmDependencyTargetType =
  'service' | 'db' | 'messaging' | 'external'

/** 依赖边（GET /api/v1/apm/dependencies 的 edges 元素） */
export interface ApmDependencyEdge {
  source: string
  target: string
  target_type: ApmDependencyTargetType
  calls: number
  error_rate: number
  avg_ms: number
}

/** 依赖关系（GET /api/v1/apm/dependencies 的 data） */
export interface ApmDependencyGraph {
  edges: ApmDependencyEdge[]
  data_source: string
  /** 口径说明（如"基于客户端 span 单视角派生"），有值时须如实展示 */
  note?: string
}

/** 运行时指标采样点（GET /api/v1/apm/runtime 的 points 元素；每指标 ≤200 点） */
export interface ApmRuntimeMetricPoint {
  ts: string
  value: number
}

/** 运行时指标（name/unit/description 因语言而异，如实展示；每实例 ≤20 个指标） */
export interface ApmRuntimeMetric {
  name: string
  unit: string
  description: string
  latest_value: number
  points: ApmRuntimeMetricPoint[]
}

/** 运行时实例（GET /api/v1/apm/runtime 的 instances 元素） */
export interface ApmRuntimeInstance {
  instance_id: string
  service_name: string
  metrics: ApmRuntimeMetric[]
}

/** 运行时指标总览（GET /api/v1/apm/runtime 的 data） */
export interface ApmRuntimeOverview {
  data_source: string
  instances: ApmRuntimeInstance[]
  /** 口径说明，有值时须如实展示 */
  note?: string
}

/** SLO 指标类型（GET/POST/PUT /api/v1/apm/slos 的 metric_type 词表） */
export type ApmSloMetricType = 'availability' | 'latency_p95'

/** SLO 状态三态（OK=达标 / AT_RISK=有风险 / BREACHED=已违约） */
export type ApmSloStatus = 'OK' | 'AT_RISK' | 'BREACHED'

/** SLO 行（GET /api/v1/apm/slos 的 list 元素） */
export interface ApmSloItem {
  id: string
  name: string
  service: string
  metric_type: ApmSloMetricType
  /** 目标阈值（availability 为 0-1 比例，如 0.999 表示 99.9%；latency_p95 为毫秒阈值） */
  target: number
  /** 评估窗口（如 7d / 30d） */
  window: string
  current_value: number
  /** 达标率（0-1） */
  compliance_ratio: number
  /** 剩余错误预算（0-1） */
  error_budget_remaining: number
  status: ApmSloStatus
  updated_at: string
}

/** SLO 清单（GET /api/v1/apm/slos 的 data） */
export interface ApmSloList {
  list: ApmSloItem[]
  total: number
}

/** SLO 达标率趋势桶（GET /api/v1/apm/slos/{id} 的 trend 元素） */
export interface ApmSloTrendBucket {
  bucket_start: string
  compliance_ratio: number
}

/** SLO 详情（GET /api/v1/apm/slos/{id} 的 data：清单字段 + 达标率趋势） */
export interface ApmSloDetail extends ApmSloItem {
  trend: ApmSloTrendBucket[]
}

/* ==================== APM 阶段4：深度诊断中心 ==================== */

/** 诊断能力词表（POST /api/v1/apm/diagnostic-sessions 的 capabilities 枚举） */
export type ApmDiagnosticCapability =
  'sql_detail' | 'function_probe' | 'thread_block' | 'gc_detail' | 'mq_wait'

/** 诊断会话状态四态（ACTIVE=进行中 / EXPIRED=到期自动结束 / STOPPED=人工停止 / KILLED=kill switch 熔断） */
export type ApmDiagnosticSessionStatus =
  'ACTIVE' | 'EXPIRED' | 'STOPPED' | 'KILLED'

/** 诊断范围（diagnostic-sessions 的 scope；深度诊断默认仅选定实例，见设计 §21.2） */
export interface ApmDiagnosticScope {
  application_id: string
  service?: string
  environment?: string
  instance_ids?: string[]
}

/** 诊断会话行（GET /api/v1/apm/diagnostic-sessions 的 items 元素） */
export interface ApmDiagnosticSession {
  id: string
  scope: ApmDiagnosticScope
  capabilities: ApmDiagnosticCapability[]
  /** 采样率（0-1 小数） */
  sampling_rate: number
  duration_minutes: number
  status: ApmDiagnosticSessionStatus
  created_by: string | null
  created_at: string
  expires_at: string
  stopped_at?: string | null
  stopped_by?: string | null
  stop_reason?: string | null
  policy_version?: number
  baseline_restored?: boolean
}

/** 诊断会话分页（GET /api/v1/apm/diagnostic-sessions 的 data；kill_switch_enabled=true 时新建会话被拒绝） */
export interface ApmDiagnosticSessionPage {
  items: ApmDiagnosticSession[]
  total: number
  page: number
  page_size: number
  kill_switch_enabled: boolean
}

/** 诊断审计条目（GET /api/v1/apm/diagnostic-sessions/{id} 的 audits 元素） */
export interface ApmDiagnosticAudit {
  id: string
  occurred_at: string
  user_id?: string | null
  username: string
  source_ip?: string
  connection_ip?: string
  user_agent_summary?: string
  module?: string
  action: string
  object_type?: string
  object_id?: string
  object_name?: string
  before_summary?: string
  after_summary?: string
  result?: 'SUCCESS' | 'FAILURE' | string
  failure_reason?: string
  risk_level?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string
  request_id?: string
}

/** 诊断会话详情（GET /api/v1/apm/diagnostic-sessions/{id} 的 data：会话全字段 + 关联审计） */
export interface ApmDiagnosticSessionDetail extends ApmDiagnosticSession {
  audits: ApmDiagnosticAudit[]
}

/** dry_run 预估开销（POST /api/v1/apm/diagnostic-sessions dry_run=true 的 data.estimated_overhead） */
export interface ApmDiagnosticOverhead {
  cpu_hint: string
  spans_per_s_hint: string
  data_volume_hint: string
  risk_notes: string[]
}

/** dry_run 响应（POST /api/v1/apm/diagnostic-sessions dry_run=true 的 data） */
export interface ApmDiagnosticDryRunResult {
  estimated_overhead: ApmDiagnosticOverhead
}
