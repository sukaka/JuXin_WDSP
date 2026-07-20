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
