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
