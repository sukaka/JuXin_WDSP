import { request } from './client'
import type { PageResult } from '../types'

/** 身份类型（与 server 端 security/identities 词表一致） */
export type IdentityType = 'UNKNOWN' | 'HUMAN' | 'BOT' | 'APPLICATION' | 'SERVICE' | 'MACHINE' | 'AGENT'

/** 身份风险等级 */
export type IdentityRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

/** 行为检测信号（十种） */
export type BehaviorSignal =
  | 'URI_ENUMERATION'
  | 'NOT_FOUND_ENUMERATION'
  | 'SENSITIVE_PATH_PROBE'
  | 'METHOD_ENUMERATION'
  | 'PARAMETER_MUTATION'
  | 'AUTH_FAIL_PROBE'
  | 'LOW_SLOW_RECON'
  | 'HEADLESS'
  | 'ACCOUNT_ENUMERATION'
  | 'OBJECT_ENUMERATION'

export interface IdentityItem {
  id: string
  identity_key: string
  identity_type: IdentityType
  identity_confidence: number
  risk_score: number
  risk_level: IdentityRiskLevel
  status: string
  primary_ip: string
  ip_count: number
  account_id: string
  request_count: number
  first_seen_at: string
  last_seen_at: string
}

export interface IdentityIpHistoryItem {
  ip: string
  first_seen_at: string
  last_seen_at: string
  request_count: number
}

export interface IdentityCredentialItem {
  credential_type: string
  credential_hash: string
  first_seen_at: string
  last_seen_at: string
}

/** 身份详情内嵌的近期事件（字段为行为事件接口的子集） */
export interface IdentityRecentEventItem {
  id: string
  occurred_at: string
  signal: BehaviorSignal
  identity_confidence?: number
  identity_evidence?: string[]
  rule_code: string
  rule_version: string
  risk_score_delta: number
  mode: string
  reason: string
  client_ip: string
  method: string
  path: string
}

export interface IdentityDetail {
  id: string
  identity_key: string
  identity_type: IdentityType
  identity_confidence: number
  confidence_source: string[]
  risk_score: number
  risk_level: IdentityRiskLevel
  status: string
  primary_ip: string
  asn: string
  tls_fingerprint: string
  browser_fingerprint: string
  account_id: string
  jwt_subject: string
  api_key_hash: string
  oauth_client_id: string
  device_type: string
  request_count: number
  first_seen_at: string
  last_seen_at: string
  created_at: string
  updated_at: string
  ip_history: IdentityIpHistoryItem[]
  credentials: IdentityCredentialItem[]
  recent_events: IdentityRecentEventItem[]
}

export type BehaviorWindowType = '1m' | '5m' | '30m' | '24h'

export interface IdentityBehaviorItem {
  window_type: BehaviorWindowType
  window_start: string
  request_count: number
  unique_uri_count: number
  new_uri_count: number
  status_401_count: number
  status_403_count: number
  status_404_count: number
  status_405_count: number
  status_500_count: number
  auth_fail_count: number
  parameter_mutation_count: number
  sensitive_path_hits: number
  account_enum_count: number
  object_enum_count: number
}

export interface IdentityEventItem {
  id: string
  occurred_at: string
  event_kind: string
  rule_code: string
  rule_version: string
  signal: BehaviorSignal
  risk_score_delta: number
  mode: string
  reason: string
  window: string
  metadata: Record<string, unknown>
  request_id: string
  client_ip: string
  method: string
  path: string
  app_id: string
  domain: string
  gateway_node: string
  identity_confidence: number
  identity_evidence: string[]
}

export interface IdentityListParams {
  risk_level?: string
  identity_type?: string
  keyword?: string
  ip?: string
  from?: string
  to?: string
  page: number
  page_size: number
}

export interface IdentityBehaviorParams {
  window?: string
  from?: string
  to?: string
  page?: number
  page_size?: number
}

export interface IdentityEventListParams {
  signal?: string
  from?: string
  to?: string
  page: number
  page_size: number
}

export const securityIdentitiesApi = {
  list: async (params: IdentityListParams) => {
    const data = await request<PageResult<IdentityItem>>('/security/identities', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: async (id: string) => {
    // 后端响应为 { identity, ip_history, credentials, recent_events } 包裹结构；
    // 无历史/凭据/事件时为 null（Go nil slice），统一归一化为空数组
    const data = await request<{
      identity: Omit<IdentityDetail, 'ip_history' | 'credentials' | 'recent_events'>
      ip_history: IdentityIpHistoryItem[] | null
      credentials: IdentityCredentialItem[] | null
      recent_events: IdentityRecentEventItem[] | null
    }>(`/security/identities/${id}`)
    return {
      ...data.identity,
      confidence_source: data.identity.confidence_source ?? [],
      ip_history: data.ip_history ?? [],
      credentials: data.credentials ?? [],
      recent_events: data.recent_events ?? [],
    }
  },
  behavior: async (id: string, params: IdentityBehaviorParams = {}) => {
    const data = await request<PageResult<IdentityBehaviorItem>>(
      `/security/identities/${id}/behavior`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  events: async (id: string, params: IdentityEventListParams) => {
    const data = await request<PageResult<IdentityEventItem>>(`/security/identities/${id}/events`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}
