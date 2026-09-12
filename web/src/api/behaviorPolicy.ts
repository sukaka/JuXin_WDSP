import { request } from './client'

/**
 * 行为策略（全局单例）：阈值/分值/白名单全量读写，version 乐观锁。
 * 与 GET/PUT /security/behavior-policy 契约一致。
 */
export interface BehaviorPolicy {
  id: string
  scope: string
  enabled: boolean
  mode: string
  version: number
  uri_enum_unique_threshold: number
  uri_enum_new_ratio_threshold: number
  not_found_ratio_threshold: number
  not_found_min_requests: number
  method_enum_threshold: number
  param_mutation_threshold: number
  auth_fail_threshold: number
  low_slow_sensitive_min_hits: number
  account_enum_threshold: number
  object_enum_threshold: number
  account_identifier_fields: string[]
  object_identifier_fields: string[]
  sensitive_paths: string[]
  scores: Record<string, number>
  whitelist_ips: string[]
  whitelist_uas: string[]
  updated_by: string
  updated_at: string
}

/** PUT 全量提交体：剔除只读字段（id/updated_by/updated_at） */
export type BehaviorPolicyBody = Omit<BehaviorPolicy, 'id' | 'updated_by' | 'updated_at'>

export const behaviorPolicyApi = {
  get: async () => {
    // 后端响应为 { policy: {...} } 包裹（见 openapi fragments/13），此处解包；
    // 空数组/空 map 可能返回 null（Go nil），统一归一化
    const data = await request<{ policy: BehaviorPolicy }>('/security/behavior-policy')
    const p = data.policy
    return {
      ...p,
      sensitive_paths: p.sensitive_paths ?? [],
      scores: p.scores ?? {},
      whitelist_ips: p.whitelist_ips ?? [],
      whitelist_uas: p.whitelist_uas ?? [],
      account_identifier_fields: p.account_identifier_fields ?? [],
      object_identifier_fields: p.object_identifier_fields ?? [],
    }
  },
  update: async (body: BehaviorPolicyBody) => {
    const data = await request<{ policy: BehaviorPolicy }>('/security/behavior-policy', { method: 'PUT', body })
    return data.policy
  },
}
