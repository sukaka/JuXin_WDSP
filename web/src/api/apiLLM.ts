import { request } from './client'
import type { PageResult } from '../types'

/* ==================== LLM API 观测（server/internal/apillm）：观测明细 / 统计 ==================== */

/** 检测明细（与网关 dsctx.DetectorMatch JSON 契约一致；证据已脱敏，不含原文） */
export interface ApiLLMDetectorMatch {
  detector: string
  rule_id?: string
  category?: string
  severity?: string
  message?: string
  evidence?: Record<string, string>
  score_delta?: number
}

/** LLM 观测行（api_llm_observations） */
export interface ApiLLMObservation {
  id: string
  occurred_at: string
  endpoint_key: string
  model: string
  /** 身份指纹（匿名流量为空串） */
  identity_fingerprint: string
  /** prompt 长度桶（如 0/1-256/257-1024/...；原始 prompt 不采集） */
  prompt_len_bucket: string
  /** token 用量（0 = 流式/缺失未采集到） */
  total_tokens: number
  stream: boolean
  /** MCP JSON-RPC 方法名（空 = 非 MCP 端点或响应对象） */
  mcp_method: string
  /** llm.* 检测明细（涉敏/异常命中口径） */
  findings: ApiLLMDetectorMatch[] | null
  created_at: string
}

/** 汇总：观测数/带命中观测数/token 合计/流式调用数/涉及模型数 */
export interface ApiLLMStatsSummary {
  observations: number
  with_findings: number
  total_tokens: number
  stream_calls: number
  distinct_models: number
}

/** 模型分布（按观测数聚合；空串 = 未声明模型单列一组） */
export interface ApiLLMModelStat {
  model: string
  observations: number
  total_tokens: number
  findings: number
}

/** token 用量趋势点（按天聚合） */
export interface ApiLLMTokenTrendPoint {
  day: string
  observations: number
  total_tokens: number
}

/** 命中规则分布（findings 按 rule_id 计数） */
export interface ApiLLMFindingRuleStat {
  rule_id: string
  count: number
}

/** LLM 观测统计（窗口按 occurred_at 口径，与列表明细同窗口） */
export interface ApiLLMStats {
  days: number
  summary: ApiLLMStatsSummary
  by_model: ApiLLMModelStat[]
  token_trend: ApiLLMTokenTrendPoint[]
  findings_by_rule: ApiLLMFindingRuleStat[]
}

export interface ApiLLMSecurityPolicy {
  id: string
  application_id: string
  name: string
  mode: 'OBSERVE' | 'PROTECT'
  prompt_injection_enabled: boolean
  input_content_enabled: boolean
  pii_detection_enabled: boolean
  output_content_enabled: boolean
  output_pii_enabled: boolean
  blocked_topics: string[]
  max_prompt_bytes: number
  max_output_tokens: number
  enabled: boolean
  version: number
  created_at: string
  updated_at: string
}

export interface ApiLLMSecurityPolicyInput {
  application_id?: string
  name?: string
  mode?: 'OBSERVE' | 'PROTECT'
  prompt_injection_enabled?: boolean
  input_content_enabled?: boolean
  pii_detection_enabled?: boolean
  output_content_enabled?: boolean
  output_pii_enabled?: boolean
  blocked_topics?: string[]
  max_prompt_bytes?: number
  max_output_tokens?: number
  enabled?: boolean
}

export interface ApiLLMSecurityPolicyVersion {
  id: string
  policy_id: string
  version: number
  policy_snapshot: ApiLLMSecurityPolicy
  created_at: string
}

export interface ApiLLMBuiltinRuleItem {
  id: string
  name: string
  description: string
  pattern: string
  engine_rule_id: string
  observe_action: string
  protect_action: string
}

export interface ApiLLMBuiltinRuleCategory {
  key: 'prompt_injection' | 'content_filter' | 'pii_detection' | string
  title: string
  scope: string
  policy_switches: string[]
  inspected_paths: string[]
  notes: string
  rules: ApiLLMBuiltinRuleItem[]
}

export interface ApiLLMBuiltinRulesCatalog {
  prompt_paths: string[]
  output_paths: string[]
  max_output_texts: number
  max_output_text_bytes: number
  categories: ApiLLMBuiltinRuleCategory[]
}

export const apiLLMApi = {
  /** 明细分页（model/endpoint_key 精确过滤，findings_only=true 仅命中观测；days 默认 7 上限 30） */
  listObservations: async (params: {
    days?: number
    model?: string
    endpoint_key?: string
    findings_only?: boolean
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiLLMObservation>>(
      `/api-security/llm/observations`,
      {
        query: { ...params },
      },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** 统计（模型分布/token 用量趋势/涉敏命中计数；days 默认 7 上限 30） */
  stats: (days?: number) =>
    request<ApiLLMStats>(`/api-security/llm/stats`, { query: { days } }),
  listSecurityPolicies: async () => {
    const data = await request<{
      items: ApiLLMSecurityPolicy[]
      total: number
    }>(`/api-security/llm/security-policies`)
    return { ...data, items: data.items ?? [] }
  },
  createSecurityPolicy: (body: ApiLLMSecurityPolicyInput) =>
    request<ApiLLMSecurityPolicy>(`/api-security/llm/security-policies`, {
      method: 'POST',
      body,
    }),
  updateSecurityPolicy: (id: string, body: ApiLLMSecurityPolicyInput) =>
    request<ApiLLMSecurityPolicy>(`/api-security/llm/security-policies/${id}`, {
      method: 'PATCH',
      body,
    }),
  deleteSecurityPolicy: (id: string) =>
    request<{ status: string }>(`/api-security/llm/security-policies/${id}`, {
      method: 'DELETE',
    }),
  listSecurityPolicyVersions: async (id: string) => {
    const data = await request<{
      items: ApiLLMSecurityPolicyVersion[]
      total: number
    }>(`/api-security/llm/security-policies/${id}/versions`)
    return { ...data, items: data.items ?? [] }
  },
  getBuiltinRules: async () => {
    const data = await request<ApiLLMBuiltinRulesCatalog>(
      `/api-security/llm/security-policies/builtin-rules`,
    )
    return {
      ...data,
      prompt_paths: data.prompt_paths ?? [],
      output_paths: data.output_paths ?? [],
      categories: data.categories ?? [],
    }
  },
}
