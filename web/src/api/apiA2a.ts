import { request } from './client'

/**
 * A2A 协议安全网关与 Agent 物料清单（AgBOM）管理面客户端（WDSP Phase 9C-1）。
 * 应用策略路由：GET/PUT /applications/{id}/a2a-policy。
 * AgBOM 台账：GET/POST /api-security/a2a/agents、PUT/DELETE /api-security/a2a/agents/{id}。
 * 安全事件：GET /api-security/a2a/events。
 * 权限：api_a2a.read（只读）/ api_a2a.manage（管理写操作）。
 */

export type A2aPolicyMode = 'OFF' | 'OBSERVE' | 'PROTECT'
export type A2aPolicyState = 'NOT_CONFIGURED' | 'DRAFT_PENDING' | 'PUBLISHED'
export type A2aAgentStatus = 'DISCOVERED' | 'APPROVED' | 'BLOCKED'
export type A2aEventType =
  | 'A2A_AGENT_CARD_DISCOVERED'
  | 'A2A_OBSERVED'
  | 'A2A_BLOCKED'
  | 'A2A_LOOP_KILLED'
  | 'A2A_LETHAL_TRIFECTA'
export type A2aRuleId =
  | 'a2a.caller_agent_denied'
  | 'a2a.delegation_depth_exceeded'
  | 'a2a.delegation_scope_escalation'
  | 'a2a.recursive_loop_detected'
  | 'a2a.lethal_trifecta_blocked'

/** 前后端共享校验上限常量（与 server/internal/apia2a/validate.go 严格对齐） */
export const API_A2A_LIMITS = {
  maxPathPrefixes: 32,
  maxPathLen: 256,
  maxAllowedAgents: 64,
  maxAgentNameLen: 128,
  minDelegationDepth: 1,
  maxDelegationDepth: 10,
  defaultDelegationDepth: 3,
  minLoopWindow: 5,
  maxLoopWindow: 3600,
  defaultLoopWindow: 60,
  minMaxCalls: 1,
  maxMaxCalls: 10000,
  defaultMaxCalls: 20,
  maxPatterns: 64,
  maxPatternLen: 256,
  maxReasonLen: 500,
  maxDescriptionLen: 2000,
  maxAgbomAgentNameLen: 256,
  maxAgentUrlLen: 2048,
  maxAgentVersionLen: 64,
  maxSkills: 64,
  maxSkillLen: 128,
  maxAuthSchemes: 16,
  maxAuthSchemeLen: 64,
} as const

/** 应用级 A2A 协议安全策略 */
export interface A2aPolicy {
  id: string
  schema_version?: number
  application_id: string
  mode: A2aPolicyMode
  version: number
  card_discovery_enabled: boolean
  a2a_path_prefixes: string[]
  allowed_caller_agents: string[]
  max_delegation_depth: number
  enforce_scope_attenuation: boolean
  loop_window_seconds: number
  max_calls_per_task_window: number
  lethal_trifecta_enabled: boolean
  confidential_read_patterns: string[]
  external_egress_patterns: string[]
  updated_by: string
  created_at: string
  updated_at: string
}

/** 策略草稿/发布版本摘要 */
export interface A2aPolicySummary {
  state: A2aPolicyState
  draft_version: number
  published_version: number
}

export interface A2aPolicyGetResult {
  policy: A2aPolicy
  summary: A2aPolicySummary
}

/** PUT 应用级 A2A 策略载荷（expected_version 乐观锁 + reason 审计） */
export interface A2aPolicyUpdateBody {
  mode: A2aPolicyMode
  expected_version: number
  card_discovery_enabled: boolean
  a2a_path_prefixes: string[]
  allowed_caller_agents: string[]
  max_delegation_depth: number
  enforce_scope_attenuation: boolean
  loop_window_seconds: number
  max_calls_per_task_window: number
  lethal_trifecta_enabled: boolean
  confidential_read_patterns: string[]
  external_egress_patterns: string[]
  reason: string
}

/** AgBOM Agent 物料清单条目 */
export interface A2aAgentItem {
  id: string
  application_id: string
  application_code?: string
  application_name?: string
  agent_name: string
  agent_url: string
  agent_version: string
  status: A2aAgentStatus | string
  description: string
  skills: string[]
  allowed_skills: string[]
  auth_schemes: string[]
  first_seen_at?: string | null
  last_seen_at?: string | null
  observed_count: number
  created_at: string
  updated_at: string
}

export interface A2aAgentListParams {
  application_id?: string
  status?: string
  keyword?: string
  page?: number
  page_size?: number
}

export interface A2aAgentListResult {
  items: A2aAgentItem[]
  total: number
  page: number
  page_size: number
}

export interface A2aAgentCreateBody {
  application_id: string
  agent_name: string
  agent_url: string
  agent_version: string
  status: A2aAgentStatus
  description: string
  skills: string[]
  allowed_skills: string[]
  auth_schemes: string[]
}

export interface A2aAgentUpdateBody {
  status: A2aAgentStatus
  description: string
  allowed_skills: string[]
}

export interface A2aAgentDeleteResult {
  deleted: boolean
  id: string
}

/** A2A 安全事件（委派越权/递归循环/致命三要素/观测） */
export interface A2aEventItem {
  id: string
  application_id: string
  application_code?: string
  application_name?: string
  request_id: string
  occurred_at: string
  event_type: A2aEventType | string
  method: string
  agent_name: string
  delegation_depth: number
  rule_id: A2aRuleId | string
  action_taken: string
  reason: string
  client_ip: string
  created_at: string
}

export interface A2aEventListParams {
  application_id?: string
  event_type?: string
  rule_id?: string
  page?: number
  page_size?: number
}

export interface A2aEventListResult {
  items: A2aEventItem[]
  total: number
  page: number
  page_size: number
}

function normalizePolicy(p: A2aPolicy): A2aPolicy {
  return {
    ...p,
    mode: p.mode ?? 'OFF',
    version: p.version ?? 0,
    card_discovery_enabled: Boolean(p.card_discovery_enabled),
    a2a_path_prefixes: p.a2a_path_prefixes ?? [],
    allowed_caller_agents: p.allowed_caller_agents ?? [],
    max_delegation_depth:
      typeof p.max_delegation_depth === 'number' && p.max_delegation_depth > 0
        ? p.max_delegation_depth
        : API_A2A_LIMITS.defaultDelegationDepth,
    enforce_scope_attenuation: Boolean(p.enforce_scope_attenuation),
    loop_window_seconds:
      typeof p.loop_window_seconds === 'number' && p.loop_window_seconds > 0
        ? p.loop_window_seconds
        : API_A2A_LIMITS.defaultLoopWindow,
    max_calls_per_task_window:
      typeof p.max_calls_per_task_window === 'number' &&
      p.max_calls_per_task_window > 0
        ? p.max_calls_per_task_window
        : API_A2A_LIMITS.defaultMaxCalls,
    lethal_trifecta_enabled: Boolean(p.lethal_trifecta_enabled),
    confidential_read_patterns: p.confidential_read_patterns ?? [],
    external_egress_patterns: p.external_egress_patterns ?? [],
    updated_by: p.updated_by ?? '',
    created_at: p.created_at ?? '',
    updated_at: p.updated_at ?? '',
  }
}

function normalizeAgent(a: A2aAgentItem): A2aAgentItem {
  return {
    ...a,
    agent_name: a.agent_name ?? '',
    agent_url: a.agent_url ?? '',
    agent_version: a.agent_version ?? '',
    status: a.status ?? 'DISCOVERED',
    description: a.description ?? '',
    skills: a.skills ?? [],
    allowed_skills: a.allowed_skills ?? [],
    auth_schemes: a.auth_schemes ?? [],
    observed_count: a.observed_count ?? 0,
    created_at: a.created_at ?? '',
    updated_at: a.updated_at ?? '',
  }
}

function normalizeEvent(e: A2aEventItem): A2aEventItem {
  return {
    ...e,
    request_id: e.request_id ?? '',
    occurred_at: e.occurred_at ?? '',
    event_type: e.event_type ?? 'A2A_OBSERVED',
    method: e.method ?? '',
    agent_name: e.agent_name ?? '',
    delegation_depth: e.delegation_depth ?? 0,
    rule_id: e.rule_id ?? '',
    action_taken: e.action_taken ?? '',
    reason: e.reason ?? '',
    client_ip: e.client_ip ?? '',
    created_at: e.created_at ?? '',
  }
}

export const apiA2aApi = {
  getPolicy: async (appId: string): Promise<A2aPolicyGetResult> => {
    const data = await request<A2aPolicyGetResult>(
      `/applications/${appId}/a2a-policy`,
    )
    return {
      ...data,
      policy: normalizePolicy(data.policy),
    }
  },

  updatePolicy: async (
    appId: string,
    body: A2aPolicyUpdateBody,
  ): Promise<A2aPolicy> => {
    const data = await request<{ policy: A2aPolicy }>(
      `/applications/${appId}/a2a-policy`,
      { method: 'PUT', body },
    )
    return normalizePolicy(data.policy)
  },

  listAgents: async (
    params: A2aAgentListParams = {},
  ): Promise<A2aAgentListResult> => {
    const data = await request<A2aAgentListResult>('/api-security/a2a/agents', {
      query: { ...params },
    })
    return {
      items: (data?.items ?? []).map(normalizeAgent),
      total: data?.total ?? 0,
      page: data?.page ?? params.page ?? 1,
      page_size: data?.page_size ?? params.page_size ?? 20,
    }
  },

  createAgent: async (body: A2aAgentCreateBody): Promise<A2aAgentItem> => {
    const data = await request<{ agent: A2aAgentItem }>(
      '/api-security/a2a/agents',
      { method: 'POST', body },
    )
    return normalizeAgent(data.agent)
  },

  updateAgent: async (
    id: string,
    body: A2aAgentUpdateBody,
  ): Promise<A2aAgentItem> => {
    const data = await request<{ agent: A2aAgentItem }>(
      `/api-security/a2a/agents/${id}`,
      { method: 'PUT', body },
    )
    return normalizeAgent(data.agent)
  },

  deleteAgent: async (id: string): Promise<A2aAgentDeleteResult> => {
    return request<A2aAgentDeleteResult>(`/api-security/a2a/agents/${id}`, {
      method: 'DELETE',
    })
  },

  listEvents: async (
    params: A2aEventListParams = {},
  ): Promise<A2aEventListResult> => {
    const data = await request<A2aEventListResult>('/api-security/a2a/events', {
      query: { ...params },
    })
    return {
      items: (data?.items ?? []).map(normalizeEvent),
      total: data?.total ?? 0,
      page: data?.page ?? params.page ?? 1,
      page_size: data?.page_size ?? params.page_size ?? 20,
    }
  },
}
