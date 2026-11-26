import { request } from './client'

/**
 * 本地离线 ONNX/SLM 语义防火墙管理面客户端（WDSP Phase 9C-2）。
 * Sidecar 状态探测：GET /semantic-guard/status（可选 query socket_path）。
 * 应用级策略路由：GET/PUT /applications/{id}/semantic-guard-policy。
 * 权限：semantic_guard.read（只读）/ semantic_guard.manage（管理写操作）。
 */

export type SemanticGuardMode = 'OFF' | 'OBSERVE' | 'PROTECT'
export type SemanticGuardPolicyState =
  | 'NOT_CONFIGURED'
  | 'DRAFT_PENDING'
  | 'PUBLISHED'
export type SemanticGuardFailPolicy = 'FAIL_OPEN' | 'FAIL_CLOSED'
export type SemanticGuardBackend = 'onnxruntime' | 'heuristic_fallback'
export type SemanticGuardEventType =
  | 'SEMANTIC_OBSERVED'
  | 'SEMANTIC_BLOCKED'
  | 'SEMANTIC_UNAVAILABLE'
export type SemanticGuardRuleId =
  | 'semantic.prompt_injection'
  | 'semantic.jailbreak'
  | 'semantic.indirect_injection'
  | 'semantic.web_payload'
  | 'semantic.sidecar_unavailable'

/** 前后端共享校验上限常量（与 server/internal/semanticguard/validate.go 及 gateway/dynamic_security/semantic/policy.go 严格对齐） */
export const SEMANTIC_GUARD_LIMITS = {
  minTimeoutMs: 5,
  maxTimeoutMs: 200,
  defaultTimeoutMs: 15,
  minMaxConcurrency: 1,
  maxMaxConcurrency: 256,
  defaultMaxConcurrency: 32,
  minMaxInputRunes: 256,
  maxMaxInputRunes: 8192,
  defaultMaxInputRunes: 4096,
  minObserveThreshold: 0.1,
  maxObserveThreshold: 0.99,
  defaultObserveThreshold: 0.5,
  minBlockThreshold: 0.5,
  maxBlockThreshold: 0.99,
  defaultBlockThreshold: 0.85,
  minCircuitFailureThreshold: 1,
  maxCircuitFailureThreshold: 100,
  defaultCircuitFailureThreshold: 5,
  minCircuitOpenSeconds: 5,
  maxCircuitOpenSeconds: 300,
  defaultCircuitOpenSeconds: 30,
  defaultSocketPath: '/var/run/caddy/sidecars/semantic.sock',
  allowedSocketPrefixes: [
    '/var/run/caddy/sidecars/',
    '/run/jiuzhang/',
  ] as const,
  maxSocketPathLen: 256,
  maxReasonLen: 500,
} as const

/** 本地语义防火墙 Sidecar 实时状态（GET /semantic-guard/status） */
export interface SemanticGuardStatus {
  available: boolean
  status: string
  socket_path: string
  model_id: string
  model_sha256: string
  backend: SemanticGuardBackend | string
  error?: string
}

/** 应用级本地语义防火墙策略 */
export interface SemanticGuardPolicy {
  id: string
  schema_version?: number
  application_id: string
  mode: SemanticGuardMode
  version: number
  socket_path: string
  timeout_ms: number
  max_concurrency: number
  max_input_runes: number
  block_threshold: number
  observe_threshold: number
  fail_policy: SemanticGuardFailPolicy
  inspect_llm_prompts: boolean
  inspect_mcp_content: boolean
  inspect_web_grayzone: boolean
  circuit_failure_threshold: number
  circuit_open_seconds: number
  updated_by: string
  created_at: string
  updated_at: string
}

/** 策略草稿/发布版本摘要 */
export interface SemanticGuardPolicySummary {
  state: SemanticGuardPolicyState
  draft_version: number
  published_version: number
}

export interface SemanticGuardPolicyGetResult {
  policy: SemanticGuardPolicy
  summary: SemanticGuardPolicySummary
}

/** PUT 应用级本地语义防火墙策略载荷（expected_version 乐观锁 + reason 审计） */
export interface SemanticGuardPolicyUpdateBody {
  mode: SemanticGuardMode
  expected_version: number
  socket_path: string
  timeout_ms: number
  max_concurrency: number
  max_input_runes: number
  block_threshold: number
  observe_threshold: number
  fail_policy: SemanticGuardFailPolicy
  inspect_llm_prompts: boolean
  inspect_mcp_content: boolean
  inspect_web_grayzone: boolean
  circuit_failure_threshold: number
  circuit_open_seconds: number
  reason: string
}

function normalizeStatus(s: SemanticGuardStatus): SemanticGuardStatus {
  return {
    available: Boolean(s.available),
    status: s.status ?? (s.available ? 'ok' : 'unavailable'),
    socket_path: s.socket_path ?? SEMANTIC_GUARD_LIMITS.defaultSocketPath,
    model_id: s.model_id ?? '',
    model_sha256: s.model_sha256 ?? '',
    backend: s.backend ?? '',
    ...(s.error ? { error: s.error } : {}),
  }
}

function normalizePolicy(p: SemanticGuardPolicy): SemanticGuardPolicy {
  const mode: SemanticGuardMode =
    p.mode === 'OBSERVE' || p.mode === 'PROTECT' ? p.mode : 'OFF'
  const failPolicy: SemanticGuardFailPolicy =
    p.fail_policy === 'FAIL_CLOSED' ? 'FAIL_CLOSED' : 'FAIL_OPEN'

  return {
    ...p,
    mode,
    version: p.version ?? 0,
    socket_path:
      typeof p.socket_path === 'string' && p.socket_path.trim()
        ? p.socket_path
        : SEMANTIC_GUARD_LIMITS.defaultSocketPath,
    timeout_ms:
      typeof p.timeout_ms === 'number' && p.timeout_ms > 0
        ? p.timeout_ms
        : SEMANTIC_GUARD_LIMITS.defaultTimeoutMs,
    max_concurrency:
      typeof p.max_concurrency === 'number' && p.max_concurrency > 0
        ? p.max_concurrency
        : SEMANTIC_GUARD_LIMITS.defaultMaxConcurrency,
    max_input_runes:
      typeof p.max_input_runes === 'number' && p.max_input_runes > 0
        ? p.max_input_runes
        : SEMANTIC_GUARD_LIMITS.defaultMaxInputRunes,
    observe_threshold:
      typeof p.observe_threshold === 'number' && p.observe_threshold > 0
        ? p.observe_threshold
        : SEMANTIC_GUARD_LIMITS.defaultObserveThreshold,
    block_threshold:
      typeof p.block_threshold === 'number' && p.block_threshold > 0
        ? p.block_threshold
        : SEMANTIC_GUARD_LIMITS.defaultBlockThreshold,
    fail_policy: failPolicy,
    inspect_llm_prompts: Boolean(p.inspect_llm_prompts),
    inspect_mcp_content: Boolean(p.inspect_mcp_content),
    inspect_web_grayzone: Boolean(p.inspect_web_grayzone),
    circuit_failure_threshold:
      typeof p.circuit_failure_threshold === 'number' &&
      p.circuit_failure_threshold > 0
        ? p.circuit_failure_threshold
        : SEMANTIC_GUARD_LIMITS.defaultCircuitFailureThreshold,
    circuit_open_seconds:
      typeof p.circuit_open_seconds === 'number' && p.circuit_open_seconds > 0
        ? p.circuit_open_seconds
        : SEMANTIC_GUARD_LIMITS.defaultCircuitOpenSeconds,
    updated_by: p.updated_by ?? '',
    created_at: p.created_at ?? '',
    updated_at: p.updated_at ?? '',
  }
}

export const semanticGuardApi = {
  getStatus: async (socketPath?: string): Promise<SemanticGuardStatus> => {
    const data = await request<SemanticGuardStatus>('/semantic-guard/status', {
      query: socketPath ? { socket_path: socketPath } : undefined,
    })
    return normalizeStatus(data)
  },

  getPolicy: async (appId: string): Promise<SemanticGuardPolicyGetResult> => {
    const data = await request<SemanticGuardPolicyGetResult>(
      `/applications/${appId}/semantic-guard-policy`,
    )
    return {
      ...data,
      policy: normalizePolicy(data.policy),
    }
  },

  updatePolicy: async (
    appId: string,
    body: SemanticGuardPolicyUpdateBody,
  ): Promise<SemanticGuardPolicy> => {
    const data = await request<{ policy: SemanticGuardPolicy }>(
      `/applications/${appId}/semantic-guard-policy`,
      { method: 'PUT', body },
    )
    return normalizePolicy(data.policy)
  },
}
