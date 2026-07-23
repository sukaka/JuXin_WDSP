import { request } from './client'
import type { PageResult } from '../types'

/* ==================== 阶段8 / WDSP：/api-security 命名空间扩展接口 ==================== */

/** 学习任务状态 */
export interface ApiLearningStatus {
  job?: {
    id: string
    status: string
    sample_target: number
    collected_count: number
    valid_count: number
    excluded_count: number
    last_error: string
    started_at: string
    stopped_at?: string | null
  } | null
  learning_status: string
  samples_total?: number
  samples_valid?: number
  samples_excluded?: number
}

export interface ApiLearningSample {
  id: string
  api_endpoint_id: string
  request_id: string
  sample_hash: string
  source_fingerprint: string
  identity_fingerprint: string
  response_status?: number | null
  accepted: boolean
  exclude_reason: string
  collected_at: string
}

export const apiLearningApi = {
  status: (endpointId: string) =>
    request<ApiLearningStatus>(`/api-security/endpoints/${endpointId}/learning/status`),
  start: (endpointId: string) =>
    request<{ message: string }>(`/api-security/endpoints/${endpointId}/learning/start`, { method: 'POST' }),
  stop: (endpointId: string) =>
    request<{ message: string }>(`/api-security/endpoints/${endpointId}/learning/stop`, { method: 'POST' }),
  samples: async (endpointId: string, params: { accepted?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiLearningSample>>(
      `/api-security/endpoints/${endpointId}/learning/samples`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
}

/** 参数模型 */
export interface ApiParameter {
  id: string
  model_version_id: string
  direction: string
  location: string
  structured_path: string
  parameter_name: string
  base_type: string
  semantic_type: string
  required: boolean
  nullable: boolean
  empty_allowed: boolean
  observed_constraints: Record<string, unknown>
  recommended_constraints: Record<string, unknown>
  confirmed_constraints: Record<string, unknown>
  sensitivity_level: string
  confidence: number
  created_at: string
}

export const apiParametersApi = {
  listByModel: async (modelId: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiParameter>>(`/api-security/models/${modelId}/parameters`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<{ parameter: ApiParameter }>(`/api-security/parameters/${id}`),
  update: (id: string, body: Partial<Pick<ApiParameter, 'required' | 'nullable' | 'empty_allowed' | 'sensitivity_level'>> & { confirmed_constraints?: Record<string, unknown> }) =>
    request<{ parameter: ApiParameter; message: string }>(`/api-security/parameters/${id}`, {
      method: 'PATCH',
      body,
    }),
  confirm: (id: string) =>
    request<{ parameter: ApiParameter; message: string }>(`/api-security/parameters/${id}/confirm`, {
      method: 'POST',
    }),
}

/** 用途分类 */
export interface ApiClassificationItem {
  id: string
  code?: string
  dimension: string
  value: string
  name?: string
  description: string
  is_builtin?: boolean
  source?: string
  created_at: string
}

export interface ApiClassificationDimension {
  id: string
  endpoint_id: string
  dimension: string
  value: string
  source: string
  confidence: number
  created_at: string
  updated_at: string
}

export const apiClassificationsApi = {
  list: async () => {
    const data = await request<{ items: ApiClassificationItem[] }>(`/api-security/classifications`)
    return data.items ?? []
  },
  create: (body: { dimension: string; value: string; description?: string }) =>
    request<{ message: string }>(`/api-security/classifications`, { method: 'POST', body }),
  setEndpointClassification: (endpointId: string, dimensions: { dimension: string; value: string }[]) =>
    request<{ message: string }>(`/api-security/endpoints/${endpointId}/classification`, {
      method: 'PUT',
      body: { dimensions },
    }),
}

/** 敏感字段 */
export interface ApiSensitiveField {
  id: string
  endpoint_id: string
  direction: string
  structured_path: string
  data_type: string
  confidence: number
  detection_source: string
  created_at: string
  updated_at: string
}

export const apiSensitiveFieldsApi = {
  list: async (params: { endpoint_id?: string; direction?: string; data_type?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiSensitiveField>>(`/api-security/sensitive-fields`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}

/** 规范导入 */
export interface ApiImportSpec {
  id: string
  format: string
  file_name: string
  content_hash: string
  endpoint_count: number
  imported_by?: string | null
  created_at: string
}

export interface ApiSpecDiff {
  id: string
  spec_id: string
  diff_type: string
  endpoint_key: string
  detail: Record<string, unknown>
  created_at: string
}

export const apiSpecsApi = {
  list: async (params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiImportSpec>>(`/api-security/specs`, { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  import: (body: { file_name?: string; spec: Record<string, unknown> }) =>
    request<{ spec: ApiImportSpec; diffs: number; message: string }>(`/api-security/specs/import`, {
      method: 'POST',
      body,
    }),
  diff: async (id: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiSpecDiff>>(`/api-security/specs/${id}/diff`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}

/** API 图谱与拓扑 */
export interface ApiGraphNode {
  id: string
  endpoint_key: string
  http_method: string
  normalized_path: string
  asset_status: string
  application_id?: string | null
}

export interface ApiGraphEdge {
  id: string
  caller_fingerprint: string
  source_endpoint_id?: string | null
  target_endpoint_id: string
  call_count: number
}

export interface ApiTopologyGroup {
  application_id?: string | null
  application_name?: string
  endpoints: ApiGraphNode[]
}

export const apiGraphApi = {
  graph: () =>
    request<{ nodes: ApiGraphNode[]; edges: ApiGraphEdge[] }>(`/api-security/graph`),
  topology: () =>
    request<{ groups: ApiTopologyGroup[]; edges: ApiGraphEdge[] }>(`/api-security/topology`),
}

/** 风险发现与违例 */
export interface ApiFinding {
  id: string
  endpoint_id?: string | null
  request_id: string
  finding_type: string
  severity: string
  status: string
  title: string
  detail: Record<string, unknown>
  first_seen_at: string
  last_seen_at: string
}

export interface ApiViolation {
  id: string
  endpoint_id?: string | null
  model_version_id?: string | null
  request_id: string
  violation_type: string
  field_path: string
  expected: string
  observed: string
  action_taken: string
  occurred_at: string
}

export const apiFindingsApi = {
  list: async (params: { finding_type?: string; severity?: string; status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiFinding>>(`/api-security/findings`, { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  violations: async (params: { endpoint_id?: string; violation_type?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiViolation>>(`/api-security/violations`, { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
}

/** 生命周期事件 */
export interface ApiLifecycleEvent {
  id: string
  endpoint_id: string
  from_status: string
  to_status: string
  reason: string
  actor: string
  created_at: string
}

export const apiLifecycleApi = {
  events: async (endpointId: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiLifecycleEvent>>(
      `/api-security/endpoints/${endpointId}/lifecycle-events`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
}

/** 安全态势与运行时统计 */
export interface ApiPosture {
  endpoints: {
    total: number
    by_asset_status: Record<string, number>
    by_learning_status: Record<string, number>
  }
  findings: { open_total: number; open_by_severity: Record<string, number> }
  learning_coverage: number
  learning_covered: number
  model_freeze_rate: number
  model_version_total: number
  model_version_frozen: number
}

export interface ApiRuntimeStatistics {
  total: number
  by_final_action: Record<string, number>
  by_risk_level: Record<string, number>
  top_endpoints: { endpoint_key: string; count: number }[]
}

export const apiPostureApi = {
  posture: () => request<ApiPosture>(`/api-security/posture`),
  runtimeStatistics: () => request<ApiRuntimeStatistics>(`/api-security/runtime/statistics`),
}

/** API 动态防护策略 */
export interface ApiPolicy {
  edition: string
  api_dynamic_protection: boolean
  mode: string
  mode_source: string
  limits: {
    max_body_parse_bytes: number
    max_body_sample_bytes: number
    max_json_depth: number
    max_field_count: number
  }
}

export const apiPolicyApi = {
  get: () => request<ApiPolicy>(`/api-security/policy`),
  updateMode: (mode: string) =>
    request<{ policy: ApiPolicy; message: string }>(`/api-security/policy`, {
      method: 'PUT',
      body: { mode },
    }),
  publish: () => request<{ message: string }>(`/api-security/policy/publish`, { method: 'POST' }),
}
