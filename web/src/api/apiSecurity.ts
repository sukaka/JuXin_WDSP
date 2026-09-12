import { request } from './client'
import type { PageResult } from '../types'

/* ==================== 阶段8 / WDSP：/api-security 命名空间扩展 API ==================== */

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
  start: (endpointId: string, body?: { sample_target?: number }) =>
    request<{ message: string }>(`/api-security/endpoints/${endpointId}/learning/start`, { method: 'POST', body }),
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

/** 三微模型成熟度阶段（与 server 端模型成熟度状态机枚举一致） */
export type ApiModelMaturityStage = 'LEARNING' | 'CANDIDATE' | 'CONFIRMED' | 'ENFORCING'

export interface ApiModelMaturityItem {
  /** 模型标识：parameter / identity / access_env / access_object */
  key: string
  name: string
  stage: ApiModelMaturityStage
  metrics: Record<string, number>
  summary: string
}

export interface ApiModelMaturity {
  generated_at: string
  models: ApiModelMaturityItem[]
}

export const apiMaturityApi = {
  get: () => request<ApiModelMaturity>(`/api-security/model-maturity`),
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
  /** 详情 data 即参数对象本身（与 OpenAPI ApiSecParameter / 后端 GetParameter 一致） */
  get: (id: string) => request<ApiParameter>(`/api-security/parameters/${id}`),
  update: (id: string, body: Partial<Pick<ApiParameter, 'required' | 'nullable' | 'empty_allowed' | 'sensitivity_level' | 'semantic_type'>> & { confirmed_constraints?: Record<string, unknown> }) =>
    request<{ parameter: ApiParameter; message: string }>(`/api-security/parameters/${id}`, {
      method: 'PATCH',
      body,
    }),
  confirm: (id: string) =>
    request<{ parameter: ApiParameter; message: string }>(`/api-security/parameters/${id}/confirm`, {
      method: 'POST',
    }),
  /** 批量采纳推荐约束；ids 省略则确认该版本全部有 recommended 的参数 */
  confirmBatch: (modelId: string, ids?: string[]) =>
    request<{ confirmed: number; skipped: number; message: string }>(
      `/api-security/models/${modelId}/parameters/confirm-batch`,
      { method: 'POST', body: ids?.length ? { ids } : {} },
    ),
  listRelations: (modelId: string) =>
    request<{ items: Array<{ id: string; relation_type: string; confidence: number; source_parameter_id: string; target_parameter_id: string }> }>(
      `/api-security/models/${modelId}/parameter-relations`,
    ),
}

/** 身份画像（身份微模型） */
export interface ApiIdentityProfile {
  identity_fingerprint: string
  endpoint_id: string
  endpoint_key?: string
  /** 所属站点名称（未归属时为空字符串） */
  application_name?: string
  /** 所属站点主域名（无域名记录时为空字符串；展示时优先于名称） */
  application_domain?: string
  auth_type: string
  request_count: number
  first_seen_at: string
  last_seen_at: string
  quality_score: number
}

export const apiIdentityProfilesApi = {
  list: async (params: { page: number; page_size: number; endpoint_id?: string; identity_fingerprint?: string; application_id?: string }) => {
    const data = await request<PageResult<ApiIdentityProfile>>(`/api-security/identity-profiles`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  detail: (params: { identity_fingerprint: string; endpoint_id: string }) =>
    request<ApiIdentityProfileDetail>(`/api-security/identity-profiles/detail`, { query: { ...params } }),
}

/** 行为基线画像（访问微模型·环境维度，api_behavior_profiles 离线聚合产出） */
export interface ApiBehaviorProfile {
  id: string
  endpoint_id: string
  /** LEFT JOIN api_endpoints 带出；端点已删除时为空串 */
  endpoint_key?: string
  /** 所属站点名称（未归属时为空字符串） */
  application_name?: string
  /** 所属站点主域名（无域名记录时为空字符串；展示时优先于名称） */
  application_domain?: string
  /** 空串表示端点级聚合行 */
  identity_fingerprint: string
  window_seconds: number
  request_count: number
  avg_rate: number
  /** 状态码分布（2xx / 4xx / 5xx / unknown 计数） */
  status_code_dist: Record<string, number>
  /** 调用时段分布（UTC 小时桶 "0"-"23" 计数） */
  hour_dist: Record<string, number>
  updated_at: string
}

export const apiBehaviorProfilesApi = {
  list: async (params: { page: number; page_size: number; endpoint_id?: string; identity_fingerprint?: string; application_id?: string }) => {
    const data = await request<PageResult<ApiBehaviorProfile>>(`/api-security/behavior-profiles`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}

/** 对象模型（访问微模型·对象维度，api_object_models，BOLA 实体画像） */
export interface ApiObjectModel {
  id: string
  endpoint_id: string
  /** LEFT JOIN api_endpoints 带出；端点已删除时为空串 */
  endpoint_key?: string
  /** 所属站点名称（未归属时为空字符串） */
  application_name?: string
  /** 所属站点主域名（无域名记录时为空字符串；展示时优先于名称） */
  application_domain?: string
  /** 对象段键："path:<pos>" 路径占位段 / "query:<参数名>" Query 对象参数 */
  object_segment: string
  /** 标识形态：numeric / uuid / hash / mixed / unknown */
  identifier_type: string
  /** 观测值 SHA-256 示例哈希（不落明文） */
  example_hash: string
  sample_count: number
  first_seen: string
  last_seen: string
  updated_at: string
}

export const apiObjectModelsApi = {
  list: async (params: { page: number; page_size: number; endpoint_id?: string; object_segment?: string; identifier_type?: string; application_id?: string }) => {
    const data = await request<PageResult<ApiObjectModel>>(`/api-security/object-models`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}

/** 威胁识别指标（GB/T 31509 修订稿 5.2.3：数量 / 时间分布 / 严重程度） */
export interface ApiIdentityRiskIndicators {
  events_total: number
  events_24h: number
  risky_events_total: number
  blocked_events_total: number
  distinct_endpoints: number
  active_days: number
  max_risk_score: number
}

/** 身份风险评估（可能性 × 严重程度 → 五级矩阵，只产信号不阻断） */
export interface ApiIdentityRiskAssessment {
  level: 'VERY_LOW' | 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH'
  likelihood: number
  severity: number
  indicators: ApiIdentityRiskIndicators
  summary: string
}

/** 详情内嵌的近期运行时事件（ApiSecRuntimeEvent 子集，明细 details 不展示） */
export interface ApiIdentityRuntimeEvent {
  id: string
  request_id: string
  endpoint_key: string
  risk_score: number
  risk_level: string
  final_action: string
  occurred_at: string
  auth_type: string
}

export interface ApiIdentityProfileDetail {
  profile: ApiIdentityProfile
  risk: ApiIdentityRiskAssessment
  recent_events: ApiIdentityRuntimeEvent[]
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
    // 后端返回 {builtin, custom} 两组，统一归一化为扁平列表（builtin 的 code/name 映射为 dimension/value）
    const data = await request<{
      builtin?: {
        id: string
        code: string
        name: string
        description: string
        is_builtin: boolean
        created_at: string
      }[]
      custom?: {
        id: string
        dimension: string
        value: string
        description: string
        created_at: string
      }[]
    }>(`/api-security/classifications`)
    const builtin = (data.builtin ?? []).map((b) => ({
      id: b.id,
      code: b.code,
      dimension: 'PURPOSE',
      value: b.name,
      name: b.name,
      description: b.description,
      is_builtin: true,
      created_at: b.created_at,
    }))
    const custom = (data.custom ?? []).map((c) => ({
      id: c.id,
      dimension: c.dimension,
      value: c.value,
      description: c.description,
      is_builtin: false,
      created_at: c.created_at,
    }))
    return [...builtin, ...custom] as ApiClassificationItem[]
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
  /** 接口键（METHOD PATH；端点缺失时为空串） */
  endpoint_key: string
  direction: string
  structured_path: string
  data_type: string
  /** 识别置信度 0-1（字段名词表命中 0.8，值级正则验证命中 1.0，重复命中取较大者） */
  confidence: number
  detection_source: string
  occurrence_count: number
  first_seen?: string | null
  last_seen?: string | null
  /** 最近一次命中摘要 { location, rule_id, event_id, data_type } */
  source_detail?: Record<string, string> | null
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
  batchDelete: (ids: string[]) =>
    request<{ message: string; deleted: number }>(`/api-security/sensitive-fields/batch-delete`, {
      method: 'POST',
      body: { ids },
    }),
}

/** 规范导入（api_import_specs；W3-C 起带版本状态机：name 为版本链标识，同名唯一 ACTIVE） */
export interface ApiImportSpec {
  id: string
  /** 规范名称（版本链标识） */
  name: string
  /** 链内版本号（自增） */
  version_no: number
  /** DRAFT / ACTIVE / HISTORICAL / INVALID / ARCHIVED */
  status: string
  parent_id?: string | null
  activated_at?: string | null
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

/** 规范导入响应（粘贴/URL 导入同构，与服务端 importSpecCore 返回一致） */
export interface ApiSpecImportResult {
  spec: ApiImportSpec
  missing_in_runtime: number
  missing_in_spec: number
  changed: number
  registered_endpoints: number
}

/** 跨版本 CHANGED 级对比的变化条目（与 apisecurity.SpecChange 一致） */
export interface ApiSpecChange {
  endpoint_key: string
  /** ENDPOINT_ADDED / ENDPOINT_REMOVED / PARAM_ADDED / PARAM_REMOVED / TYPE_CHANGED / REQUIRED_CHANGED */
  change_type: string
  param_in?: string
  param_name?: string
  /** 旧值（类型名或 "true"/"false"） */
  before?: string
  /** 新值 */
  after?: string
}

/** 版本对比响应（GET /specs/{id}/version-diff?other=；id 为基准旧版，other 为目标新版） */
export interface ApiSpecVersionDiff {
  base: { id: string; name: string; version_no: number }
  target: { id: string; name: string; version_no: number }
  changes: ApiSpecChange[]
}

export const apiSpecsApi = {
  list: async (params: { name?: string; status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiImportSpec>>(`/api-security/specs`, { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  import: (body: { file_name?: string; spec: Record<string, unknown> }) =>
    request<ApiSpecImportResult>(`/api-security/specs/import`, {
      method: 'POST',
      body,
    }),
  /** 从 URL 拉取规范文档导入（服务端 SSRF 防护；headers 可选认证头，最多 20 个） */
  importUrl: (body: { url: string; name?: string; headers?: Record<string, string> }) =>
    request<ApiSpecImportResult>(`/api-security/specs/import-url`, {
      method: 'POST',
      body,
    }),
  /** 激活指定版本：同名当前 ACTIVE 降为 HISTORICAL（已是 ACTIVE 时 409） */
  activate: (id: string) =>
    request<{ spec: ApiImportSpec }>(`/api-security/specs/${id}/activate`, { method: 'POST' }),
  /** 任意两版本 CHANGED 级对比（id 为基准旧版，otherId 为目标新版；只读不落库） */
  versionDiff: (id: string, otherId: string) =>
    request<ApiSpecVersionDiff>(`/api-security/specs/${id}/version-diff`, { query: { other: otherId } }),
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
    request<{ applications: ApiTopologyGroup[]; edges: ApiGraphEdge[] }>(`/api-security/topology`),
}

/** 风险发现与违例 */
export interface ApiFinding {
  id: string
  endpoint_id?: string | null
  /** 关联接口的「METHOD 路径模板」（后端 LEFT JOIN api_endpoints 带出；未匹配时为空串） */
  endpoint_key?: string
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

/**
 * 风险处置动作（P0 风险中心契约，与 server/internal/apisecurity/risk.go 状态机一致）：
 * 仅备注类动作 confirm/start/ignore/archive（body 可选 {note}，≤512 字符）；
 * resolve（必填 resolution）与 false-positive（必填 reason）走独立方法。
 */
export type ApiFindingHandleAction = 'confirm' | 'start' | 'ignore' | 'archive'

/** 风险详情（GET /findings/{id} 的 finding）：列表行的超集，含主体/风险分/累计命中/证据/模型与策略版本 */
export interface ApiFindingDetail extends ApiFinding {
  subject_type: string
  /** 身份指纹或来源指纹（后端永不落明文） */
  subject_id: string
  risk_score?: number | null
  risk_level: string
  /** 同指纹累计命中次数（dedup upsert 只保留首次 request_id，后续命中仅计数） */
  count: number
  /** 已脱敏证据（字段名/粗类型词表/约束名，生产方落库时已脱敏，原样展示） */
  evidence: Record<string, unknown>
  model_version: string
  policy_version: string
  created_at?: string
  updated_at?: string | null
}

/** 风险汇总视图键（summary 一次返回三视图，前端本地切换）：subject 主体 / endpoint 接口 / type 类型 */
export type ApiFindingSummaryGroupBy = 'subject' | 'endpoint' | 'type'

/** 风险汇总桶（三视图共用，与 server 端 RiskSummaryBucket 一致；按视图取用相应维度字段） */
export interface ApiFindingSummaryBucket {
  subject_type?: string
  subject_id?: string
  endpoint_id?: string | null
  endpoint_key?: string
  finding_type?: string
  /** 聚合的 finding 条目数（dedup 去重后） */
  count: number
  /** 累计命中次数（sum(count)） */
  hits: number
  /** 桶内最高严重级别 */
  max_severity: string
  last_seen_at: string
}

/** 风险降噪聚合（GET /findings/summary）：主体/接口/类型三视图一次返回，各取头部桶 */
export interface ApiFindingSummary {
  by_subject: ApiFindingSummaryBucket[]
  by_endpoint: ApiFindingSummaryBucket[]
  by_finding_type: ApiFindingSummaryBucket[]
}

export const apiFindingsApi = {
  list: async (params: { finding_type?: string; severity?: string; status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiFinding>>(`/api-security/findings`, { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  violations: async (params: {
    endpoint_id?: string
    violation_type?: string
    /** 发生时间范围（ISO 8601；后端未支持前静默忽略，由集成方补齐服务端过滤） */
    start_time?: string
    end_time?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiViolation>>(`/api-security/violations`, { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  /** 风险汇总：主体/接口/类型三视图一次返回（权限 api_risk.read；无 group_by 参数，前端本地切换视图） */
  summary: () => request<ApiFindingSummary>(`/api-security/findings/summary`),
  /** 风险详情（权限 api_risk.read）：finding + 同端点（同身份）近期事件的近似关联 request_id 列表 */
  detail: (id: string) =>
    request<{ finding: ApiFindingDetail; related_request_ids: string[]; related_request_note: string }>(
      `/api-security/findings/${id}`,
    ),
  /** 风险处置（权限 api_risk.handle）：confirm/start/ignore/archive，body 可选 {note}（≤512 字符） */
  handle: (id: string, action: ApiFindingHandleAction, body?: { note?: string }) =>
    request<{ finding: ApiFindingDetail }>(`/api-security/findings/${id}/${action}`, { method: 'POST', body: body ?? {} }),
  /** 标记已解决（权限 api_risk.handle）：body 必填 {resolution}（≤512 字符） */
  resolve: (id: string, resolution: string) =>
    request<{ finding: ApiFindingDetail }>(`/api-security/findings/${id}/resolve`, { method: 'POST', body: { resolution } }),
  /** 标记误报（权限 api_risk.handle）：body 必填 {reason}（≤512 字符） */
  falsePositive: (id: string, reason: string) =>
    request<{ finding: ApiFindingDetail }>(`/api-security/findings/${id}/false-positive`, { method: 'POST', body: { reason } }),
}

/** 运行时事件检测明细项（与网关 dsctx.DetectorMatch 序列化结构一致） */
export interface ApiRuntimeEventDetail {
  detector: string
  rule_id?: string
  category?: string
  severity?: string
  message?: string
  /** 已脱敏的证据键值 */
  evidence?: Record<string, string>
  score_delta?: number
}

/**
 * 运行时主事件（api_runtime_events；client 见 apiAssets.ts 的 apiRuntimeEventsApi）。
 * 审计维度字段（client_ip/method/raw_path/latency_ms/model_version/policy_version/response_status）
 * 为迁移 000030/000035 新增列，旧版网关事件可能为 NULL，读取侧全部按可空处理。
 */
export interface ApiRuntimeEvent {
  id: string
  request_id: string
  endpoint_key: string
  risk_score: number
  risk_level: string
  final_action: string
  details?: ApiRuntimeEventDetail[] | null
  occurred_at: string
  identity_fingerprint: string
  auth_type: string
  response_status?: number | null
  client_ip?: string | null
  method?: string | null
  raw_path?: string | null
  latency_ms?: number | null
  model_version?: string | null
  policy_version?: string | null
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
