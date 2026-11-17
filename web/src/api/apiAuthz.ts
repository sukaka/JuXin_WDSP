import { request } from './client'
import type { PageResult } from '../types'

/* ==================== 阶段8 / WDSP：API 授权实体层（/api-security/authz） ====================
 * 字段与 server/internal/apiauthz 实体一致：角色基线（BFLA）、对象权属（BOLA 基线，只读）、
 * 字段权限（Mass Assignment / 字段越权）、BOLA 五档评估。
 * 权限点：api_authorization.read（查询/评估）/ api_authorization.manage（增删改/确认）。
 */

/** 角色功能级基线（api_role_baselines，BFLA） */
export interface ApiRoleBaseline {
  id: string
  endpoint_id: string
  /** 角色码 */
  role: string
  /** HTTP 方法（大写） */
  method: string
  /** 业务动作（大写归一） */
  action: string
  allowed: boolean
  /** 基线来源：MANUAL / SPEC / OBSERVED / IMPORTED */
  source: string
  /** 置信度 0..1 */
  confidence: number
  /** 人工确认标记（候选 → 正式基线） */
  confirmed: boolean
  created_by?: string | null
  created_at: string
  updated_at: string
}

/** 角色基线创建/编辑请求（编辑场景仅传变更字段；endpoint_id/confirmed 不可经编辑变更） */
export interface ApiRoleBaselineBody {
  endpoint_id?: string
  role?: string
  method?: string
  action?: string
  allowed?: boolean
  source?: string
  confidence?: number
}

/** 对象权属基线（api_object_ownership，BOLA；SweepOnce 生产，只读查询） */
export interface ApiObjectOwnership {
  id: string
  endpoint_id: string
  identity_fingerprint: string
  object_type: string
  object_id: string
  first_seen: string
  last_seen: string
  access_count: number
}

/** 字段属性七值枚举（api_field_permissions.attribute CHECK 对齐） */
export type ApiFieldAttribute =
  | 'READABLE'
  | 'WRITABLE'
  | 'READ_ONLY'
  | 'ADMIN_WRITABLE'
  | 'SERVER_GENERATED'
  | 'SENSITIVE'
  | 'FORBIDDEN'

/** 字段权限（api_field_permissions）；role/tenant 为 NULL 即默认行，非空为覆盖行 */
export interface ApiFieldPermission {
  id: string
  endpoint_id: string
  field_path: string
  /** REQUEST（防 Mass Assignment）/ RESPONSE（防越权读取） */
  direction: string
  attribute: string
  role?: string | null
  tenant?: string | null
  created_by?: string | null
  created_at: string
  updated_at: string
}

/** 字段权限创建/编辑请求（role/tenant 显式传空串 = 清除为 NULL，回到默认行语义） */
export interface ApiFieldPermissionBody {
  endpoint_id?: string
  field_path?: string
  direction?: string
  attribute?: string
  role?: string
  tenant?: string
}

/** BOLA 评估证据（各信号计数，供研判溯源） */
export interface ApiBolaEvaluateEvidence {
  /** (身份,对象) 权属记录存在 */
  own_match: boolean
  /** 该对象在本端点的权属记录数 */
  object_owner_count: number
  /** 该身份在本端点的权属对象数 */
  identity_object_count: number
  /** 该身份在本端点的历史运行时事件数 */
  identity_event_count: number
  /** 本端点权属记录总数 */
  endpoint_ownership_rows: number
}

/** BOLA 五档评估结果（GET /authz/evaluate） */
export interface ApiBolaEvaluateResult {
  endpoint_id: string
  identity: string
  object_id: string
  /** 五档结论：POLICY_CONFIRMED / HIGH_CONFIDENCE / LIKELY / POSSIBLE / INSUFFICIENT_EVIDENCE */
  verdict: string
  /** 倾向判定；INSUFFICIENT_EVIDENCE 为 null（无法判定） */
  allowed?: boolean | null
  /** 结论置信度 0..1（档位固定值） */
  confidence: number
  evidence?: ApiBolaEvaluateEvidence | null
  /** 中文结论说明 */
  comment: string
  evaluated_at: string
}

export type ApiAuthzCandidateStatus = 'PENDING' | 'REJECTED' | 'FROZEN' | 'CONFIRMED'
/** NG-AZ-03 D7：VERIFIED_VIOLATION 为第四值（资格全真且端点 PROTECT 的实断决策） */
export type ApiAuthzDecisionValue = 'ALLOW' | 'OBSERVE_VIOLATION' | 'UNKNOWN' | 'VERIFIED_VIOLATION'

export interface ApiAuthzRelationCandidate {
  id: string
  application_id: string
  endpoint_id?: string | null
  object_type: string
  object_ref: string
  principal_id?: string | null
  tenant_id?: string | null
  legacy_identity_fingerprint?: string | null
  source: string
  status: ApiAuthzCandidateStatus
  source_count: number
  observation_count: number
  confidence_inputs: Record<string, unknown>
  evidence_ref?: string | null
  reject_reason?: string | null
  first_seen: string
  last_seen: string
  created_at: string
  updated_at: string
}

export type ApiAuthzObjectRelationType = 'OWNER' | 'SHARED_WITH'

export interface ApiAuthzObjectRelation {
  id: string
  application_id: string
  object_type: string
  object_ref: string
  principal_id: string
  tenant_id?: string | null
  relation: ApiAuthzObjectRelationType
  /** 来源词表（迁移 000172 扩 AUTHORITY_SYNC 权威同步通道） */
  source: 'MANUAL' | 'IMPORT' | 'CREATE_BINDING' | 'AUTHORITY_SYNC'
  /** 权威来源 ID（source=AUTHORITY_SYNC 时非空） */
  source_id?: string | null
  status: 'CONFIRMED' | 'REVOKED' | 'EXPIRED'
  valid_from: string
  valid_until?: string | null
  evidence_ref?: string | null
  confirmed_by: string
  confirmed_at: string
  reason: string
  created_at: string
  updated_at: string
}

export interface ApiAuthzCreateObjectRelationBody {
  application_id: string
  object_type: string
  /** 服务端生成的 objref: HMAC 引用，不接受对象明文 */
  object_ref: string
  principal_id: string
  tenant_id?: string
  relation: ApiAuthzObjectRelationType
  source?: 'MANUAL' | 'IMPORT'
  valid_from?: string
  valid_until?: string
  evidence_ref?: string
  reason: string
}

/** 重新授权请求（POST /authz/relations/{id}/reauthorize；仅 REVOKED/EXPIRED 关系允许） */
export interface ApiAuthzReauthorizeBody {
  reason: string
  valid_from: string
  valid_until?: string
}

export interface ApiAuthzDecision {
  id: string
  decision_id: string
  application_id?: string | null
  endpoint_key: string
  policy_version: string
  decision: ApiAuthzDecisionValue
  checks: unknown[]
  evidence?: Record<string, unknown>
  occurred_at: string
}

export interface ApiAuthzCoverage {
  application_id?: string | null
  pending_candidates: number
  confirmed_relations: number
  decisions: number
  unknown_decisions: number
  observe_violations: number
  verified_identity_rate: number
  model_coverage_rate: number
  confirmed_relation_rate: number
  unknown_rate: number
}

/* ==================== NG-AZ-04：态势与实断资格（docs/nextgen/NG-AZ-04-protect-wizard.md） ==================== */

/** readiness 徽章词表（§1.2 冻结六态 + PROTECT_ACTIVE 展示态；服务端唯一事实源派生） */
export type ApiAuthzEnforcementReadiness =
  | 'READY'
  | 'PROTECT_ACTIVE'
  | 'NOT_PUBLISHABLE'
  | 'BLOCKED_BY_NO_RELATION'
  | 'BLOCKED_BY_CONFLICT'
  | 'BLOCKED_BY_STALE'
  | 'BLOCKED_BY_NODE'

/** 端点级 readiness 行（§1.2 逐键：reasons 为全部不真因子原文，而非仅首个） */
export interface ApiAuthzEnforcementReadinessItem {
  endpoint_id: string
  endpoint_key: string
  object_segment: string
  /** 当前 enforcement（OBSERVE/PROTECT） */
  enforcement: string
  readiness: ApiAuthzEnforcementReadiness | string
  reasons: string[]
  checked_at: string
}

/** 影响评估请求（§1.3；window_days 词表 1~30，越界 400） */
export interface ApiAuthzEnforcementImpactRequest {
  endpoint_id: string
  window_days: number
  /** 端点多对象模型行时指定（token 绑定粒度=对象模型行；恰一行可省） */
  object_segment?: string
}

export interface ApiAuthzUnknownBucket {
  reason_code: string
  count: number
}

/** 脱敏样本（仅 api_authorization.evidence_read 时返回，否则整个键省略） */
export interface ApiAuthzImpactSample {
  occurred_at: string
  decision: string
  reason_code: string
}

/** 影响评估响应（§1.3 逐键；confirm_token 仅 api_authorization.manage 调用签发，一次性、15 分钟 TTL） */
export interface ApiAuthzEnforcementImpact {
  endpoint_id: string
  endpoint_key: string
  object_segment: string
  window_days: number
  evaluated_at: string
  /** 切换后将被 403 的请求量近似（decision='OBSERVE_VIOLATION'） */
  observe_violation_count: number
  unknown_total: number
  unknown_by_reason: ApiAuthzUnknownBucket[]
  distinct_principal_count: number
  /** 已实断数（PROTECT 复评时非零） */
  verified_violation_count: number
  recent_samples?: ApiAuthzImpactSample[]
  readiness: ApiAuthzEnforcementReadiness | string
  readiness_reasons: string[]
  confirm_token?: string
  confirm_token_expires_at?: string
}

/** 业务确认单（§1.4，迁移 000175；留存不删——历史事实） */
export interface ApiAuthzEnforcementConfirmation {
  id: string
  confirm_token: string
  application_id: string
  endpoint_id: string
  /** 确认粒度 = 对象模型行（端点×对象段） */
  object_segment: string
  window_days: number
  /** 签署时刻影响评估摘要全量（§1.3 响应无 token 键） */
  impact_snapshot: Record<string, unknown>
  /** 冻结确认语义文案（含文案版本号；落库文本以 server 为准） */
  confirm_text: string
  enforcement_owner: string
  evidence_source: 'AUTHORITY_SYNC' | 'MANUAL_CONFIRMED' | string
  /** 首批唯一 UNKNOWN 处理方式：ALLOW_UNKNOWN（UNKNOWN 永不阻断） */
  on_unknown: string
  confirmed_by: string
  confirmed_by_name: string
  created_at: string
  token_expires_at: string
  /** 向导第 4 步签署时刻（NULL=未签署） */
  signed_at?: string | null
  /** PATCH 消费时刻（NULL=未消费） */
  consumed_at?: string | null
  consumed_audit_id: string
}

/** 确认单签署请求（向导第 4 步：四要素先签后切换） */
export interface ApiAuthzEnforcementSignBody {
  enforcement_owner: string
  evidence_source: 'AUTHORITY_SYNC' | 'MANUAL_CONFIRMED' | string
  on_unknown: string
}

/** OPEN 冲突记录（D1：列同 server ConflictRecord） */
export interface ApiAuthzConflict {
  id: string
  application_id: string
  object_type: string
  tenant_domain: string
  object_ref: string
  principals: string[]
  status: string
  first_seen: string
  updated_at: string
}

/** 向量水位（server apiruntime.VectorWatermark；分量比较在服务端，前端只读展示） */
export interface ApiAuthzVectorWatermark {
  manual_seq: number
  sources: Record<string, number>
}

/** 单节点授权 ACK 视图行（NG-AZ-02 D6 §1.4 冻结字段集；null=「无此事实」如实呈现） */
export interface ApiAuthzNodeAck {
  node_name: string
  /** 节点活性（ACTIVE/STALE/SILENT） */
  status: string
  /** 授权快照策略版本戳；空串 = 未上报 */
  authz_policy_version: string
  authz_watermark?: ApiAuthzVectorWatermark | null
  authz_applied_at?: string | null
  last_ack_at?: string | null
  /** now − authz_applied_at（可为负：节点时钟超前）；null = 未应用过授权快照 */
  staleness_seconds?: number | null
  /** 授权租约秒数；null = 未配置租约 */
  lease_seconds?: number | null
  /** 五态词表：FRESH/STALE_WITHIN_LEASE/STALE_EXPIRED/NEVER_ACKED/CLOCK_SKEW */
  ack_state: string
}

/** node-acks 顶层响应（NG-AZ-02 §1.4） */
export interface ApiAuthzNodeAckView {
  items: ApiAuthzNodeAck[]
  /** 全节点最大陈旧窗口；null = 无参与节点 */
  max_staleness_seconds?: number | null
  management_watermark: ApiAuthzVectorWatermark
  generated_at: string
}

/** 权威来源（api_authority_sources；管理写通道本批不做，态势区块只读） */
export interface ApiAuthzAuthoritySource {
  id: string
  name: string
  status: string
  scopes: { tenant_domains?: string[]; object_types?: string[] }
  max_event_age_seconds?: number | null
  created_at: string
  updated_at: string
  version: number
}

export interface ApiAuthzAuthorityBatch {
  id: string
  source_id: string
  mode: string
  status: string
  counts: { applied: number; skipped_duplicate: number; skipped_stale: number; grants: number; revokes: number; conflicts: number }
  error?: string
  created_by?: string | null
  created_at: string
}

/** 权威来源状态（GET authorities/{id}/status 响应逐键） */
export interface ApiAuthzAuthorityStatus {
  source: ApiAuthzAuthoritySource
  watermark: {
    last_sequence: number
    last_event_id: string
    revocation_watermark: number
    gap_from?: number | null
    updated_at: string
  }
  /** OK / NO_DATA / AUTHZ_SOURCE_GAP */
  gap_status: string
  conflicts: ApiAuthzConflict[]
  batches: ApiAuthzAuthorityBatch[]
}

export const apiAuthzApi = {
  /** 角色基线分页列表（过滤 endpoint_id/role/method/source/confirmed） */
  listRoleBaselines: async (params: {
    endpoint_id?: string
    role?: string
    method?: string
    source?: string
    confirmed?: boolean
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiRoleBaseline>>('/api-security/authz/role-baselines', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 新建为候选（confirmed=false），确认走 confirm 接口 */
  createRoleBaseline: (body: ApiRoleBaselineBody) =>
    request<ApiRoleBaseline>('/api-security/authz/role-baselines', { method: 'POST', body }),
  /** 部分更新（endpoint_id 不可改，换端点 = 删除后重建） */
  updateRoleBaseline: (id: string, body: ApiRoleBaselineBody) =>
    request<ApiRoleBaseline>(`/api-security/authz/role-baselines/${id}`, { method: 'PATCH', body }),
  deleteRoleBaseline: (id: string) =>
    request<{ message: string }>(`/api-security/authz/role-baselines/${id}`, { method: 'DELETE' }),
  /** 候选 → 正式基线（confirmed=true）；传 false 撤回确认 */
  confirmRoleBaseline: (id: string, confirmed: boolean) =>
    request<ApiRoleBaseline>(`/api-security/authz/role-baselines/${id}/confirm`, {
      method: 'POST',
      body: { confirmed },
    }),

  /** 对象权属只读查询（按最近访问倒序；过滤 endpoint_id/identity/object_type/object_id） */
  listOwnership: async (params: {
    endpoint_id?: string
    identity?: string
    object_type?: string
    object_id?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiObjectOwnership>>('/api-security/authz/ownership', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },

  /** 字段权限分页列表（过滤 endpoint_id/direction/attribute/role/tenant/defaults_only） */
  listFieldPermissions: async (params: {
    endpoint_id?: string
    direction?: string
    attribute?: string
    role?: string
    tenant?: string
    defaults_only?: boolean
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiFieldPermission>>('/api-security/authz/field-permissions', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  createFieldPermission: (body: ApiFieldPermissionBody) =>
    request<ApiFieldPermission>('/api-security/authz/field-permissions', { method: 'POST', body }),
  updateFieldPermission: (id: string, body: ApiFieldPermissionBody) =>
    request<ApiFieldPermission>(`/api-security/authz/field-permissions/${id}`, { method: 'PATCH', body }),
  deleteFieldPermission: (id: string) =>
    request<{ message: string }>(`/api-security/authz/field-permissions/${id}`, { method: 'DELETE' }),

  /** BOLA 五档评估（只读；identity 可空 = 匿名身份，只走对象侧信号） */
  evaluate: (params: { endpoint_id: string; identity?: string; object_id: string }) =>
    request<ApiBolaEvaluateResult>('/api-security/authz/evaluate', { query: { ...params } }),

  listRelationCandidates: async (params: { application_id: string; status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiAuthzRelationCandidate>>('/api-security/authz/relations/candidates', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  confirmRelationCandidate: (id: string, body: { relation: 'OWNER'; reason: string; valid_until?: string }) =>
    request<ApiAuthzObjectRelation>(`/api-security/authz/relations/candidates/${id}/confirm`, { method: 'POST', body }),
  rejectRelationCandidate: (id: string, reason: string) =>
    request<ApiAuthzRelationCandidate>(`/api-security/authz/relations/candidates/${id}/reject`, { method: 'POST', body: { reason } }),
  listObjectRelations: async (params: { application_id: string; object_type?: string; status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiAuthzObjectRelation>>('/api-security/authz/relations', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  /** 手工登记所有者或共享关系（权限 api_authorization.relation_manage；409 原样呈现冲突） */
  createObjectRelation: (body: ApiAuthzCreateObjectRelationBody) =>
    request<ApiAuthzObjectRelation>('/api-security/authz/relations', { method: 'POST', body }),
  /** 撤销有效关系并保留历史记录；reason 写入 HIGH 级操作审计 */
  revokeObjectRelation: (id: string, body: { reason: string }) =>
    request<ApiAuthzObjectRelation>(`/api-security/authz/relations/${id}/revoke`, { method: 'POST', body }),
  /** 显式重新授权（仅 REVOKED/EXPIRED 关系；权限 api_authorization.relation_manage） */
  reauthorizeObjectRelation: (id: string, body: ApiAuthzReauthorizeBody) =>
    request<ApiAuthzObjectRelation>(`/api-security/authz/relations/${id}/reauthorize`, { method: 'POST', body }),
  listAuthorizationDecisions: async (params: { application_id: string; decision?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiAuthzDecision>>('/api-security/authz/decisions', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  getAuthorizationCoverage: (application_id: string) =>
    request<ApiAuthzCoverage>('/api-security/authz/coverage', { query: { application_id } }),

  /* ==================== NG-AZ-04：态势与实断资格（§1.1~§1.4 冻结契约） ==================== */

  /** 端点级实断资格徽章列表（服务端唯一事实源派生；前端只渲染不拼装。endpoint_id 单查时 application_id 可省） */
  listEnforcementReadiness: async (params: { application_id?: string; endpoint_id?: string }) => {
    const data = await request<{ items: ApiAuthzEnforcementReadinessItem[] }>('/api-security/authz/enforcement-readiness', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 切换前影响评估（只读，POST 承载参数；manage 调用同时签发一次性 confirm_token） */
  evaluateEnforcementImpact: (body: ApiAuthzEnforcementImpactRequest) =>
    request<ApiAuthzEnforcementImpact>('/api-security/authz/enforcement-impact', { method: 'POST', body }),
  /** 确认单分页查询（api_authorization.read） */
  listEnforcementConfirmations: async (params: { application_id?: string; endpoint_id?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiAuthzEnforcementConfirmation>>('/api-security/authz/enforcement-confirmations', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 确认单签署（向导第 4 步；路径参数为影响评估签发的 confirm_token，签署后 signed_at 落库） */
  signEnforcementConfirmation: (confirmToken: string, body: ApiAuthzEnforcementSignBody) =>
    request<ApiAuthzEnforcementConfirmation>(`/api-security/authz/enforcement-confirmations/${confirmToken}/sign`, {
      method: 'POST',
      body,
    }),
  /** OPEN 冲突独立分页查询（D1；列同 ConflictRecord） */
  listAuthzConflicts: async (params: { application_id?: string; status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiAuthzConflict>>('/api-security/authz/conflicts', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },

  /* ==================== 既有只读端点补 client（NG-AZ-02 D6 / NG-AZ-01 §6） ==================== */

  /** 全节点授权 ACK 视图（ack_state 五态派生在服务端） */
  listNodeAcks: () => request<ApiAuthzNodeAckView>('/api-security/authz/node-acks'),
  /** 权威来源列表（态势 Tab「最后同步时间」区块） */
  listAuthzAuthorities: async () => {
    const data = await request<{ items: ApiAuthzAuthoritySource[] }>('/api-security/authz/authorities')
    return { ...data, items: data.items ?? [] }
  },
  /** 权威来源状态（水位/缺口/冲突/最近批次） */
  getAuthzAuthorityStatus: (id: string) =>
    request<ApiAuthzAuthorityStatus>(`/api-security/authz/authorities/${id}/status`),
}
