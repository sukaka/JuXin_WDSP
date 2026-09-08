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
}
