import { request } from './client'
import type { PageResult } from '../types'

/* ==================== 敏感数据管理面（server/internal/apidata）：敏感数据类型 / 脱敏规则 / 敏感数据态势 ==================== */

/** 五级敏感等级（api_sensitive_data_types.level CHECK 对齐） */
export type ApiSensitiveLevel = 'NON_SENSITIVE' | 'GENERAL' | 'SENSITIVE' | 'IMPORTANT' | 'CORE'

/** 类型状态（api_sensitive_data_types.status CHECK 对齐） */
export type ApiSensitiveTypeStatus = 'ENABLED' | 'DISABLED'

/** 脱敏作用域（api_masking_rules.scope CHECK 对齐） */
export type ApiMaskingScope = 'GLOBAL' | 'APPLICATION' | 'ENDPOINT'

/** 脱敏算法（api_masking_rules.algorithm CHECK 对齐） */
export type ApiMaskingAlgorithm = 'MASK' | 'HASH' | 'REMOVE'

/** 敏感数据类型（api_sensitive_data_types） */
export interface ApiSensitiveDataType {
  id: string
  name: string
  description: string
  category: string
  level: ApiSensitiveLevel
  /** 数据类型标签（与网关 evidence.data_type 对齐） */
  data_type: string
  /** 可能出现位置（query/json/form/xml/header/cookie/path/response_body） */
  locations: string[]
  /** 字段名词根 */
  keywords: string[]
  /** 值级正则（空 = 不做值检测） */
  regex: string
  /** 值校验器（'' / luhn） */
  validator: string
  /** 排除字段名 */
  exclude_fields: string[]
  status: ApiSensitiveTypeStatus
  /** 编辑自增 */
  version: number
  /** 内置类型：禁删、名称不可改 */
  is_builtin: boolean
  created_at: string
  updated_at: string
}

/** 类型创建/编辑提交体（编辑为部分更新：仅提交的字段生效） */
export interface ApiSensitiveTypeBody {
  name?: string
  description?: string
  category?: string
  level?: ApiSensitiveLevel
  data_type?: string
  locations?: string[]
  keywords?: string[]
  regex?: string
  validator?: string
  exclude_fields?: string[]
  status?: ApiSensitiveTypeStatus
}

/** 类型导出文档（与导入格式对称，可回灌） */
export interface ApiSensitiveTypeExport {
  format: string
  version: number
  exported_at: string
  types: ApiSensitiveDataType[]
}

/** 类型导入结果（按 name upsert） */
export interface ApiSensitiveTypeImportResult {
  created: number
  updated: number
}

export const apiSensitiveTypesApi = {
  list: async (params: {
    status?: string
    level?: string
    category?: string
    keyword?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiSensitiveDataType>>(`/api-security/sensitive-types`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  create: (body: ApiSensitiveTypeBody) =>
    request<ApiSensitiveDataType>(`/api-security/sensitive-types`, { method: 'POST', body }),
  update: (id: string, body: ApiSensitiveTypeBody) =>
    request<ApiSensitiveDataType>(`/api-security/sensitive-types/${id}`, { method: 'PATCH', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/api-security/sensitive-types/${id}`, { method: 'DELETE' }),
  /** 导出全量类型（内置 + 自定义）为 JSON 文档 */
  exportTypes: () =>
    request<ApiSensitiveTypeExport>(`/api-security/sensitive-types/export`),
  /** 导入（按 name upsert；全量校验通过后单事务应用，单次 ≤500 条） */
  importTypes: (types: ApiSensitiveTypeBody[]) =>
    request<ApiSensitiveTypeImportResult>(`/api-security/sensitive-types/import`, {
      method: 'POST',
      body: { types },
    }),
}

/** 脱敏排除对象（键白名单 identity/role/ip；ip 项须为合法 IP 或 CIDR） */
export interface ApiMaskExclusions {
  identity?: string[]
  role?: string[]
  ip?: string[]
}

/** 脱敏规则（api_masking_rules） */
export interface ApiMaskingRule {
  id: string
  name: string
  enabled: boolean
  scope: ApiMaskingScope
  /** scope=APPLICATION 必填，其余 scope 为 null */
  application_id?: string | null
  /** scope=ENDPOINT 必填（METHOD + 空格 + 路径模板），其余 scope 为 null */
  endpoint_key?: string | null
  /** 目标字段点路径（与 data_type 至少其一） */
  field_path: string
  /** 目标数据类型标签（整类脱敏） */
  data_type?: string | null
  algorithm: ApiMaskingAlgorithm
  /** 算法参数对象（MASK 支持 keep_head/keep_tail，非负整数 ≤64） */
  params_json: Record<string, unknown>
  /** 排除对象 */
  exclusions_json: ApiMaskExclusions
  created_by?: string | null
  created_at: string
  updated_at: string
}

/**
 * 规则创建/编辑提交体（指针语义：仅提交的字段生效；
 * 可空字段 application_id/endpoint_key/data_type 显式传空串表示清除为 NULL）。
 */
export interface ApiMaskingRuleBody {
  name?: string
  enabled?: boolean
  scope?: ApiMaskingScope
  application_id?: string
  endpoint_key?: string
  field_path?: string
  data_type?: string
  algorithm?: ApiMaskingAlgorithm
  params_json?: Record<string, unknown>
  exclusions_json?: ApiMaskExclusions
}

export const apiMaskingRulesApi = {
  list: async (params: {
    scope?: string
    application_id?: string
    endpoint_key?: string
    enabled?: boolean
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiMaskingRule>>(`/api-security/masking-rules`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  create: (body: ApiMaskingRuleBody) =>
    request<ApiMaskingRule>(`/api-security/masking-rules`, { method: 'POST', body }),
  update: (id: string, body: ApiMaskingRuleBody) =>
    request<ApiMaskingRule>(`/api-security/masking-rules/${id}`, { method: 'PATCH', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/api-security/masking-rules/${id}`, { method: 'DELETE' }),
}

/** 敏感数据类型分布项 */
export interface ApiSensitiveTypeDistItem {
  data_type: string
  field_count: number
  endpoint_count: number
  occurrence_count: number
}

/** 敏感检测单日趋势点 */
export interface ApiSensitiveTrendPoint {
  date: string
  event_count: number
  hit_count: number
}

/** 敏感数据态势（GET /api-security/sensitive/overview） */
export interface ApiSensitiveOverview {
  sensitive_endpoint_count: number
  sensitive_field_count: number
  type_distribution: ApiSensitiveTypeDistItem[]
  trend: ApiSensitiveTrendPoint[]
  days: number
}

export const apiSensitiveOverviewApi = {
  get: (days?: number) =>
    request<ApiSensitiveOverview>(`/api-security/sensitive/overview`, {
      query: { days },
    }),
}
