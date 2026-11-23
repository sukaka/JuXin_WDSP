import { buildUrl, request } from './client'
import type {
  AccessControlEventItem,
  AccessRuleDetail,
  AccessRuleImportResult,
  AccessRuleItem,
  AccessRuleValidateResult,
  PageResult,
  PublishTaskItem,
} from '../types'

export interface AccessRuleListParams {
  rule_type?: string
  scope_type?: string
  application_id?: string
  status?: string
  source_type?: string
  keyword?: string
  address?: string
  page: number
  page_size: number
}

export type AccessRuleExportParams = Partial<Omit<AccessRuleListParams, 'page' | 'page_size'>> & {
  ids?: string
}

export interface CreateAccessRuleBody {
  name: string
  rule_type: string
  scope_type: string
  application_id?: string | null
  address: string
  priority?: number
  validity_type: string
  effective_from?: string | null
  effective_until?: string | null
  reason: string
  /** 来源类型：缺省 MANUAL；事件联动创建传 SECURITY_EVENT（须携带 source_event_id） */
  source_type?: 'MANUAL' | 'SECURITY_EVENT'
  /** 来源安全事件 ID（仅 source_type=SECURITY_EVENT 时传） */
  source_event_id?: string | null
}

/** 更新规则（rule_type/scope_type/application_id 不可变更，后端忽略） */
export interface UpdateAccessRuleBody {
  name: string
  address: string
  priority?: number
  validity_type: string
  effective_from?: string | null
  effective_until?: string | null
  reason: string
  /** 乐观锁版本号（后端校验不一致返回 409） */
  version: number
}

export interface ImportAccessRulesBody {
  content: string
  format: 'csv' | 'text'
  /** ALL_OR_NOTHING 全部成功才提交 / SKIP_ERRORS 跳过错误行 */
  mode: 'ALL_OR_NOTHING' | 'SKIP_ERRORS'
  rule_type: string
  scope_type: string
  application_id?: string | null
  effective_until?: string | null
  reason?: string
  /** true 时只校验预览不落库 */
  dry_run?: boolean
}

export const accessRulesApi = {
  list: async (params: AccessRuleListParams) => {
    const data = await request<PageResult<AccessRuleItem>>('/access-rules', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<AccessRuleDetail>(`/access-rules/${id}`),
  create: (body: CreateAccessRuleBody) =>
    request<AccessRuleDetail>('/access-rules', { method: 'POST', body }),
  update: (id: string, body: UpdateAccessRuleBody) =>
    request<AccessRuleDetail>(`/access-rules/${id}`, { method: 'PUT', body }),
  remove: (id: string) => request<{ message: string }>(`/access-rules/${id}`, { method: 'DELETE' }),
  enable: (id: string) =>
    request<{ message: string }>(`/access-rules/${id}/enable`, { method: 'POST' }),
  disable: (id: string) =>
    request<{ message: string }>(`/access-rules/${id}/disable`, { method: 'POST' }),
  extend: (id: string, effectiveUntil: string) =>
    request<{ message: string }>(`/access-rules/${id}/extend`, {
      method: 'POST',
      body: { effective_until: effectiveUntil },
    }),
  release: (id: string) =>
    request<{ message: string }>(`/access-rules/${id}/release`, { method: 'POST' }),
  copy: (id: string) => request<AccessRuleDetail>(`/access-rules/${id}/copy`, { method: 'POST' }),
  import: (body: ImportAccessRulesBody) =>
    request<AccessRuleImportResult>('/access-rules/import', { method: 'POST', body }),
  validate: (body: CreateAccessRuleBody) =>
    request<AccessRuleValidateResult>('/access-rules/validate', { method: 'POST', body }),
  /** 发布访问控制配置到网关（与配置发布共用发布任务） */
  publish: (idempotencyKey: string) =>
    request<PublishTaskItem>('/access-rules/publish', {
      method: 'POST',
      body: { idempotency_key: idempotencyKey },
    }),
  /** 导出 CSV 下载地址（浏览器直接打开，携带会话 Cookie） */
  exportUrl: (params: AccessRuleExportParams = {}) => buildUrl('/access-rules/export', { ...params }),
  /** 规则关联事件（按 access_rule_id 过滤访问控制事件，§8.5） */
  listEvents: async (id: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<AccessControlEventItem>>(`/access-rules/${id}/events`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}
