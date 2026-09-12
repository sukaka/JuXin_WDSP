import { request } from './client'
import type {
  ApiExceptionRuleRef,
  ExceptionAction,
  ExceptionDetail,
  ExceptionItem,
  ExceptionPreviewResult,
  ExceptionTargetEngine,
  PageResult,
} from '../types'

export interface ExceptionListParams {
  scope_type?: string
  status?: string
  page: number
  page_size: number
}

export interface CreateExceptionBody {
  name: string
  description: string
  scope_type: string
  application_id?: string | null
  policy_id?: string | null
  domain: string
  uri_exact: string
  uri_prefix: string
  uri_regex: string
  methods: string[]
  source_ips: string[]
  param_names: string[]
  cookie_names: string[]
  header_names: string[]
  rule_ids: number[]
  rule_tags: string[]
  attack_types: string[]
  content_types: string[]
  exception_action: ExceptionAction
  action_target: string
  is_temporary: boolean
  effective_from?: string | null
  effective_until?: string | null
  risk_acknowledged: boolean
  reason: string
  /** 目标引擎（P0-04，迁移 000130；缺省 WAF） */
  target_engine?: ExceptionTargetEngine
  /** API 规则引用（target_engine=API 且 OBSERVE_RULE 时非空，S4 §3） */
  api_rule_refs?: ApiExceptionRuleRef[]
}

/** 更新例外（PUT /exceptions/{id}）；携带当前 version 做乐观并发校验，冲突返回 409 */
export interface UpdateExceptionBody extends CreateExceptionBody {
  version: number
}

export const exceptionsApi = {
  list: async (params: ExceptionListParams) => {
    const data = await request<PageResult<ExceptionItem>>('/exceptions', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<ExceptionDetail>(`/exceptions/${id}`),
  create: (body: CreateExceptionBody) =>
    request<ExceptionDetail>('/exceptions', { method: 'POST', body }),
  update: (id: string, body: UpdateExceptionBody) =>
    request<ExceptionDetail>(`/exceptions/${id}`, { method: 'PUT', body }),
  remove: (id: string) => request<{ message: string }>(`/exceptions/${id}`, { method: 'DELETE' }),
  enable: (id: string) => request<{ message: string }>(`/exceptions/${id}/enable`, { method: 'POST' }),
  disable: (id: string) => request<{ message: string }>(`/exceptions/${id}/disable`, { method: 'POST' }),
  /** 影响预览（P0-04 S4 §8）：不启用、不发布、不回放；expected_version 与当前版本不符返回 409 */
  preview: (id: string, expected_version: number) =>
    request<ExceptionPreviewResult>(`/exceptions/${id}/preview`, {
      method: 'POST',
      body: { expected_version },
    }),
}
