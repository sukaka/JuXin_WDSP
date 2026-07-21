import { request } from './client'
import type { ExceptionAction, ExceptionDetail, ExceptionItem, PageResult } from '../types'

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
}

export const exceptionsApi = {
  list: async (params: ExceptionListParams) => {
    const data = await request<PageResult<ExceptionItem>>('/exceptions', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<ExceptionDetail>(`/exceptions/${id}`),
  create: (body: CreateExceptionBody) =>
    request<ExceptionDetail>('/exceptions', { method: 'POST', body }),
  remove: (id: string) => request<{ message: string }>(`/exceptions/${id}`, { method: 'DELETE' }),
  enable: (id: string) => request<{ message: string }>(`/exceptions/${id}/enable`, { method: 'POST' }),
  disable: (id: string) => request<{ message: string }>(`/exceptions/${id}/disable`, { method: 'POST' }),
}
