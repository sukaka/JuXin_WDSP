import { request } from './client'
import type {
  AccessControlEventItem,
  PageResult,
  PublishTaskItem,
  URLWhitelistRuleDetail,
  URLWhitelistRuleItem,
} from '../types'

export interface URLWhitelistListParams {
  scope_type?: string
  application_id?: string
  match_type?: string
  status?: string
  source_type?: string
  keyword?: string
  page: number
  page_size: number
}

export interface CreateURLWhitelistBody {
  name: string
  scope_type: 'GLOBAL' | 'APPLICATION'
  application_id?: string | null
  match_type: 'EXACT' | 'PREFIX' | 'REGEX'
  uri_pattern: string
  methods?: string[]
  priority?: number
  validity_type: 'PERMANENT' | 'TEMPORARY'
  effective_from?: string | null
  effective_until?: string | null
  reason: string
  source_type?: 'MANUAL' | 'SECURITY_EVENT'
  source_event_id?: string | null
}

export interface UpdateURLWhitelistBody {
  name: string
  match_type: 'EXACT' | 'PREFIX' | 'REGEX'
  uri_pattern: string
  methods?: string[]
  priority?: number
  validity_type: 'PERMANENT' | 'TEMPORARY'
  effective_from?: string | null
  effective_until?: string | null
  reason: string
  version: number
}

export const urlWhitelistsApi = {
  list: async (params: URLWhitelistListParams) => {
    const data = await request<PageResult<URLWhitelistRuleItem>>('/url-whitelists', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<URLWhitelistRuleDetail>(`/url-whitelists/${id}`),
  create: (body: CreateURLWhitelistBody) =>
    request<URLWhitelistRuleDetail>('/url-whitelists', { method: 'POST', body }),
  update: (id: string, body: UpdateURLWhitelistBody) =>
    request<URLWhitelistRuleDetail>(`/url-whitelists/${id}`, { method: 'PUT', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/url-whitelists/${id}`, { method: 'DELETE' }),
  enable: (id: string) =>
    request<{ message: string }>(`/url-whitelists/${id}/enable`, { method: 'POST' }),
  disable: (id: string) =>
    request<{ message: string }>(`/url-whitelists/${id}/disable`, { method: 'POST' }),
  extend: (id: string, effectiveUntil: string) =>
    request<{ message: string }>(`/url-whitelists/${id}/extend`, {
      method: 'POST',
      body: { effective_until: effectiveUntil },
    }),
  release: (id: string) =>
    request<{ message: string }>(`/url-whitelists/${id}/release`, { method: 'POST' }),
  publish: (idempotencyKey: string) =>
    request<PublishTaskItem>('/url-whitelists/publish', {
      method: 'POST',
      body: { idempotency_key: idempotencyKey },
    }),
  listEvents: async (id: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<AccessControlEventItem>>(`/url-whitelists/${id}/events`, {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}
