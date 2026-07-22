import { request } from './client'
import type { PageResult } from '../types'

export interface ApiEndpointItem {
  id: string
  method: string
  path_template: string
  endpoint_key: string
  confidence: number
  status: string
  is_api: boolean
  hit_count: number
  first_seen_at: string
  last_seen_at: string
  confirmed_at?: string | null
}

export const apiEndpointsApi = {
  list: async (params: { status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiEndpointItem>>('/api-endpoints', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  discover: (body: { method: string; path: string; confidence?: number }) =>
    request<{ endpoint: ApiEndpointItem }>('/api-endpoints/discover', { method: 'POST', body }),
  confirm: (id: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(`/api-endpoints/${id}/confirm`, {
      method: 'POST',
    }),
}

export interface ApiModelVersion {
  id: string
  endpoint_id: string
  endpoint_key: string
  status: string
  schema: Record<string, string>
  content_hash: string
  created_at: string
  frozen_at?: string | null
}

export const apiModelsApi = {
  list: async (params: { endpoint_key?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiModelVersion>>('/api-model-versions', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  createCandidate: (body: {
    endpoint_id: string
    endpoint_key: string
    schema: Record<string, string>
  }) => request<{ version: ApiModelVersion; message: string }>('/api-model-versions', { method: 'POST', body }),
  confirm: (id: string) =>
    request<{ version: ApiModelVersion; message: string }>(`/api-model-versions/${id}/confirm`, {
      method: 'POST',
    }),
}

export const apiRuntimeEventsApi = {
  list: async (params: { page: number; page_size: number }) => {
    const data = await request<PageResult<Record<string, unknown>>>('/api-runtime-events', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}

export const productApi = {
  edition: () =>
    request<{
      edition: string
      api_dynamic_protection: boolean
    }>('/product/edition'),
}
