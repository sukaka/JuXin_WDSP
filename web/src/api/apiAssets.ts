import { request } from './client'
import type { PageResult } from '../types'

/** API 端点资产（/api-security/endpoints，字段与 server/internal/apiassets.Endpoint 一致） */
export interface ApiEndpointItem {
  id: string
  application_id?: string | null
  /** 所属站点名称（未归属时为空字符串） */
  application_name: string
  /** 归一化目录路径（未归类时为空字符串） */
  directory_path: string
  domain_id?: string | null
  http_method: string
  normalized_path: string
  raw_path_example: string
  endpoint_key: string
  protocol_type: string
  api_confidence: number
  asset_status: string
  learning_status: string
  is_api: boolean
  hit_count: number
  first_seen_at: string
  last_seen_at: string
  confirmed_at?: string | null
  current_model_version_id?: string | null
  classification_locked: boolean
  created_at: string
  updated_at: string
}

export const apiEndpointsApi = {
  list: async (params: {
    asset_status?: string
    learning_status?: string
    keyword?: string
    application_id?: string
    /** 目录前缀过滤（含子目录） */
    directory_path?: string
    /** 仅查未归属站点的端点 */
    unassigned?: boolean
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiEndpointItem>>('/api-security/endpoints', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 站点归属汇总：各站点端点数 + 未归属数 */
  siteSummary: async () => {
    const data = await request<{
      items: { application_id: string; application_name: string; endpoint_count: number }[]
      unassigned: number
    }>('/api-security/endpoints/site-summary')
    return { items: data.items ?? [], unassigned: data.unassigned ?? 0 }
  },
  /** 目录扁平列表（按站点过滤；不传 application_id 查全部，unassigned=true 查未归属），前端按段组装层级 */
  directoryTree: async (params: { application_id?: string; unassigned?: boolean }) => {
    const data = await request<{
      items: { directory_path: string; endpoint_count: number }[]
    }>('/api-security/endpoints/directory-tree', {
      query: { ...params },
    })
    return data.items ?? []
  },
  /** 批量确认（页面行内操作传单个 id） */
  confirm: (ids: string[]) =>
    request<{ confirmed: number; confirmed_ids: string[]; failed: { id: string; reason: string }[] }>(
      '/api-security/endpoints/confirm',
      { method: 'POST', body: { ids } },
    ),
  ignore: (id: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(`/api-security/endpoints/${id}/ignore`, {
      method: 'POST',
      body: {},
    }),
}

/** 接口模型版本（字段与 server/internal/apimodels.Version 一致） */
export interface ApiModelVersion {
  id: string
  api_endpoint_id: string
  endpoint_key: string
  status: string
  schema: Record<string, string>
  content_hash: string
  version_number: number
  change_summary: string
  created_reason: string
  created_at: string
  confirmed_at?: string | null
  activated_at?: string | null
}

export const apiModelsApi = {
  /** 模型版本按端点查询 */
  list: async (endpointId: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiModelVersion>>(
      `/api-security/endpoints/${endpointId}/models`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  createCandidate: (endpointId: string, body: { schema: Record<string, string>; change_summary?: string }) =>
    request<{ version: ApiModelVersion; message: string }>(
      `/api-security/endpoints/${endpointId}/models`,
      { method: 'POST', body },
    ),
  /** 确认冻结为正式模型 */
  confirm: (id: string) =>
    request<{ version: ApiModelVersion; message: string }>(`/api-security/models/${id}/confirm`, {
      method: 'POST',
      body: {},
    }),
}

export const apiRuntimeEventsApi = {
  list: async (params: {
    endpoint_key?: string
    final_action?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<Record<string, unknown>>>('/api-security/runtime/events', {
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
