import { buildUrl, request } from './client'
import type { AccessLogDetail, AccessLogItem, PageResult } from '../types'

export interface AccessLogListParams {
  start_time?: string
  end_time?: string
  domain?: string
  client_ip?: string
  method?: string
  uri?: string
  status?: number
  waf_action?: string
  request_id?: string
  application_id?: string
  trace_id?: string
  identity_fingerprint?: string
  rule_id?: string
  endpoint_key?: string
  field_path?: string
  data_type?: string
  direction?: 'REQUEST' | 'RESPONSE'
  request_ids?: string
  page: number
  page_size: number
}

export type AccessLogTrendParams = Partial<Omit<AccessLogListParams, 'page' | 'page_size'>> & {
  bucket_seconds?: number
}

export interface AccessLogTrendPoint {
  bucket: string
  total: number
  blocked: number
  errors: number
}

export interface AccessLogTrendResult {
  items: AccessLogTrendPoint[]
  bucket_seconds: number
  start_time?: string
  end_time?: string
}

export type AccessLogFlowParams = AccessLogTrendParams & { node_limit?: number }

export interface FlowNode {
  id: string
  name: string
  kind: 'SOURCE' | 'ACCOUNT' | 'REQUEST_FIELD' | 'APPLICATION' | 'API' | 'RESPONSE_FIELD'
  request_count: number
  field_hits: number
  verified: boolean
  other: boolean
  aggregated_nodes?: number
  filters: Record<string, string>
  request_ids: string[]
  drill_exact: boolean
}

export interface FlowEdge {
  id: string
  source_id: string
  target_id: string
  request_count: number
  field_hits: number
  filters: Record<string, string>
  request_ids: string[]
  drill_exact: boolean
}

export interface FlowResult {
  nodes: FlowNode[]
  edges: FlowEdge[]
  request_count: number
  sensitive_request_count: number
  start_time: string
  end_time: string
  truncated: boolean
  data_source: string
}

export const accessLogsApi = {
  list: async (params: AccessLogListParams) => {
    const data = await request<PageResult<AccessLogItem>>('/access-logs', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  trend: async (params: AccessLogTrendParams) => {
    const data = await request<AccessLogTrendResult>('/access-logs/trend', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  flow: async (params: AccessLogFlowParams) => {
    const data = await request<FlowResult>('/access-logs/flow', { query: { ...params } })
    return {
      ...data,
      nodes: (data.nodes ?? []).map((node) => ({ ...node, request_ids: node.request_ids ?? [] })),
      edges: (data.edges ?? []).map((edge) => ({ ...edge, request_ids: edge.request_ids ?? [] })),
    }
  },
  get: (id: string) => request<AccessLogDetail>(`/access-logs/${id}`),
  /** 导出 CSV（过滤参数与列表一致，支持按勾选 ids 导出，上限 10000 行） */
  exportUrl: (
    params: Partial<Omit<AccessLogListParams, 'page' | 'page_size'>> & { ids?: string },
  ) => buildUrl('/access-logs/export', { ...params }),
}
