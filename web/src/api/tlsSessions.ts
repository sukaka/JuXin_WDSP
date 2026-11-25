import { request } from './client'
import type { PageResult, TLSSessionItem, TLSSessionSummary } from '../types'

export interface TLSSessionListParams {
  page: number
  page_size: number
  start_time?: string
  end_time?: string
  sni?: string
  client_ip?: string
  detected_protocol?: string
  action?: string
  is_gm?: 'true' | 'false'
  application_id?: string
}

export interface TLSSessionSummaryParams {
  start_time?: string
  end_time?: string
  application_id?: string
}

export const tlsSessionsApi = {
  list: async (params: TLSSessionListParams) => {
    const data = await request<PageResult<TLSSessionItem>>('/tls-sessions', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  summary: async (params: TLSSessionSummaryParams) => {
    const data = await request<TLSSessionSummary>('/tls-sessions/summary', {
      query: { ...params },
    })
    return {
      ...data,
      by_protocol: data.by_protocol ?? [],
      by_cipher_suite: data.by_cipher_suite ?? [],
    }
  },
}
