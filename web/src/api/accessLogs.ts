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
  page: number
  page_size: number
}

export const accessLogsApi = {
  list: async (params: AccessLogListParams) => {
    const data = await request<PageResult<AccessLogItem>>('/access-logs', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<AccessLogDetail>(`/access-logs/${id}`),
  /** 导出 CSV（过滤参数与列表一致，上限 10000 行） */
  exportUrl: (
    params: Partial<Omit<AccessLogListParams, 'page' | 'page_size'>>,
  ) => buildUrl('/access-logs/export', { ...params }),
}
