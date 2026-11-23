import { buildUrl, request } from './client'
import type { AccessControlEventDetail, AccessControlEventItem, PageResult } from '../types'

export interface AccessControlEventListParams {
  start_time?: string
  end_time?: string
  application_id?: string
  client_ip?: string
  event_type?: string
  action?: string
  policy_id?: string
  request_id?: string
  gateway_node_id?: string
  page: number
  page_size: number
}

export type AccessControlEventExportParams = Partial<
  Omit<AccessControlEventListParams, 'page' | 'page_size'>
> & { ids?: string }

export const accessControlEventsApi = {
  list: async (params: AccessControlEventListParams) => {
    const data = await request<PageResult<AccessControlEventItem>>('/access-control-events', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<AccessControlEventDetail>(`/access-control-events/${id}`),
  /** 导出 CSV 下载地址（浏览器直接打开，携带会话 Cookie） */
  exportUrl: (params: AccessControlEventExportParams = {}) =>
    buildUrl('/access-control-events/export', { ...params }),
}
