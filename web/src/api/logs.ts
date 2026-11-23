import { buildUrl, request } from './client'
import type { LoginLogEntry, PageResult } from '../types'

export interface LoginLogParams {
  username?: string
  source_ip?: string
  result?: string
  event_type?: string
  start_time?: string
  end_time?: string
  page: number
  page_size: number
}

export const logsApi = {
  loginLogs: async (params: LoginLogParams): Promise<PageResult<LoginLogEntry>> => {
    const data = await request<PageResult<LoginLogEntry>>('/login-logs', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  /** CSV 导出地址（浏览器导航自动携带 Cookie；支持筛选与按勾选 ids 导出） */
  loginLogsExportUrl: (params: Omit<LoginLogParams, 'page' | 'page_size'> & { ids?: string }) =>
    buildUrl('/login-logs/export', { ...params }),
}
