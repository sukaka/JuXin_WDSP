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
  loginLogs: (params: LoginLogParams) =>
    request<PageResult<LoginLogEntry>>('/login-logs', { query: { ...params } }),
  /** CSV 导出地址（浏览器导航自动携带 Cookie） */
  loginLogsExportUrl: (params: Omit<LoginLogParams, 'page' | 'page_size'>) =>
    buildUrl('/login-logs/export', { ...params }),
}
