import { buildUrl, request } from './client'
import type { AuditEntry, PageResult, VerifyChainResult } from '../types'

export interface AuditParams {
  username?: string
  module?: string
  action?: string
  result?: string
  risk_level?: string
  start_time?: string
  end_time?: string
  page: number
  page_size: number
}

export const auditsApi = {
  list: (params: AuditParams) =>
    request<PageResult<AuditEntry>>('/audits', { query: { ...params } }),
  detail: (id: string) => request<AuditEntry>(`/audits/${id}`),
  verifyChain: () => request<VerifyChainResult>('/audits/verify-chain', { method: 'POST' }),
  exportUrl: (params: Omit<AuditParams, 'page' | 'page_size'> & { ids?: string }) =>
    buildUrl('/audits/export', { ...params }),
}
