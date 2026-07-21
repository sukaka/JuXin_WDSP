import { buildUrl, request } from './client'
import type {
  CreateExceptionFromEventResult,
  PageResult,
  SecurityEventDetail,
  SecurityEventItem,
} from '../types'

export interface SecurityEventListParams {
  start_time?: string
  end_time?: string
  application_id?: string
  domain?: string
  client_ip?: string
  uri?: string
  method?: string
  attack_type?: string
  severity?: string
  action?: string
  rule_id?: number | string
  disposition_status?: string
  request_id?: string
  gateway_node?: string
  page: number
  page_size: number
}

export interface DispositionBody {
  result?: string
  note?: string
}

export const securityEventsApi = {
  list: async (params: SecurityEventListParams) => {
    const data = await request<PageResult<SecurityEventItem>>('/security-events', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: async (id: string) => {
    const data = await request<SecurityEventDetail>(`/security-events/${id}`)
    // 后端对无匹配/备注/记录返回 null（Go nil slice），统一归一化为空数组
    return {
      ...data,
      matches: data.matches ?? [],
      notes: data.notes ?? [],
      actions: data.actions ?? [],
      related: data.related ?? [],
    }
  },
  related: async (id: string) => {
    const data = await request<{ items: SecurityEventItem[] }>(`/security-events/${id}/related`)
    return { items: data.items ?? [] }
  },
  addNote: (id: string, note: string) =>
    request<{ message: string }>(`/security-events/${id}/notes`, { method: 'POST', body: { note } }),
  confirmAttack: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/confirm-attack`, { method: 'POST', body }),
  confirmFalsePositive: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/confirm-false-positive`, {
      method: 'POST',
      body,
    }),
  ignore: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/ignore`, { method: 'POST', body }),
  resolve: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/resolve`, { method: 'POST', body }),
  markAnalyzing: (id: string, body: DispositionBody = {}) =>
    request<{ message: string }>(`/security-events/${id}/mark-analyzing`, { method: 'POST', body }),
  createException: (id: string) =>
    request<CreateExceptionFromEventResult>(`/security-events/${id}/create-exception`, {
      method: 'POST',
    }),
  /** 导出 CSV（后端仅支持 start_time/end_time/domain/attack_type/severity 过滤） */
  exportUrl: (
    params: Pick<
      SecurityEventListParams,
      'start_time' | 'end_time' | 'domain' | 'attack_type' | 'severity'
    >,
  ) => buildUrl('/security-events/export', { ...params }),
}
