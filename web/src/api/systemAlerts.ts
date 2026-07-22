import { request } from './client'
import type { PageResult, SystemAlertDetail, SystemAlertItem, SystemAlertNote } from '../types'

export interface SystemAlertListParams {
  status?: string
  severity?: string
  alert_type?: string
  component?: string
  page: number
  page_size: number
}

/**
 * 系统告警。
 * 权限：system_alerts.read（全部）/ system_alerts.read_security（安全类）/ system_alerts.read_audit（只读审计视角）；
 * 操作：system_alerts.acknowledge / system_alerts.resolve / system_alerts.acknowledge_security。
 */
export const systemAlertsApi = {
  list: async (params: SystemAlertListParams) => {
    const data = await request<PageResult<SystemAlertItem>>('/system-alerts', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<SystemAlertDetail>(`/system-alerts/${id}`),
  acknowledge: (id: string) =>
    request<SystemAlertItem>(`/system-alerts/${id}/acknowledge`, { method: 'POST' }),
  resolve: (id: string) => request<SystemAlertItem>(`/system-alerts/${id}/resolve`, { method: 'POST' }),
  ignore: (id: string) => request<SystemAlertItem>(`/system-alerts/${id}/ignore`, { method: 'POST' }),
  addNote: (id: string, note: string) =>
    request<SystemAlertNote>(`/system-alerts/${id}/notes`, { method: 'POST', body: { note } }),
}
