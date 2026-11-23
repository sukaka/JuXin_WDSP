import { buildUrl, request } from './client'
import type {
  PageResult,
  SystemAlertDetail,
  SystemAlertItem,
  SystemAlertMaintenanceWindow,
  SystemAlertMaintenanceWindowCreateInput,
  SystemAlertNote,
} from '../types'

export interface SystemAlertListParams {
  status?: string
  view?: 'ACTIVE' | 'SILENCED' | 'HISTORY'
  severity?: string
  alert_type?: string
  component?: string
  page: number
  page_size: number
}

export type SystemAlertExportParams = Partial<Omit<SystemAlertListParams, 'page' | 'page_size'>> & {
  ids?: string
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
  /** 导出 CSV 下载地址（浏览器直接打开，携带会话 Cookie） */
  exportUrl: (params: SystemAlertExportParams = {}) => buildUrl('/system-alerts/export', { ...params }),
  /** 维护窗口列表（阶段6 §11.5） */
  listMaintenanceWindows: async () => {
    const data = await request<{ items?: SystemAlertMaintenanceWindow[] | null; total: number }>(
      '/system-alerts/maintenance-windows',
    )
    return { ...data, items: data.items ?? [] }
  },
  createMaintenanceWindow: (input: SystemAlertMaintenanceWindowCreateInput) =>
    request<SystemAlertMaintenanceWindow>('/system-alerts/maintenance-windows', { method: 'POST', body: input }),
  deleteMaintenanceWindow: (id: string) =>
    request<{ message: string }>(`/system-alerts/maintenance-windows/${id}`, { method: 'DELETE' }),
}
