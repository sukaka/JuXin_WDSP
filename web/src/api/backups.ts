import { buildUrl, request } from './client'
import type { BackupJobItem, BackupVerifyResult, PageResult } from '../types'

export interface BackupListParams {
  backup_type?: string
  status?: string
  page: number
  page_size: number
}

/**
 * 备份任务（backups.read / backups.create / backups.verify / backups.delete）。
 * 恢复与删除备份属于高风险操作，页面层必须二次确认。
 */
export const backupsApi = {
  list: async (params: BackupListParams) => {
    const data = await request<PageResult<BackupJobItem>>('/backups', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  create: async (body: { backup_type: 'FULL' | 'CONFIG_ONLY' }) =>
    (await request<{ job: BackupJobItem }>('/backups', { method: 'POST', body })).job,
  get: async (id: string) => (await request<{ job: BackupJobItem }>(`/backups/${id}`)).job,
  /** 验证失败时后端返回 400 及原因文案，前端按错误提示展示 */
  verify: (id: string) =>
    request<{ verified: boolean; result?: BackupVerifyResult }>(`/backups/${id}/verify`, { method: 'POST' }),
  /** 下载地址（浏览器直接打开，携带会话 Cookie） */
  downloadUrl: (id: string) => buildUrl(`/backups/${id}/download`),
  remove: (id: string) => request<{ message: string }>(`/backups/${id}`, { method: 'DELETE' }),
}
