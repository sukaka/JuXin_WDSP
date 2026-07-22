import { request } from './client'
import type { PageResult, RestoreJobItem, RestorePreviewData } from '../types'

export interface RestoreListParams {
  status?: string
  page: number
  page_size: number
}

/**
 * 恢复任务（backups.restore）。
 * 流程：选择备份 → validate 校验预览 → 创建恢复任务（异步隔离恢复）→
 * 状态进入 AWAITING_CONFIRM → confirm 确认执行正式恢复（高危二次确认）。
 */
export const restoresApi = {
  list: async (params: RestoreListParams) => {
    const data = await request<PageResult<RestoreJobItem>>('/restores', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  /** 校验备份并生成恢复预览（不创建任务，不修改数据） */
  validate: async (backupJobId: string) =>
    (
      await request<{ preview: RestorePreviewData }>('/restores/validate', {
        method: 'POST',
        body: { backup_job_id: backupJobId },
      })
    ).preview,
  /** 创建恢复任务（异步执行隔离恢复，完成后待确认） */
  create: async (body: { backup_job_id: string; scope: string }) =>
    (await request<{ job: RestoreJobItem }>('/restores', { method: 'POST', body })).job,
  get: async (id: string) => (await request<{ job: RestoreJobItem }>(`/restores/${id}`)).job,
  /** 确认执行正式恢复（高危操作，后端要求二次确认理由可选） */
  confirm: (id: string, reason?: string) =>
    request<{ job: RestoreJobItem; post_verify?: unknown }>(`/restores/${id}/confirm`, {
      method: 'POST',
      body: { reason: reason ?? '' },
    }),
  cancel: (id: string) => request<{ message: string }>(`/restores/${id}/cancel`, { method: 'POST' }),
}
