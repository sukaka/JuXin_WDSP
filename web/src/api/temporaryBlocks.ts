import { request } from './client'
import type {
  PageResult,
  TemporaryBlockConvertResult,
  TemporaryBlockDetail,
  TemporaryBlockItem,
} from '../types'

export interface TemporaryBlockListParams {
  status?: string
  client_ip?: string
  application_id?: string
  page: number
  page_size: number
}

export const temporaryBlocksApi = {
  list: async (params: TemporaryBlockListParams) => {
    const data = await request<PageResult<TemporaryBlockItem>>('/temporary-blocks', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<TemporaryBlockDetail>(`/temporary-blocks/${id}`),
  release: (id: string) =>
    request<{ message: string }>(`/temporary-blocks/${id}/release`, { method: 'POST' }),
  /** 延长封禁，newExpiresAt 必须为 RFC3339 时间 */
  extend: (id: string, newExpiresAt: string) =>
    request<{ message: string }>(`/temporary-blocks/${id}/extend`, {
      method: 'POST',
      body: { new_expires_at: newExpiresAt },
    }),
  /** 转永久封禁（生成 DENY 规则，高风险操作） */
  convertToPermanent: (id: string) =>
    request<TemporaryBlockConvertResult>(`/temporary-blocks/${id}/convert-to-permanent`, {
      method: 'POST',
    }),
}
