import { buildUrl, request } from './client'
import type { DeliveryCheckDetail, DeliveryCheckItem, PageResult } from '../types'

/** 交付检查（delivery_checks.read / delivery_checks.run） */
export const deliveryChecksApi = {
  list: async (params: { page: number; page_size: number }) => {
    const data = await request<PageResult<DeliveryCheckItem>>('/delivery-checks', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  run: async () => {
    const data = await request<DeliveryCheckDetail>('/delivery-checks/run', { method: 'POST' })
    return { ...data, results: data.results ?? [] }
  },
  get: async (id: string) => {
    const data = await request<DeliveryCheckDetail>(`/delivery-checks/${id}`)
    return { ...data, results: data.results ?? [] }
  },
  /** 导出地址（浏览器直接打开，携带会话 Cookie） */
  exportUrl: (id: string) => buildUrl(`/delivery-checks/${id}/export`),
}
