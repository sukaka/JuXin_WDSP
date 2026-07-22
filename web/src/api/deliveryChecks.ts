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
  run: () => request<DeliveryCheckItem>('/delivery-checks/run', { method: 'POST' }),
  get: (id: string) => request<DeliveryCheckDetail>(`/delivery-checks/${id}`),
  /** 导出地址（浏览器直接打开，携带会话 Cookie） */
  exportUrl: (id: string) => buildUrl(`/delivery-checks/${id}/export`),
}
