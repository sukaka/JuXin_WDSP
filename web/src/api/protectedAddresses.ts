import { request } from './client'
import type {
  ProtectedAddressDetail,
  ProtectedAddressItem,
  ProtectedAddressRefreshResult,
} from '../types'

export interface ProtectedAddressListParams {
  address_type?: string
}

/** 创建自定义保护地址：address 与 cidr 必须且只能填写一个 */
export interface CreateProtectedAddressBody {
  name: string
  address?: string
  cidr?: string
  description: string
}

export const protectedAddressesApi = {
  // 保护地址列表不分页（系统登记 + 自定义，量级有限）
  list: async (params: ProtectedAddressListParams = {}) => {
    const data = await request<{ items: ProtectedAddressItem[] }>('/protected-addresses', {
      query: { ...params },
    })
    return { items: data.items ?? [] }
  },
  create: (body: CreateProtectedAddressBody) =>
    request<ProtectedAddressDetail>('/protected-addresses', { method: 'POST', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/protected-addresses/${id}`, { method: 'DELETE' }),
  refresh: () =>
    request<ProtectedAddressRefreshResult>('/protected-addresses/refresh', { method: 'POST' }),
}
