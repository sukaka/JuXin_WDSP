import { request } from './client'
import type {
  PageResult,
  ProtectedAddressDetail,
  ProtectedAddressItem,
  ProtectedAddressRefreshResult,
} from '../types'

export interface ProtectedAddressListParams {
  address_type?: string
  page: number
  page_size: number
}

/** 创建自定义保护地址：address 与 cidr 必须且只能填写一个 */
export interface CreateProtectedAddressBody {
  name: string
  address?: string
  cidr?: string
  description: string
}

export const protectedAddressesApi = {
  list: async (params: ProtectedAddressListParams) => {
    const data = await request<PageResult<ProtectedAddressItem>>('/protected-addresses', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  create: (body: CreateProtectedAddressBody) =>
    request<ProtectedAddressDetail>('/protected-addresses', { method: 'POST', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/protected-addresses/${id}`, { method: 'DELETE' }),
  refresh: () =>
    request<ProtectedAddressRefreshResult>('/protected-addresses/refresh', { method: 'POST' }),
}
