import { request } from './client'
import type {
  PageResult,
  TrustedProxyDetail,
  TrustedProxyItem,
  TrustedProxyTestResult,
} from '../types'

export interface TrustedProxyListParams {
  keyword?: string
  status?: string
  header_type?: string
  page: number
  page_size: number
}

export interface TrustedProxyBody {
  name: string
  cidr: string
  header_type: string
  custom_header_name: string
  priority: number
  scope: string
  node_name: string
  description: string
}

export interface UpdateTrustedProxyBody extends TrustedProxyBody {
  /** 乐观锁版本号（后端校验不一致返回 409） */
  version: number
}

export interface TrustedProxyTestBody {
  cidr: string
  test_ips: string[]
}

export const trustedProxiesApi = {
  list: async (params: TrustedProxyListParams) => {
    const data = await request<PageResult<TrustedProxyItem>>('/trusted-proxies', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<TrustedProxyDetail>(`/trusted-proxies/${id}`),
  create: (body: TrustedProxyBody) =>
    request<TrustedProxyDetail>('/trusted-proxies', { method: 'POST', body }),
  update: (id: string, body: UpdateTrustedProxyBody) =>
    request<TrustedProxyDetail>(`/trusted-proxies/${id}`, { method: 'PUT', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/trusted-proxies/${id}`, { method: 'DELETE' }),
  enable: (id: string) =>
    request<{ message: string }>(`/trusted-proxies/${id}/enable`, { method: 'POST' }),
  disable: (id: string) =>
    request<{ message: string }>(`/trusted-proxies/${id}/disable`, { method: 'POST' }),
  test: (body: TrustedProxyTestBody) =>
    request<TrustedProxyTestResult>('/trusted-proxies/test', { method: 'POST', body }),
}
