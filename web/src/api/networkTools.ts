import { buildUrl, request } from './client'
import type { NetworkToolAction, NetworkToolJob, PageResult } from '../types'

export interface NetworkToolJobListParams {
  page: number
  page_size: number
  action?: string
  status?: string
}

export interface CreateNetworkToolJobBody {
  action: NetworkToolAction
  target: string
  port?: number
  count?: number
  max_hops?: number
  duration_sec?: number
  iface?: string
  filter_proto?: 'tcp' | 'udp' | 'icmp' | ''
  filter_port?: number
  filter_host?: string
}

/** 网络工具诊断任务（network_tools.execute / network_tools.download） */
export const networkToolsApi = {
  list: async (params: NetworkToolJobListParams) => {
    const data = await request<PageResult<NetworkToolJob>>('/network-tools/jobs', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  create: async (body: CreateNetworkToolJobBody) =>
    (await request<{ job: NetworkToolJob }>('/network-tools/jobs', { method: 'POST', body })).job,
  get: async (id: string) =>
    (await request<{ job: NetworkToolJob }>(`/network-tools/jobs/${id}`)).job,
  stop: (id: string) =>
    request<{ message?: string }>(`/network-tools/jobs/${id}/stop`, { method: 'POST' }),
  /** pcap 下载地址（浏览器直接打开，携带会话 Cookie，后端记录下载审计） */
  downloadUrl: (id: string) => buildUrl(`/network-tools/jobs/${id}/download`),
}
