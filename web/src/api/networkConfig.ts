import { request } from './client'
import type { NetworkConfigData, NetworkDesiredConfig } from '../types'

/** 节点网络配置：网桥与路由牵引（读 system_health.read；写 system_settings.update） */
export const networkConfigApi = {
  get: (nodeName?: string) =>
    request<NetworkConfigData>('/gateway/network-config', { query: { node_name: nodeName } }),
  /** 全量替换期望配置；节点通过 node_name 查询参数指定（与 GET 对齐） */
  save: (body: NetworkDesiredConfig, nodeName?: string) =>
    request<{ message?: string }>('/gateway/network-config', {
      method: 'PUT',
      query: { node_name: nodeName },
      body,
    }),
}
