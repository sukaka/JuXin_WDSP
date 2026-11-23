import { request } from './client'
import type { NetworkConfigData, NetworkDesiredConfig } from '../types'

/** 节点网络配置：网桥与路由牵引（读 system_health.read；写 system_settings.update） */
export const networkConfigApi = {
  get: (nodeName?: string) =>
    request<NetworkConfigData>('/gateway/network-config', { query: { node_name: nodeName } }),
  /** 全量替换期望配置；node_name 通过 JSON 请求体可选指定（缺省为默认节点） */
  save: (body: NetworkDesiredConfig, nodeName?: string) => {
    const trimmed = nodeName?.trim()
    return request<NetworkConfigData>('/gateway/network-config', {
      method: 'PUT',
      body: trimmed ? { ...body, node_name: trimmed } : body,
    })
  },
}
