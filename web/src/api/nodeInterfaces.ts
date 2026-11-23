import { request } from './client'
import type { NodeInterfaceOrderPayload, NodeInterfacesData } from '../types'

/** 节点网口管理（读 system_health.read；排序保存 system_settings.update） */
export const nodeInterfacesApi = {
  list: (nodeName?: string) =>
    request<NodeInterfacesData>('/gateway/interfaces', { query: { node_name: nodeName } }),
  saveOrder: (body: NodeInterfaceOrderPayload) =>
    request<NodeInterfacesData>('/gateway/interfaces/order', { method: 'PUT', body }),
}
