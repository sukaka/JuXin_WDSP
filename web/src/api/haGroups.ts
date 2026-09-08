import { request } from './client'
import type { HaGroup, HaGroupDetailData, HaGroupListData, HaGroupUpsert } from '../types'

/** 主备高可用（读 ha.read；写 ha.manage） */
export const haGroupsApi = {
  list: () => request<HaGroupListData>('/ha/groups'),
  create: (body: HaGroupUpsert) => request<{ group?: HaGroup }>('/ha/groups', { method: 'POST', body }),
  get: (id: string) => request<HaGroupDetailData>(`/ha/groups/${id}`),
  update: (id: string, body: HaGroupUpsert) =>
    request<{ group?: HaGroup }>(`/ha/groups/${id}`, { method: 'PATCH', body }),
  remove: (id: string) => request<{ message?: string }>(`/ha/groups/${id}`, { method: 'DELETE' }),
  /** 人工回切：把 VIP 切到指定节点（必要时调整成员优先级并重新下发） */
  failback: (id: string, nodeId: string) =>
    request<{ message?: string; group?: HaGroup }>(`/ha/groups/${id}/failback`, {
      method: 'POST',
      body: { node_id: nodeId },
    }),
}
