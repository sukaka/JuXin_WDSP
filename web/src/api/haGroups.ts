import { request } from './client'
import type {
  HaEvent,
  HaGroup,
  HaGroupDetailData,
  HaGroupListData,
  HaGroupUpsert,
  HaSyncResult,
  PageResult,
} from '../types'

export interface HaEventListParams {
  group_id?: string
  node_name?: string
  event_type?: string
  page?: number
  page_size?: number
}

export interface HaGroupMutationResult {
  group?: HaGroup
  message?: string
  sync_results?: HaSyncResult[]
}

/** 主备高可用（读 ha.read；写 ha.manage） */
export const haGroupsApi = {
  list: () => request<HaGroupListData>('/ha/groups'),
  create: (body: HaGroupUpsert) =>
    request<HaGroupMutationResult>('/ha/groups', { method: 'POST', body }),
  get: (id: string) => request<HaGroupDetailData>(`/ha/groups/${id}`),
  update: (id: string, body: HaGroupUpsert) =>
    request<HaGroupMutationResult>(`/ha/groups/${id}`, { method: 'PATCH', body }),
  remove: (id: string) =>
    request<{ message?: string; sync_results?: HaSyncResult[] }>(`/ha/groups/${id}`, {
      method: 'DELETE',
    }),
  /** 人工回切：把 VIP 切到指定节点（必要时调整成员优先级并重新下发） */
  failback: (id: string, nodeId: string) =>
    request<HaGroupMutationResult>(`/ha/groups/${id}/failback`, {
      method: 'POST',
      body: { node_id: nodeId },
    }),
  /** 持久化 HA 历史事件分页查询（GET /ha/events） */
  listEvents: async (params?: HaEventListParams) => {
    const data = await request<PageResult<HaEvent>>('/ha/events', {
      query: params ? { ...params } : undefined,
    })
    return { ...data, items: data.items ?? [] }
  },
}
