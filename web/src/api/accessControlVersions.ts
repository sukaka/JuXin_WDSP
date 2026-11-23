import { request } from './client'
import type { PageResult } from '../types'

export interface AccessControlVersionItem {
  id: string
  version_no: number
  config_hash: string
  change_summary: string
  previous_version_id?: string | null
  publish_task_id?: string | null
  publish_result: string
  created_by?: string | null
  created_at: string
}

export interface AccessControlVersionDetail extends AccessControlVersionItem {
  config?: unknown
}

export interface AccessControlVersionDiff {
  version_id: string
  version_no: number
  compare_with: string
  compare_with_no: number
  differences: string[]
}

export const accessControlVersionsApi = {
  list: async (params: { page: number; page_size: number }) => {
    const data = await request<PageResult<AccessControlVersionItem>>('/access-control/versions', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) =>
    request<{ version: AccessControlVersionDetail }>(`/access-control/versions/${id}`),
  diff: async (id: string, compareWith?: string) => {
    const data = await request<AccessControlVersionDiff>(`/access-control/versions/${id}/diff`, {
      query: compareWith ? { compare_with: compareWith } : undefined,
    })
    return { ...data, differences: data.differences ?? [] }
  },
  rollback: (id: string) =>
    request<{ message: string; result?: unknown }>(`/access-control/versions/${id}/rollback`, {
      method: 'POST',
    }),
}
