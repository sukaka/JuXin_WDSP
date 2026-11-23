import { request } from './client'
import type { PermissionItem, RoleDetail, RoleItem } from '../types'

export const rolesApi = {
  list: async (): Promise<{ items: RoleItem[] }> => {
    const data = await request<{ items: RoleItem[] | null }>('/roles')
    return { items: data.items ?? [] }
  },
  detail: async (id: string): Promise<RoleDetail> => {
    const data = await request<RoleDetail>(`/roles/${id}`)
    return { ...data, permissions: data.permissions ?? [] }
  },
  permissions: async (): Promise<{ items: PermissionItem[] }> => {
    const data = await request<{ items: PermissionItem[] | null }>('/permissions')
    return { items: data.items ?? [] }
  },
}
