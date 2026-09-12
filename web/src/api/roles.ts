import { request } from './client'
import type { PermissionItem, RoleDetail, RoleItem } from '../types'

export const rolesApi = {
  list: () => request<{ items: RoleItem[] }>('/roles'),
  detail: (id: string) => request<RoleDetail>(`/roles/${id}`),
  permissions: () => request<{ items: PermissionItem[] }>('/permissions'),
}
