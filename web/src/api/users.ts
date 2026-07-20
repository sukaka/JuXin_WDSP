import { request } from './client'
import type { PageResult, UserItem } from '../types'

export interface UserListParams {
  username?: string
  status?: string
  role_code?: string
  page: number
  page_size: number
}

export interface CreateUserBody {
  username: string
  display_name: string
  role_code: string
}

export interface CreateUserResult {
  user: UserItem
  temporary_password: string
  notice?: string
}

export interface UpdateUserBody {
  display_name: string
  role_code: string
  version: number
}

export const usersApi = {
  list: (params: UserListParams) =>
    request<PageResult<UserItem>>('/users', { query: { ...params } }),
  get: (id: string) => request<UserItem>(`/users/${id}`),
  create: (body: CreateUserBody) =>
    request<CreateUserResult>('/users', { method: 'POST', body }),
  update: (id: string, body: UpdateUserBody) =>
    request<UserItem>(`/users/${id}`, { method: 'PUT', body }),
  remove: (id: string) => request<null>(`/users/${id}`, { method: 'DELETE' }),
  enable: (id: string) => request<null>(`/users/${id}/enable`, { method: 'POST' }),
  disable: (id: string) => request<null>(`/users/${id}/disable`, { method: 'POST' }),
  unlock: (id: string) => request<null>(`/users/${id}/unlock`, { method: 'POST' }),
  resetPassword: (id: string) =>
    request<{ temporary_password: string; notice?: string }>(`/users/${id}/reset-password`, {
      method: 'POST',
    }),
  forceLogout: (id: string) => request<null>(`/users/${id}/sessions`, { method: 'DELETE' }),
}
