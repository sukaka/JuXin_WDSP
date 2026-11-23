import { request } from './client'
import type { LoginLogEntry, PageResult, ProfileData, UserItem } from '../types'

export const profileApi = {
  get: () => request<ProfileData>('/profile'),
  update: (body: { display_name: string; version: number }) =>
    request<UserItem>('/profile', { method: 'PUT', body }),
  loginLogs: async (page: number, pageSize: number): Promise<PageResult<LoginLogEntry>> => {
    const data = await request<PageResult<LoginLogEntry>>('/profile/login-logs', {
      query: { page, page_size: pageSize },
    })
    return { ...data, items: data.items ?? [] }
  },
}
