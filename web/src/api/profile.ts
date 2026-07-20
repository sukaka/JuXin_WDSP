import { request } from './client'
import type { LoginLogEntry, PageResult, ProfileData } from '../types'

export const profileApi = {
  get: () => request<ProfileData>('/profile'),
  update: (body: { display_name: string; version: number }) =>
    request<ProfileData>('/profile', { method: 'PUT', body }),
  loginLogs: (page: number, pageSize: number) =>
    request<PageResult<LoginLogEntry>>('/profile/login-logs', {
      query: { page, page_size: pageSize },
    }),
}
