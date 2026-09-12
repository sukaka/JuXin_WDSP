import { request } from './client'
import type { NotificationChannel, NotificationMeta } from '../types'

/** 新增/更新通知渠道请求体 */
export interface NotificationChannelBody {
  name: string
  type: NotificationChannel['type']
  enabled: boolean
  min_severity: NotificationChannel['min_severity']
  /** 订阅类别 code 列表；空数组 = 全部类别 */
  categories: string[]
  config: Record<string, unknown>
}

/**
 * 告警通知渠道。
 * 权限：notification.read（查询）/ notification.update（增删改与启停）/ notification.test（发送测试）。
 */
export const notificationChannelsApi = {
  meta: () => request<NotificationMeta>('/notification-meta'),
  list: async () => {
    const data = await request<{ items: NotificationChannel[] | null }>('/notification-channels')
    return data.items ?? []
  },
  create: (body: NotificationChannelBody) =>
    request<NotificationChannel>('/notification-channels', { method: 'POST', body }),
  update: (id: string, body: NotificationChannelBody) =>
    request<NotificationChannel>(`/notification-channels/${id}`, { method: 'PUT', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/notification-channels/${id}`, { method: 'DELETE' }),
  test: (id: string) =>
    request<{ message: string }>(`/notification-channels/${id}/test`, { method: 'POST' }),
}
