import { request } from './client'
import type { SettingItem } from '../types'

export interface UpdateSettingBody {
  setting_group: string
  setting_key: string
  setting_value: string
  version: number
}

export const settingsApi = {
  list: (group: string) =>
    request<{ items: SettingItem[] }>('/system-settings', { query: { group } }),
  update: (body: UpdateSettingBody) =>
    request<SettingItem>('/system-settings', { method: 'PUT', body }),
}
