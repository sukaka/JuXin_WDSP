import { request } from './client'
import type { ApmSettings, SettingItem } from '../types'

export interface UpdateSettingBody {
  setting_group: string
  setting_key: string
  // 按后端 value_type 提交 JSON 原生类型（boolean/integer 不能给字符串）
  setting_value: string | number | boolean
  version: number
}

export const settingsApi = {
  list: (group: string) =>
    request<{ items: SettingItem[] }>('/system-settings', { query: { group } }),
  update: (body: UpdateSettingBody) =>
    request<SettingItem>('/system-settings', { method: 'PUT', body }),
  syslogTest: () =>
    request<{ message: string }>('/system-settings/syslog-test', { method: 'POST' }),
}

/** APM 设置更新体：字段缺省=不变；clickhouse_dsn="" = 清除界面覆盖、回退环境变量 */
export interface UpdateApmSettingsBody {
  enabled?: boolean
  clickhouse_dsn?: string
}

export const apmSettingsApi = {
  get: () => request<ApmSettings>('/apm/settings'),
  update: (body: UpdateApmSettingsBody) =>
    request<unknown>('/apm/settings', { method: 'PUT', body }),
}
