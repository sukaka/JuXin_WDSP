import { request } from './client'
import type { PageResult } from '../types'

export interface SharedDeviceQuery {
  start: string
  end: string
  application_id?: string
  device_fingerprint?: string
  min_accounts: number
  page: number
  page_size: number
}

export interface SharedDeviceGroup {
  application_id: string
  application_name: string
  device_fingerprint: string
  distinct_accounts: number
  event_count: number
  signal_count: number
  endpoint_count: number
  gateway_node_count: number
  first_seen_at: string
  last_seen_at: string
}

export interface SharedDeviceResult extends PageResult<SharedDeviceGroup> {
  partial: boolean
  data_scope: 'NOTABLE_SECURITY_EVENTS'
}

export interface SharedDeviceAccountQuery {
  start: string
  end: string
  application_id: string
  device_fingerprint: string
  page: number
  page_size: number
}

export interface SharedDeviceAccount {
  principal_ref: string
  event_count: number
  signal_count: number
  endpoint_count: number
  first_seen_at: string
  last_seen_at: string
}

export interface SharedDeviceAccountResult extends PageResult<SharedDeviceAccount> {
  partial: boolean
  data_scope: 'NOTABLE_SECURITY_EVENTS'
}

export type SharedDeviceBucket = 'hour' | 'day'

export interface SharedDeviceTrendQuery {
  start: string
  end: string
  application_id?: string
  device_fingerprint?: string
  min_accounts: number
  bucket?: SharedDeviceBucket
}

export interface SharedDeviceTrendPoint {
  bucket: string
  group_count: number
  signal_count: number
  event_count: number
}

export interface SharedDeviceTrendResult {
  items: SharedDeviceTrendPoint[]
  start: string
  end: string
  bucket: SharedDeviceBucket
  partial: boolean
  data_scope: 'NOTABLE_SECURITY_EVENTS'
}

export const apiGroupControlApi = {
  sharedDevices: async (params: SharedDeviceQuery) => {
    const data = await request<SharedDeviceResult>(
      '/api-security/group-control/shared-devices',
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  sharedDeviceAccounts: async (params: SharedDeviceAccountQuery) => {
    const data = await request<SharedDeviceAccountResult>(
      '/api-security/group-control/shared-devices/accounts',
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  trends: async (params: SharedDeviceTrendQuery) => {
    const data = await request<SharedDeviceTrendResult>(
      '/api-security/group-control/trends',
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
}
