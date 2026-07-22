import { request } from './client'
import type { RuntimeComponent, StorageOverview, SystemHealthData } from '../types'

/** 系统运行监控（system_health.read） */
export const systemHealthApi = {
  overview: () => request<SystemHealthData>('/system-health'),
  components: async () => {
    const data = await request<{ components?: RuntimeComponent[] | null; checked_at?: string }>(
      '/system-health/components',
    )
    return { components: data.components ?? [], checked_at: data.checked_at }
  },
  storage: () => request<StorageOverview>('/system-health/storage'),
}
