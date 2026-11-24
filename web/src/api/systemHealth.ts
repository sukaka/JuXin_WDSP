import { request } from './client'
import type {
  GatewayTrendRange,
  GatewayTrendResponse,
  RuntimeComponent,
  StorageOverview,
  SystemHealthData,
} from '../types'

/** 系统运行监控（system_health.read；大屏只读接口同步放行 big_screen.runtime.read） */
export const systemHealthApi = {
  overview: () => request<SystemHealthData>('/system-health'),
  components: async () => {
    const data = await request<{ components?: RuntimeComponent[] | null; checked_at?: string }>(
      '/system-health/components',
    )
    return { components: data.components ?? [], checked_at: data.checked_at }
  },
  storage: () => request<StorageOverview>('/system-health/storage'),
  gatewayTrend: async (range: GatewayTrendRange = '10m') => {
    const data = await request<GatewayTrendResponse>('/system-health/gateway-trend', {
      query: { range },
    })
    return {
      ...data,
      points: data.points ?? [],
      applications: data.applications ?? [],
    }
  },
}
