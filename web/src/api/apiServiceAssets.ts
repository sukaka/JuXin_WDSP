import { request } from './client'
import type { PageResult } from '../types'

/* ==================== 服务资产（server/internal/apiassets §14）：upstreams 主机:端口 聚合视图 ==================== */

/** 服务资产（host:port 粒度，与 server/internal/apiassets.ServiceAsset 一致） */
export interface ApiServiceAsset {
  /** upstreams.normalized_host（主机名或 IP） */
  server_ip: string
  /** upstreams.port */
  port: number
  /** 承载应用数（去重） */
  application_count: number
  /** 归属 API 端点数 */
  api_count: number
  /** 近 7 天请求量（traffic buckets 留存窗口聚合） */
  traffic_7d: number
  /** 含敏感字段的端点数 */
  sensitive_api_count: number
  /** 未闭环风险发现数（findings NEW/CONFIRMED/IN_PROGRESS） */
  risk_count: number
}

export const apiServiceAssetsApi = {
  /** 服务资产分页列表（按 host,port 升序） */
  list: async (params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiServiceAsset>>('/api-security/service-assets', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}
