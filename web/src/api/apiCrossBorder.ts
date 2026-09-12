import { request } from './client'
import type { PageResult } from '../types'

/* ==================== 数据出境看板（server/internal/apigeo）：GET /api-security/cross-border ==================== */

/** 方向：OUT = 涉敏数据流向境外客户端（出境）；IN = 境外客户端提交涉敏数据（入境） */
export type ApiCrossBorderDirection = 'OUT' | 'IN'

/** 风险等级（由数据类型等级推导：CORE/IMPORTANT→HIGH，SENSITIVE/字典外→MEDIUM，其余→LOW） */
export type ApiCrossBorderRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH'

/** 跨境观察记录（api_cross_border_events） */
export interface ApiCrossBorderEvent {
  id: string
  occurred_at: string
  client_ip: string
  /** ISO 3166-1 alpha-2 国家码 */
  country: string
  asn?: number | null
  endpoint_key: string
  /** 身份指纹（匿名流量为空串） */
  identity_fingerprint: string
  data_types: string[] | null
  direction: ApiCrossBorderDirection
  risk_level: ApiCrossBorderRiskLevel
  source_event_id: string
  created_at: string
}

/** 窗口内汇总 */
export interface ApiCrossBorderSummary {
  total_events: number
  /** 涉及境外国家/地区数 */
  country_count: number
  /** 涉及端点数 */
  endpoint_count: number
  high_risk_count: number
}

/** 国家/地区聚合项 */
export interface ApiCrossBorderCountryStat {
  country: string
  event_count: number
  endpoint_count: number
  data_types: string[] | null
}

/** 国家/地区×敏感类型聚合项（一事件多类型时每类型各计一次） */
export interface ApiCrossBorderCountryTypeStat {
  country: string
  data_type: string
  event_count: number
}

/** 端点聚合项（上限 50） */
export interface ApiCrossBorderEndpointStat {
  endpoint_key: string
  event_count: number
  /** 该端点涉及的境外国家/地区数 */
  country_count: number
}

/** 单日趋势点 */
export interface ApiCrossBorderTrendPoint {
  date: string
  event_count: number
}

/** 看板聚合（geo_enabled/home_regions 元信息由响应顶层携带） */
export interface ApiCrossBorderDashboard {
  days: number
  summary: ApiCrossBorderSummary
  by_country: ApiCrossBorderCountryStat[]
  by_country_type: ApiCrossBorderCountryTypeStat[]
  by_endpoint: ApiCrossBorderEndpointStat[]
  trend: ApiCrossBorderTrendPoint[]
}

/** 看板 + 明细组合响应（单端点返回） */
export interface ApiCrossBorderResponse {
  /** GeoIP 数据源是否可用（false 时看板可能为历史数据，页面降级提示） */
  geo_enabled: boolean
  /** 当前本土地区判定基准（settings api_data.home_regions） */
  home_regions: string[]
  dashboard: ApiCrossBorderDashboard | null
  /** 明细分页（与看板同窗口；country/direction/risk_level/endpoint_key 仅过滤明细） */
  events: PageResult<ApiCrossBorderEvent>
}

export const apiCrossBorderApi = {
  /** 看板 + 明细分页（days 默认 7 上限 30，作用于看板与明细） */
  get: async (params: {
    days?: number
    country?: string
    direction?: string
    risk_level?: string
    endpoint_key?: string
    page: number
    page_size: number
  }) => {
    const data = await request<ApiCrossBorderResponse>(`/api-security/cross-border`, {
      query: { ...params },
    })
    return { ...data, events: { ...data.events, items: data.events?.items ?? [] } }
  },
}
