import { request } from './client'
import type {
  AccessControlOverviewData,
  AnalyticsTrendData,
  AppStat,
  CcOverviewData,
  CountList,
  DispositionOverviewData,
  RuleStat,
  SiteAccessTrendsData,
  SiteAccessTrendDomainsData,
  SourceIPStat,
  URIStat,
} from '../types'

/** 统计分析查询参数（start_time/end_time 为 RFC3339；range 由前端换算为起止时间） */
export interface AnalyticsParams {
  start_time?: string
  end_time?: string
  application_id?: string
  /** 快捷时间范围：1h/24h/7d/30d/today（前端换算为 start_time/end_time） */
  range?: string
}

const RANGE_MS: Record<string, number> = {
  '1h': 3600_000,
  '24h': 24 * 3600_000,
  '7d': 7 * 24 * 3600_000,
  '30d': 30 * 24 * 3600_000,
}

/** 后端仅接受 start_time/end_time：range 在此换算（缺省最近 24 小时；today 为本地当日零点至今） */
function toQuery(params: AnalyticsParams): Record<string, string> {
  const query: Record<string, string> = {}
  if (params.start_time && params.end_time) {
    query.start_time = params.start_time
    query.end_time = params.end_time
  } else if (params.range === 'today') {
    const end = new Date()
    const start = new Date(end)
    start.setHours(0, 0, 0, 0)
    query.end_time = end.toISOString()
    query.start_time = start.toISOString()
  } else {
    const span = RANGE_MS[params.range ?? ''] ?? RANGE_MS['24h']
    const end = new Date()
    query.end_time = end.toISOString()
    query.start_time = new Date(end.getTime() - span).toISOString()
  }
  if (params.application_id) query.application_id = params.application_id
  return query
}

/** 统计分析接口（analytics.security.read / analytics.disposition.read） */
export const analyticsApi = {
  /** 请求趋势（series: requests/p50_ms/p95_ms/p99_ms；另含请求方法、Content-Type 主类型、客户端 IP 来源与可信代理来源分布） */
  requestTrend: (params: AnalyticsParams) =>
    request<AnalyticsTrendData>('/analytics/request-trend', { query: toQuery(params) }),
  /** 安全事件趋势（series: events/blocks/observes） */
  securityEventTrend: (params: AnalyticsParams) =>
    request<AnalyticsTrendData>('/analytics/security-event-trend', { query: toQuery(params) }),
  /** 风险等级分布 */
  riskLevels: async (params: AnalyticsParams) =>
    (await request<CountList>('/analytics/risk-levels', { query: toQuery(params) })).items ?? [],
  /** 攻击类型分布 */
  attackTypes: async (params: AnalyticsParams) =>
    (await request<CountList>('/analytics/attack-types', { query: toQuery(params) })).items ?? [],
  /** 攻击源 IP 排行 */
  topSourceIps: async (params: AnalyticsParams) =>
    (await request<CountList<SourceIPStat>>('/analytics/top-source-ips', { query: toQuery(params) })).items ?? [],
  /** 被攻击应用排行 */
  topApplications: async (params: AnalyticsParams) =>
    (await request<CountList<AppStat>>('/analytics/top-applications', { query: toQuery(params) })).items ?? [],
  /** 命中规则排行 */
  topRules: async (params: AnalyticsParams) =>
    (await request<CountList<RuleStat>>('/analytics/top-rules', { query: toQuery(params) })).items ?? [],
  /** 被攻击 URI 排行 */
  topUris: async (params: AnalyticsParams) =>
    (await request<CountList<URIStat>>('/analytics/top-uris', { query: toQuery(params) })).items ?? [],
  /** CC 防护概览 */
  ccOverview: (params: AnalyticsParams) =>
    request<CcOverviewData>('/analytics/cc-overview', { query: toQuery(params) }),
  /** 访问控制概览 */
  accessControlOverview: (params: AnalyticsParams) =>
    request<AccessControlOverviewData>('/analytics/access-control-overview', { query: toQuery(params) }),
  /** 事件处置统计 */
  dispositionOverview: (params: AnalyticsParams) =>
    request<DispositionOverviewData>('/analytics/disposition-overview', { query: toQuery(params) }),
  /** 网站访问趋势（按应用聚合，含零流量应用，按总访问量降序；时间跨度上限 7 天） */
  siteAccessTrends: (params: AnalyticsParams) =>
    request<SiteAccessTrendsData>('/analytics/site-access-trends', { query: toQuery(params) }),
  /** 网站访问趋势-域名钻取（指定应用下各域名的访问量与趋势） */
  siteAccessTrendDomains: (params: AnalyticsParams & { application_id: string }) =>
    request<SiteAccessTrendDomainsData>('/analytics/site-access-trends/domains', { query: toQuery(params) }),
}
