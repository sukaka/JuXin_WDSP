import { request } from './client'

/**
 * API 安全态势总览（GET /api/v1/api-security/posture/overview，W9-P101）。
 * 字段口径与 server/internal/apisecurity.PostureOverview 一致（逐字段注释见后端结构体）。
 */
export interface ApiPostureOverview {
  generated_at: string
  /** 近 24h API 访问量（api_endpoint_traffic_buckets 5 分钟桶求和，桶留存 7 天） */
  traffic_24h: number
  /** 近 24h 防护量（api_runtime_events 处置动作 BLOCK/TEMP_BLOCK/RATE_LIMIT/MASK_RESPONSE 计数） */
  protected_24h: number
  /** API 资产总数（api_endpoints 全量） */
  assets_total: number
  /** 近 24h 新增 API（端点 created_at） */
  assets_new_24h: number
  /** Shadow：SHADOW 类型未闭环（NEW/CONFIRMED/IN_PROGRESS）风险发现数 */
  shadow_open: number
  /** Zombie：asset_status=ZOMBIE（已下线仍有流量） */
  zombie_total: number
  /** Deprecated：asset_status=DEPRECATED */
  deprecated_total: number
  /** 涉敏 API：api_sensitive_fields 去重端点数 */
  sensitive_endpoints: number
  /** 高风险 API：asset_value ∈ HIGH/CRITICAL */
  high_risk_assets: number
  /** 无认证 API：从未观测到带认证类型身份画像的端点数 */
  unauthenticated_endpoints: number
  /** 待确认模型：api_model_versions status ∈ CANDIDATE/IN_REVIEW */
  models_pending: number
  /** 近 24h 运行时 Schema 偏离（api_schema_violations） */
  schema_deviations_24h: number
}

/** 单日趋势点（Date 为 UTC 日界 YYYY-MM-DD，服务端补零为连续点列） */
export interface ApiPostureTrendPoint {
  date: string
  /** 访问量（流量桶当日求和；留存 7 天，days>7 时更早日期为 0） */
  traffic: number
  /** 防护量（处置动作事件当日计数） */
  protected: number
  /** 风险新增（api_runtime_findings created_at 当日计数） */
  risk: number
  /** 新增 API（端点 created_at 当日计数） */
  new_endpoints: number
  /** Schema 偏离（api_schema_violations occurred_at 当日计数） */
  schema_deviations: number
  /** 敏感数据命中（事件明细含 sensitive_data 检测的当日计数） */
  sensitive_hits: number
}

/** 按天桶趋势（GET /api/v1/api-security/posture/trends?days=N） */
export interface ApiPostureTrends {
  days: number
  points: ApiPostureTrendPoint[]
}

/** W10-SEC 访问来源：客户端 IP Top 项（IP 已脱敏：IPv4 末段 *，IPv6 前 48bit + :*） */
export interface ApiPostureSourceIP {
  client_ip: string
  count: number
}

/** 地域归属分桶（HOME/FOREIGN/INTERNAL/UNKNOWN 四桶零补齐；geo_enabled=false 时为空数组） */
export interface ApiPostureGeoScope {
  scope: string
  count: number
}

/** 国家码 Top 项（ISO 3166-1 alpha-2，仅 geo_enabled=true 时有数据） */
export interface ApiPostureSourceCountry {
  country: string
  count: number
}

/** 身份指纹 Top 项（指纹截断 12 字符 + …，不可逆 HMAC 指纹不落明文凭据） */
export interface ApiPostureSourceIdentity {
  fingerprint: string
  count: number
}

/** 认证类型分布项（auth_type 空串 = 匿名流量） */
export interface ApiPostureSourceAuthType {
  auth_type: string
  count: number
}

/**
 * 访问来源聚合（GET /api/v1/api-security/posture/sources?days=N，W10-SEC）。
 * 口径：api_runtime_events 只落安全相关事件，反映「事件来源分布」而非全量流量；
 * api_runtime_events 无 UA 列，User-Agent 族维度不提供（后端 runtime.go 有注释说明）。
 */
export interface ApiPostureSources {
  days: number
  /** GeoIP 数据源是否可用（false 时 geo_scopes/top_countries 如实为空） */
  geo_enabled: boolean
  /** distinct 客户端 IP 超上限截断标注（仅 geo_enabled 时有意义） */
  geo_truncated: boolean
  top_client_ips: ApiPostureSourceIP[]
  geo_scopes: ApiPostureGeoScope[]
  top_countries: ApiPostureSourceCountry[]
  top_identities: ApiPostureSourceIdentity[]
  auth_types: ApiPostureSourceAuthType[]
}

/** API 访问量 Top 项（流量桶窗口求和；桶留存 7 天，days>7 时更早日期不计） */
export interface ApiPostureTargetTraffic {
  endpoint_id: string
  endpoint_key: string
  request_count: number
}

/** API 风险发现 Top 项（窗口内 findings 新增计数） */
export interface ApiPostureTargetFindings {
  endpoint_id: string
  endpoint_key: string
  findings_count: number
}

/** 应用访问量 Top 项（application_name 空串 = 未分组端点聚合） */
export interface ApiPostureTargetApplication {
  application_id?: string
  application_name: string
  request_count: number
}

/** 涉敏 API Top 项（按窗口访问量降序，附敏感字段数） */
export interface ApiPostureTargetSensitive {
  endpoint_id: string
  endpoint_key: string
  request_count: number
  sensitive_fields: number
}

/** 高风险 API Top 项（asset_value ∈ HIGH/CRITICAL，按窗口访问量降序） */
export interface ApiPostureTargetHighRisk {
  endpoint_id: string
  endpoint_key: string
  asset_value: string
  request_count: number
}

/** 访问目标排名（GET /api/v1/api-security/posture/targets?days=N，W10-SEC） */
export interface ApiPostureTargets {
  days: number
  top_by_traffic: ApiPostureTargetTraffic[]
  top_by_findings: ApiPostureTargetFindings[]
  top_applications: ApiPostureTargetApplication[]
  top_sensitive: ApiPostureTargetSensitive[]
  top_high_risk: ApiPostureTargetHighRisk[]
}

/** W9-P101 态势总览/趋势（与 apiSecurity.ts 既有 apiPostureApi「旧 /posture 契约」区分命名） */
export const apiPostureOverviewApi = {
  /** 顶部核心指标总览（12 项真实聚合） */
  overview: () => request<ApiPostureOverview>('/api-security/posture/overview'),
  /** 按天趋势（days 限定 1-30，缺省 7） */
  trends: (days: number) =>
    request<ApiPostureTrends>('/api-security/posture/trends', {
      query: { days },
    }),
  /** W10-SEC 访问来源聚合（IP/Geo/身份/认证类型；days 限定 1-30，缺省 7） */
  sources: (days: number) =>
    request<ApiPostureSources>('/api-security/posture/sources', {
      query: { days },
    }),
  /** W10-SEC 访问目标排名（API 双口径/应用/涉敏/高风险；days 限定 1-30，缺省 7） */
  targets: (days: number) =>
    request<ApiPostureTargets>('/api-security/posture/targets', {
      query: { days },
    }),
}
