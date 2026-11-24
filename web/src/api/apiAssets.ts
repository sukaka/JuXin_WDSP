import { buildUrl, request } from './client'
import type { PageResult } from '../types'

/** 资产价值评分单维得分（asset_value_explain.dimensions 元素，与 apiassets.ScoreDimension 一致） */
export interface ApiAssetValueDimension {
  name: string
  score: number
  max: number
  input: string
  reason: string
}

/** 资产价值评分明细（asset_value_explain 列，与 apiassets.AssetValueScore 一致） */
export interface ApiAssetValueExplain {
  /** LOW / MEDIUM / HIGH / CRITICAL */
  level: string
  total: number
  max_total: number
  computed_at?: string
  dimensions: ApiAssetValueDimension[]
}

/** API 接口资产（/api-security/endpoints，字段与 server/internal/apiassets.Endpoint 一致） */
export interface ApiEndpointItem {
  id: string
  application_id?: string | null
  /** 所属站点名称（未归属时为空字符串） */
  application_name: string
  /** 所属站点主域名（无域名记录时为空字符串；展示时优先于名称） */
  application_domain?: string
  /** 归一化目录路径（未归类时为空字符串） */
  directory_path: string
  domain_id?: string | null
  http_method: string
  normalized_path: string
  raw_path_example: string
  endpoint_key: string
  protocol_type: string
  api_confidence: number
  asset_status: string
  learning_status: string
  is_api: boolean
  hit_count: number
  first_seen_at: string
  last_seen_at: string
  confirmed_at?: string | null
  current_model_version_id?: string | null
  classification_locked: boolean
  /** 资产价值等级（LOW/MEDIUM/HIGH/CRITICAL；未评分为空） */
  asset_value?: string
  /** 资产价值评分明细（各维得分/上限/输入/理由；未评分为空） */
  asset_value_explain?: ApiAssetValueExplain | null
  /** 僵尸态起点（asset_status=ZOMBIE 时置位） */
  zombie_since?: string | null
  /** 业务标签（13 值枚举，设计文档 #12.1；未标注为空字符串） */
  business_type?: string
  /** 自由标签（api_assets.tags，列表带出；无资产记录为空） */
  tags?: string[]
  /** 资产档案（详情接口附带；列表不返回） */
  asset?: ApiEndpointAsset | null
}

/** API 资产档案（api_assets，与 server/internal/apiassets.Asset 一致；owner 即系统负责人） */
export interface ApiEndpointAsset {
  endpoint_id: string
  purpose: string
  exposure: string
  data_classification: string
  owner: string
  tags: string[]
  business_type: string
  organization: string
  business_system: string
  technical_owner: string
  data_owner: string
  data_level: string
  api_level: string
  auth_type: string
  created_at: string
  updated_at: string
}

/** 资产档案可编辑字段（PATCH 全量替换语义，前端提交完整表单） */
export interface ApiAssetProfileInput {
  purpose: string
  exposure: string
  owner: string
  tags: string[]
  business_type: string
  organization: string
  business_system: string
  technical_owner: string
  data_owner: string
  data_level: string
  api_level: string
  auth_type: string
}

/** 数据等级词表（UNKNOWN=未标注） */
export const API_DATA_LEVEL_META: Record<string, { label: string }> = {
  UNKNOWN: { label: '未标注' },
  CORE: { label: '核心数据' },
  IMPORTANT: { label: '重要数据' },
  GENERAL: { label: '一般数据' },
}

/** API 等级词表（UNKNOWN=未标注） */
export const API_LEVEL_META: Record<string, { label: string }> = {
  UNKNOWN: { label: '未标注' },
  LEVEL_1: { label: '一级' },
  LEVEL_2: { label: '二级' },
  LEVEL_3: { label: '三级' },
}

/** 认证方式词表（空串=未标注） */
export const API_AUTH_TYPE_META: Record<string, { label: string }> = {
  '': { label: '未标注' },
  NONE: { label: '无认证' },
  BASIC: { label: 'Basic 认证' },
  API_KEY: { label: 'API Key' },
  TOKEN: { label: 'Token' },
  JWT: { label: 'JWT' },
  OAUTH2: { label: 'OAuth 2.0' },
  MTLS: { label: '双向 TLS（mTLS）' },
  SESSION: { label: '会话（Session/Cookie）' },
  OTHER: { label: '其他' },
}

/**
 * 由已保存档案构造 PATCH 全量表单（无档案记录时给零值）。
 * 服务端 Update 为全量替换语义，任何局部修改（如仅改业务标签）都必须经此函数合并，避免清空其他字段。
 */
export function assetProfileInput(
  asset: ApiEndpointAsset | null | undefined,
  overrides: Partial<ApiAssetProfileInput> = {},
): ApiAssetProfileInput {
  return {
    purpose: asset?.purpose ?? '',
    exposure: asset?.exposure ?? '',
    owner: asset?.owner ?? '',
    tags: asset?.tags ?? [],
    business_type: asset?.business_type ?? '',
    organization: asset?.organization ?? '',
    business_system: asset?.business_system ?? '',
    technical_owner: asset?.technical_owner ?? '',
    data_owner: asset?.data_owner ?? '',
    data_level: asset?.data_level ?? '',
    api_level: asset?.api_level ?? '',
    auth_type: asset?.auth_type ?? '',
    ...overrides,
  }
}

/** 业务标签词表（PATCH /api-security/endpoints/{id} 的 business_type 枚举，设计文档 #12.1） */
export const API_BUSINESS_TYPE_META: Record<string, { label: string }> = {
  LOGIN: { label: '登录' },
  REGISTER: { label: '注册' },
  PASSWORD_RESET: { label: '找回密码' },
  SMS: { label: '短信发送' },
  EMAIL: { label: '邮件发送' },
  ORDER: { label: '下单' },
  PAYMENT: { label: '支付' },
  EXPORT: { label: '导出' },
  DOWNLOAD: { label: '下载' },
  SEARCH: { label: '搜索' },
  QUERY_PERSONAL_DATA: { label: '查询个人数据' },
  AI_INFERENCE: { label: 'AI推理' },
  OTHER: { label: '其他' },
}

/** 接口访问趋势时间范围 */
export type ApiTrafficTrendRange = '1h' | '24h' | '7d'

/** 接口访问趋势（/api-security/endpoints/{id}/traffic-trend）：points 为服务端补零后的连续时间桶（升序） */
export interface ApiTrafficTrend {
  endpoint_id: string
  bucket_seconds: number
  range: ApiTrafficTrendRange
  total: number
  points: { time: string; count: number }[]
}

/** API 资产清单导出筛选参数（与列表接口一致，不含分页参数） */
export interface ApiEndpointListExportParams {
  asset_status?: string
  learning_status?: string
  keyword?: string
  application_id?: string
  directory_path?: string
  unassigned?: boolean
  include_non_api?: boolean
  business_type?: string
  ids?: string
}

/** API 资产发现静态资源与非 API 过滤配置（与 server/internal/apiassets.DiscoveryFilterConfig 一致） */
export interface ApiDiscoveryFilterConfig {
  exclude_static_assets: boolean
  filter_non_api: boolean
  exclude_extensions: string[]
  exclude_path_prefixes: string[]
  include_path_prefixes: string[]
}

/** 存量噪声扫描命中的单条候选端点 */
export interface NoiseEndpointCandidate {
  id: string
  application_id?: string | null
  application_name?: string
  http_method: string
  normalized_path: string
  directory_path: string
  endpoint_key: string
  asset_status: string
  is_api: boolean
  api_confidence: number
  hit_count: number
  last_seen_at: string
  reason: string
}

/** 存量噪声扫描预览结果 */
export interface NoiseCleanupPreview {
  total: number
  protected_skipped: number
  by_reason: Record<string, number>
  items: NoiseEndpointCandidate[]
}

/** 存量噪声执行清理结果 */
export interface NoiseCleanupResult {
  action: 'DELETE' | 'IGNORE' | string
  affected: number
  protected_skipped: number
  by_reason: Record<string, number>
  sample_keys: string[]
}

export const apiEndpointsApi = {
  list: async (params: {
    asset_status?: string
    learning_status?: string
    keyword?: string
    application_id?: string
    /** 目录前缀过滤（含子目录） */
    directory_path?: string
    /** 仅查未归属站点的接口 */
    unassigned?: boolean
    /** 是否包含历史非 API 记录（默认仅查 is_api=true） */
    include_non_api?: boolean
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiEndpointItem>>(
      '/api-security/endpoints',
      {
        query: { ...params },
      },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** 分页拉取某站点下全量接口（遵守后端 page_size<=100 上限） */
  listAllByApplication: async (applicationId: string): Promise<ApiEndpointItem[]> => {
    const pageSize = 100
    const first = await apiEndpointsApi.list({
      application_id: applicationId,
      page: 1,
      page_size: pageSize,
    })
    const items = [...first.items]
    const total = first.total ?? items.length
    const totalPages = Math.ceil(total / pageSize)
    for (let page = 2; page <= totalPages; page++) {
      const next = await apiEndpointsApi.list({
        application_id: applicationId,
        page,
        page_size: pageSize,
      })
      if (next.items.length === 0) break
      items.push(...next.items)
    }
    return items
  },
  /** 单个 API 详细档案下载 URL（JSON；浏览器直接打开，不经前端缓存） */
  detailExportUrl: (id: string) =>
    buildUrl(`/api-security/endpoints/${id}/export`, { format: 'json' }),
  /** 当前筛选条件下的 API 资产清单下载 URL（CSV；浏览器直接打开） */
  listExportUrl: (params: ApiEndpointListExportParams = {}) =>
    buildUrl('/api-security/endpoints/export', { ...params, format: 'csv' }),
  /** 站点归属汇总：各站点接口数 + 未归属数 */
  siteSummary: async () => {
    const data = await request<{
      items: {
        application_id: string
        application_name: string
        application_domain?: string
        endpoint_count: number
      }[]
      unassigned: number
    }>('/api-security/endpoints/site-summary')
    return { items: data.items ?? [], unassigned: data.unassigned ?? 0 }
  },
  /** 目录扁平列表（按站点过滤；不传 application_id 查全部，unassigned=true 查未归属），前端按段组装层级 */
  directoryTree: async (params: {
    application_id?: string
    unassigned?: boolean
  }) => {
    const data = await request<{
      items: { directory_path: string; endpoint_count: number }[]
    }>('/api-security/endpoints/directory-tree', {
      query: { ...params },
    })
    return data.items ?? []
  },
  /** 批量确认（单次最多 100 个；可选联动自动启动模型学习） */
  confirm: (
    ids: string[],
    options?: { auto_start_learning?: boolean; sample_target?: number },
  ) =>
    request<{
      confirmed: number
      confirmed_ids: string[]
      failed: { id: string; reason: string }[]
      learning_started?: number
      learning_started_ids?: string[]
      learning_skipped?: number
      learning_skipped_ids?: string[]
      learning_failed?: { id: string; reason: string }[]
    }>('/api-security/endpoints/confirm', {
      method: 'POST',
      body: {
        ids,
        ...(options?.auto_start_learning !== undefined
          ? { auto_start_learning: options.auto_start_learning }
          : {}),
        ...(options?.sample_target !== undefined
          ? { sample_target: options.sample_target }
          : {}),
      },
    }),
  /** 批量启动接口学习（单次最多 100 个；已在学习中的接口自动跳过） */
  learningStartBatch: (ids: string[], sampleTarget?: number) =>
    request<{
      started: number
      started_ids: string[]
      skipped: number
      skipped_ids: string[]
      failed: { id: string; reason: string }[]
      sample_target: number
      message: string
    }>('/api-security/endpoints/learning/start', {
      method: 'POST',
      body: {
        ids,
        ...(sampleTarget !== undefined ? { sample_target: sampleTarget } : {}),
      },
    }),
  /** 获取 API 学习默认选项（确认资产时默认自动启动学习开关及样本目标范围） */
  learningOptions: () =>
    request<{
      auto_start_on_confirm: boolean
      default_sample_target: number
      min_sample_target: number
      max_sample_target: number
    }>('/api-security/endpoints/learning/options'),
  /** 批量忽略（单次最多 100 个） */
  ignoreBatch: (ids: string[]) =>
    request<{
      ignored: number
      ignored_ids: string[]
      failed: { id: string; reason: string }[]
    }>('/api-security/endpoints/ignore', { method: 'POST', body: { ids } }),
  /** 获取 API 发现静态资源与非 API 过滤配置 */
  getDiscoveryFilter: () =>
    request<{
      config: ApiDiscoveryFilterConfig
      default_extensions: string[]
    }>('/api-security/discovery-filter'),
  /** 更新 API 发现静态资源与非 API 过滤配置（立即生效） */
  updateDiscoveryFilter: (body: ApiDiscoveryFilterConfig) =>
    request<{
      config: ApiDiscoveryFilterConfig
      message: string
    }>('/api-security/discovery-filter', { method: 'PUT', body }),
  /** 预览存量可安全清理的非 API 与静态资源噪声 */
  previewNoiseCleanup: (body: {
    application_id?: string
    include_ignored?: boolean
    limit?: number
  } = {}) =>
    request<NoiseCleanupPreview>('/api-security/endpoints/cleanup-noise/preview', {
      method: 'POST',
      body,
    }),
  /** 执行存量静态/非 API 噪声清理（DELETE 删除释放配额 或 IGNORE 批量忽略） */
  executeNoiseCleanup: (body: {
    action: 'DELETE' | 'IGNORE'
    application_id?: string
    include_ignored?: boolean
    ids?: string[]
  }) =>
    request<{ result: NoiseCleanupResult; message: string }>(
      '/api-security/endpoints/cleanup-noise',
      { method: 'POST', body },
    ),
  ignore: (id: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(
      `/api-security/endpoints/${id}/ignore`,
      {
        method: 'POST',
        body: {},
      },
    ),
  /** 人工标记下线（仅 DISCOVERED/CONFIRMED → DEPRECATED；状态不允许时 409） */
  deprecate: (id: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(
      `/api-security/endpoints/${id}/deprecate`,
      {
        method: 'POST',
      },
    ),
  /** 人工恢复（仅 DEPRECATED/ZOMBIE → CONFIRMED，confirmed_at 刷新；状态不允许时 409） */
  restore: (id: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(
      `/api-security/endpoints/${id}/restore`,
      {
        method: 'POST',
      },
    ),
  /** 访问趋势波形：range 1h|24h|7d，points 为服务端补零后的连续时间桶 */
  trafficTrend: async (id: string, range: ApiTrafficTrendRange) => {
    const data = await request<ApiTrafficTrend>(
      `/api-security/endpoints/${id}/traffic-trend`,
      {
        query: { range },
      },
    )
    return { ...data, points: data.points ?? [] }
  },
  /** 合并：将 other_id 接口并入 id（命中数累加，源接口退役；高风险操作服务端记审计） */
  merge: (id: string, otherId: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(
      `/api-security/endpoints/${id}/merge`,
      {
        method: 'POST',
        body: { other_id: otherId },
      },
    ),
  /** 拆分：按路径段从 id 拆出新接口（服务端归一化；单次最多 50 个路径） */
  split: (id: string, paths: string[]) =>
    request<{ endpoints: ApiEndpointItem[]; message: string }>(
      `/api-security/endpoints/${id}/split`,
      {
        method: 'POST',
        body: { paths },
      },
    ),
  /** 启动/重新触发学习（缺省样本目标由服务端归一；已有运行中任务时 409） */
  learningStart: (id: string) =>
    request<{ job: { id: string; status: string }; message: string }>(
      `/api-security/endpoints/${id}/learning/start`,
      { method: 'POST' },
    ),
  /** 接口详情（含资产档案 asset 与近 7 天日均调用量 daily_requests） */
  get: (id: string) =>
    request<{ endpoint: ApiEndpointItem; daily_requests: number }>(
      `/api-security/endpoints/${id}`,
    ),
  /** 更新接口资产档案（全量替换；业务标签单存时仅传 business_type，其余字段服务端按零值覆盖，档案编辑须提交完整表单） */
  update: (
    id: string,
    body: { business_type: string } | ApiAssetProfileInput,
  ) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(
      `/api-security/endpoints/${id}`,
      {
        method: 'PATCH',
        body,
      },
    ),
}

/** API 模型版本（字段与 server/internal/apimodels.Version 一致） */
export interface ApiModelVersion {
  id: string
  api_endpoint_id: string
  endpoint_key: string
  status: string
  schema: Record<string, string>
  content_hash: string
  version_number: number
  change_summary: string
  created_reason: string
  created_at: string
  confirmed_at?: string | null
  activated_at?: string | null
}

/** 模型版本字段级差异（/api-security/models/{id}/diff/{other_id}，与 apimodels.ModelDiff 一致） */
export interface ApiModelDiff {
  id: string
  model_version_id: string
  other_version_id: string
  diff: {
    added: string[]
    removed: string[]
    type_changed: { field: string; from: string; to: string }[]
  }
  created_at: string
}

export interface ApiResponseSchemaItem {
  id: string
  endpoint_key: string
  status_code: number
  fields: Record<string, string>
  content_type?: string
  truncated: boolean
  content_hash: string
  sample_count: number
  first_seen: string
  last_seen: string
  updated_at: string
}

export interface ApiApplicationValueDimension {
  name: string
  average_score: number
  max: number
}

export interface ApiApplicationAssetValue {
  application_id: string
  level: string
  average_score: number
  max_score: number
  max_total: number
  endpoint_count: number
  scored_count: number
  unscored_count: number
  level_distribution: Record<string, number>
  dimensions: ApiApplicationValueDimension[]
  generated_at: string
}

export const apiApplicationAssetsApi = {
  value: (applicationId: string) =>
    request<ApiApplicationAssetValue>(
      `/api-security/applications/${applicationId}/asset-value`,
    ),
}

export const apiModelsApi = {
  /** 模型版本按接口查询 */
  list: async (
    endpointId: string,
    params: { page: number; page_size: number },
  ) => {
    const data = await request<PageResult<ApiModelVersion>>(
      `/api-security/endpoints/${endpointId}/models`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  listResponseSchemas: async (endpointId: string) => {
    const data = await request<{ items: ApiResponseSchemaItem[] }>(
      `/api-security/endpoints/${endpointId}/response-schemas`,
    )
    return data.items ?? []
  },
  createCandidate: (
    endpointId: string,
    body: { schema: Record<string, string>; change_summary?: string },
  ) =>
    request<{ version: ApiModelVersion; message: string }>(
      `/api-security/endpoints/${endpointId}/models`,
      { method: 'POST', body },
    ),
  /** 确认冻结为正式模型 */
  confirm: (id: string) =>
    request<{ version: ApiModelVersion; message: string }>(
      `/api-security/models/${id}/confirm`,
      {
        method: 'POST',
        body: {},
      },
    ),
  /** 提交评审：CANDIDATE → IN_REVIEW（comment 可选） */
  submitReview: (id: string, comment?: string) =>
    request<{ version: ApiModelVersion; message: string }>(
      `/api-security/models/${id}/submit-review`,
      {
        method: 'POST',
        body: { comment: comment ?? '' },
      },
    ),
  /** 评审拒绝：CANDIDATE / IN_REVIEW → REJECTED（comment 可选） */
  reject: (id: string, comment?: string) =>
    request<{ version: ApiModelVersion; message: string }>(
      `/api-security/models/${id}/reject`,
      {
        method: 'POST',
        body: { comment: comment ?? '' },
      },
    ),
  /** 激活正式模型为接口当前模型（仅 FORMAL） */
  activate: (id: string) =>
    request<{ version: ApiModelVersion; message: string }>(
      `/api-security/models/${id}/activate`,
      {
        method: 'POST',
        body: {},
      },
    ),
  /** 归档历史版本（FORMAL / SUPERSEDED / REJECTED → ARCHIVED） */
  archive: (id: string) =>
    request<{ version: ApiModelVersion; message: string }>(
      `/api-security/models/${id}/archive`,
      {
        method: 'POST',
        body: {},
      },
    ),
  /** 版本对比：otherId → id 的字段级差异 */
  diff: (id: string, otherId: string) =>
    request<ApiModelDiff>(`/api-security/models/${id}/diff/${otherId}`),
}

export const apiRuntimeEventsApi = {
  list: async (params: {
    endpoint_key?: string
    final_action?: string
    identity_fingerprint?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<Record<string, unknown>>>(
      '/api-security/runtime/events',
      {
        query: { ...params },
      },
    )
    return { ...data, items: data.items ?? [] }
  },
}

export const productApi = {
  edition: () =>
    request<{
      edition: string
      api_dynamic_protection: boolean
      web_waf_enabled?: boolean
      /** APM 业务性能开关（共享底座能力，所有产品形态可开启；缺省按关闭处理） */
      apm_enabled?: boolean
      product_name?: string
      max_body_parse_bytes?: number
      max_body_sample_bytes?: number
    }>('/product/edition'),
}
