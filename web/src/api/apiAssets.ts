import { request } from './client'
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
  created_at: string
  updated_at: string
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
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiEndpointItem>>('/api-security/endpoints', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
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
  directoryTree: async (params: { application_id?: string; unassigned?: boolean }) => {
    const data = await request<{
      items: { directory_path: string; endpoint_count: number }[]
    }>('/api-security/endpoints/directory-tree', {
      query: { ...params },
    })
    return data.items ?? []
  },
  /** 批量确认（页面行内操作传单个 id） */
  confirm: (ids: string[]) =>
    request<{ confirmed: number; confirmed_ids: string[]; failed: { id: string; reason: string }[] }>(
      '/api-security/endpoints/confirm',
      { method: 'POST', body: { ids } },
    ),
  ignore: (id: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(`/api-security/endpoints/${id}/ignore`, {
      method: 'POST',
      body: {},
    }),
  /** 人工标记下线（仅 DISCOVERED/CONFIRMED → DEPRECATED；状态不允许时 409） */
  deprecate: (id: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(`/api-security/endpoints/${id}/deprecate`, {
      method: 'POST',
    }),
  /** 人工恢复（仅 DEPRECATED/ZOMBIE → CONFIRMED，confirmed_at 刷新；状态不允许时 409） */
  restore: (id: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(`/api-security/endpoints/${id}/restore`, {
      method: 'POST',
    }),
  /** 访问趋势波形：range 1h|24h|7d，points 为服务端补零后的连续时间桶 */
  trafficTrend: async (id: string, range: ApiTrafficTrendRange) => {
    const data = await request<ApiTrafficTrend>(`/api-security/endpoints/${id}/traffic-trend`, {
      query: { range },
    })
    return { ...data, points: data.points ?? [] }
  },
  /** 合并：将 other_id 接口并入 id（命中数累加，源接口退役；高风险操作服务端记审计） */
  merge: (id: string, otherId: string) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(`/api-security/endpoints/${id}/merge`, {
      method: 'POST',
      body: { other_id: otherId },
    }),
  /** 拆分：按路径段从 id 拆出新接口（服务端归一化；单次最多 50 个路径） */
  split: (id: string, paths: string[]) =>
    request<{ endpoints: ApiEndpointItem[]; message: string }>(`/api-security/endpoints/${id}/split`, {
      method: 'POST',
      body: { paths },
    }),
  /** 启动/重新触发学习（缺省样本目标由服务端归一；已有运行中任务时 409） */
  learningStart: (id: string) =>
    request<{ job: { id: string; status: string }; message: string }>(
      `/api-security/endpoints/${id}/learning/start`,
      { method: 'POST' },
    ),
  /** 更新接口可编辑字段（当前仅 business_type；非法枚举服务端 400 字段级报错） */
  update: (id: string, body: { business_type: string }) =>
    request<{ endpoint: ApiEndpointItem; message: string }>(`/api-security/endpoints/${id}`, {
      method: 'PATCH',
      body,
    }),
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

export const apiModelsApi = {
  /** 模型版本按接口查询 */
  list: async (endpointId: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiModelVersion>>(
      `/api-security/endpoints/${endpointId}/models`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  createCandidate: (endpointId: string, body: { schema: Record<string, string>; change_summary?: string }) =>
    request<{ version: ApiModelVersion; message: string }>(
      `/api-security/endpoints/${endpointId}/models`,
      { method: 'POST', body },
    ),
  /** 确认冻结为正式模型 */
  confirm: (id: string) =>
    request<{ version: ApiModelVersion; message: string }>(`/api-security/models/${id}/confirm`, {
      method: 'POST',
      body: {},
    }),
  /** 提交评审：CANDIDATE → IN_REVIEW（comment 可选） */
  submitReview: (id: string, comment?: string) =>
    request<{ version: ApiModelVersion; message: string }>(`/api-security/models/${id}/submit-review`, {
      method: 'POST',
      body: { comment: comment ?? '' },
    }),
  /** 评审拒绝：CANDIDATE / IN_REVIEW → REJECTED（comment 可选） */
  reject: (id: string, comment?: string) =>
    request<{ version: ApiModelVersion; message: string }>(`/api-security/models/${id}/reject`, {
      method: 'POST',
      body: { comment: comment ?? '' },
    }),
  /** 激活正式模型为接口当前模型（仅 FORMAL） */
  activate: (id: string) =>
    request<{ version: ApiModelVersion; message: string }>(`/api-security/models/${id}/activate`, {
      method: 'POST',
      body: {},
    }),
  /** 归档历史版本（FORMAL / SUPERSEDED / REJECTED → ARCHIVED） */
  archive: (id: string) =>
    request<{ version: ApiModelVersion; message: string }>(`/api-security/models/${id}/archive`, {
      method: 'POST',
      body: {},
    }),
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
    const data = await request<PageResult<Record<string, unknown>>>('/api-security/runtime/events', {
      query: { ...params },
    })
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
