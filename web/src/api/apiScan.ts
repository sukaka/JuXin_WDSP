import { request } from './client'
import type { PageResult } from '../types'

/* ==================== API 主动扫描（server/internal/apiscan）：目标/授权/任务/发现/复测 ==================== */

/** 目标状态（与 server/internal/apiscan 目标状态枚举一致） */
export type ApiScanTargetStatus = 'ENABLED' | 'DISABLED'

/** 任务状态（PENDING/RUNNING/PAUSED 非终态，STOPPED/COMPLETED/FAILED 终态） */
export type ApiScanJobStatus =
  | 'PENDING'
  | 'RUNNING'
  | 'PAUSED'
  | 'STOPPED'
  | 'COMPLETED'
  | 'FAILED'

/** 发现状态（与 api_scan_findings status 词表一致） */
export type ApiScanFindingStatus = 'NEW' | 'CONFIRMED' | 'FALSE_POSITIVE' | 'RETIRED'

/** 内置探针集词表（引擎只执行词表内探针，白名单外一律拒绝） */
export type ApiScanProbeSet =
  | 'AUTH_REQUIRED'
  | 'DEPRECATED_ALIVE'
  | 'SENSITIVE_EXPOSURE'
  | 'SCHEMA_CONFORM'
  | 'BOLA_COMPARE'
  | 'METHOD_ENUM'

/** 内置探针集全量（授权画像为空时的默认全集；顺序与 server AllProbeSets 一致） */
export const API_SCAN_PROBE_SETS: ApiScanProbeSet[] = [
  'AUTH_REQUIRED',
  'DEPRECATED_ALIVE',
  'SENSITIVE_EXPOSURE',
  'SCHEMA_CONFORM',
  'BOLA_COMPARE',
  'METHOD_ENUM',
]

/** 严重度（与 api_runtime_findings / api_weaknesses 口径一致） */
export type ApiScanSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

/** 扫描目标（api_scan_targets） */
export interface ApiScanTarget {
  id: string
  application_id: string
  name: string
  base_url: string
  allowed_paths: string[]
  status: ApiScanTargetStatus
  created_by?: string | null
  created_at: string
  updated_at: string
}

/** 授权时间窗（nil 端不限制） */
export interface ApiScanTimeWindow {
  start?: string | null
  end?: string | null
}

/** 扫描授权单（api_scan_authorizations；生效状态由 expires_at/revoked_at/time_window 派生） */
export interface ApiScanAuthorization {
  id: string
  target_id: string
  authorized_by: string
  allowlist: string[]
  time_window: ApiScanTimeWindow
  max_qps: number
  max_concurrency: number
  /** 逗号分隔探针集画像（空 = 默认全集） */
  test_profile: string
  expires_at: string
  revoked_at?: string | null
  created_at: string
}

/** 任务执行进度（progress JSONB） */
export interface ApiScanJobProgress {
  total: number
  done: number
  requests: number
  findings: number
  errors: number
  last_error?: string
}

/** 扫描任务（api_scan_jobs） */
export interface ApiScanJob {
  id: string
  target_id: string
  authorization_id: string
  /** 逗号分隔探针集（创建时可空 = 授权画像默认） */
  probe_set: string
  status: ApiScanJobStatus
  progress: ApiScanJobProgress
  started_at?: string | null
  finished_at?: string | null
  created_by?: string | null
  created_at: string
}

/** 扫描发现（api_scan_findings；样本均已脱敏截断） */
export interface ApiScanFinding {
  id: string
  job_id: string
  engine: string
  /** 来源探针集（词表内取值） */
  template: string
  /** 「METHOD /path」端点键 */
  endpoint_key: string
  category: string
  severity: ApiScanSeverity
  confidence: number
  evidence: unknown
  request_sample: string
  response_sample: string
  status: ApiScanFindingStatus
  weakness_id?: string | null
  created_at: string
}

/** 新建目标请求体 */
export interface ApiScanTargetCreateBody {
  application_id: string
  name: string
  base_url: string
  allowed_paths: string[]
}

/** 更新目标请求体（application_id 不可改；PUT 全量替换） */
export interface ApiScanTargetUpdateBody {
  name: string
  base_url: string
  allowed_paths: string[]
  status: ApiScanTargetStatus
}

/** 签发授权请求体（window_start/window_end 可空；RFC3339 时间串） */
export interface ApiScanAuthorizeBody {
  allowlist: string[]
  window_start?: string
  window_end?: string
  max_qps: number
  max_concurrency: number
  /** 逗号分隔探针集，空 = 默认全集 */
  test_profile: string
  expires_at: string
}

/** 发起任务请求体 */
export interface ApiScanJobCreateBody {
  target_id: string
  authorization_id: string
  /** 逗号分隔探针集；可空 = 授权画像默认 */
  probe_set?: string
}

/** 复测结果（POST /findings/{id}/retest 响应 result 字段） */
export type ApiScanRetestResult = 'PASS' | 'FAIL'

export const apiScanApi = {
  /* ---------- 目标 ---------- */
  listTargets: async (params: {
    application_id?: string
    status?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiScanTarget>>('/api-security/scans/targets', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  createTarget: (body: ApiScanTargetCreateBody) =>
    request<{ target: ApiScanTarget }>('/api-security/scans/targets', { method: 'POST', body }),
  updateTarget: (id: string, body: ApiScanTargetUpdateBody) =>
    request<{ target: ApiScanTarget }>(`/api-security/scans/targets/${id}`, {
      method: 'PUT',
      body,
    }),

  /* ---------- 授权 ---------- */
  /** 签发授权（双人分离：建标人不得自签，后端强制 403） */
  authorize: (targetId: string, body: ApiScanAuthorizeBody) =>
    request<{ authorization: ApiScanAuthorization }>(
      `/api-security/scans/targets/${targetId}/authorize`,
      { method: 'POST', body },
    ),
  listAuthorizations: async (targetId: string, params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ApiScanAuthorization>>(
      `/api-security/scans/targets/${targetId}/authorizations`,
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  /** 吊销授权（吊销即停：联动停止该授权下全部在跑任务） */
  revokeAuthorization: (id: string) =>
    request<{ authorization: ApiScanAuthorization; stopped_jobs: number }>(
      `/api-security/scans/authorizations/${id}/revoke`,
      { method: 'POST' },
    ),

  /* ---------- 任务 ---------- */
  listJobs: async (params: { target_id?: string; status?: string; page: number; page_size: number }) => {
    const data = await request<PageResult<ApiScanJob>>('/api-security/scans/jobs', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  createJob: (body: ApiScanJobCreateBody) =>
    request<{ job: ApiScanJob }>('/api-security/scans/jobs', { method: 'POST', body }),
  startJob: (id: string) =>
    request<{ job: ApiScanJob }>(`/api-security/scans/jobs/${id}/start`, { method: 'POST' }),
  stopJob: (id: string) =>
    request<{ job: ApiScanJob }>(`/api-security/scans/jobs/${id}/stop`, { method: 'POST' }),
  /** 紧急停止（STOP + 撤销授权 + 停止该授权下全部任务） */
  emergencyStopJob: (id: string) =>
    request<{ authorization: ApiScanAuthorization; stopped_jobs: number }>(
      `/api-security/scans/jobs/${id}/emergency-stop`,
      { method: 'POST' },
    ),

  /* ---------- 发现 ---------- */
  listFindings: async (params: {
    job_id?: string
    status?: string
    severity?: string
    template?: string
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiScanFinding>>('/api-security/scans/findings', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 确认发现（NEW → CONFIRMED，可携带 weakness_id 关联弱点） */
  confirmFinding: (id: string, body?: { weakness_id?: string }) =>
    request<{ finding: ApiScanFinding }>(`/api-security/scans/findings/${id}/confirm`, {
      method: 'POST',
      body,
    }),
  /** 判定误报（NEW → FALSE_POSITIVE） */
  falsePositiveFinding: (id: string) =>
    request<{ finding: ApiScanFinding }>(`/api-security/scans/findings/${id}/false-positive`, {
      method: 'POST',
    }),
  /** 定向复测（须已关联弱点；对关联弱点真实重探并回写弱点状态机） */
  retestFinding: (id: string, body?: { note?: string }) =>
    request<{ result: ApiScanRetestResult; reproduced: boolean; weakness_id: string }>(
      `/api-security/scans/findings/${id}/retest`,
      { method: 'POST',
        body },
    ),
}
