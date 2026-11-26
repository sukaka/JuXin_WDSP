import {
  ApiError,
  buildUrl,
  notifyLicenseInvalid,
  notifySessionExpired,
  request,
} from './client'
import type { ApiEnvelope } from '../types'

/**
 * 客户端供应链安全（Magecart 防护 / PCI DSS 4.0 6.4.3 & 11.6.1）管理面客户端（WDSP Phase 9B）。
 * 应用策略路由：GET/PUT /applications/{id}/client-side-policy。
 * 脚本资产台账：GET/POST /client-side/scripts、PUT/DELETE /client-side/scripts/{id}。
 * 违规告警处置：GET /client-side/violations、PUT /client-side/violations/{id}/status。
 * 合规证据导出：GET /client-side/compliance-export（UTF-8 BOM CSV）。
 * 权限：client_side.read / client_side.manage。草稿保存不等于线上生效，发布走既有发布通道。
 */

export type ClientSideMode = 'OFF' | 'OBSERVE' | 'PROTECT'
export type ClientSideCspMode = 'OFF' | 'REPORT_ONLY' | 'ENFORCE'
export type ClientSideState = 'NOT_CONFIGURED' | 'DRAFT_PENDING' | 'PUBLISHED'
export type ClientScriptType = 'EXTERNAL' | 'INLINE_HASH'
export type ClientScriptStatus = 'DISCOVERED' | 'AUTHORIZED' | 'BLOCKED'
export type ClientSideViolationType =
  | 'UNAUTHORIZED_SCRIPT'
  | 'SCRIPT_TAMPERED'
  | 'CSP_VIOLATION'
  | 'PROBE_ALERT'
export type ClientSideViolationStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE'
export type ClientSideActionTaken =
  | 'OBSERVED'
  | 'REPORTED'
  | 'STRIPPED'
  | 'CSP_ENFORCED'

/** 前后端共享校验上限常量（与 server/internal/clientside/validate.go 严格对齐） */
export const CLIENT_SIDE_LIMITS = {
  maxSensitivePaths: 64,
  maxPathLen: 512,
  maxOrigins: 64,
  maxOriginLen: 512,
  maxCustomDirectivesLen: 2048,
  maxJustificationLen: 1000,
  maxReasonLen: 500,
  maxNoteLen: 1000,
  maxScriptUrlLen: 2048,
  maxSriLen: 256,
  cspReportEndpoint: '/_wdsp/csp/v1/report',
  probeEndpoint: '/_wdsp/cs/v1/probe.js',
} as const

/** 应用级客户端供应链安全策略 */
export interface ClientSidePolicy {
  id: string
  schema_version?: number
  application_id: string
  mode: ClientSideMode
  version: number
  csp_mode: ClientSideCspMode
  sensitive_paths: string[]
  probe_enabled: boolean
  strip_unauthorized_scripts: boolean
  allowed_script_origins: string[]
  allowed_connect_origins: string[]
  allowed_form_origins: string[]
  custom_csp_directives: string
  updated_by: string
  created_at: string
  updated_at: string
}

/** 状态摘要：草稿版本 vs 已发布生效版本 */
export interface ClientSideStatusSummary {
  state: ClientSideState
  draft_version: number
  published_version: number
}

export interface ClientSidePolicyGetResult {
  policy: ClientSidePolicy
  summary: ClientSideStatusSummary
}

/** PUT 应用级客户端供应链安全策略载荷（expected_version 乐观锁 + reason 审计） */
export interface ClientSidePolicyUpdateBody {
  mode: ClientSideMode
  expected_version: number
  csp_mode: ClientSideCspMode
  sensitive_paths: string[]
  probe_enabled: boolean
  strip_unauthorized_scripts: boolean
  allowed_script_origins: string[]
  allowed_connect_origins: string[]
  allowed_form_origins: string[]
  custom_csp_directives: string
  reason: string
}

/** 脚本资产清单记录（PCI DSS 4.0 6.4.3） */
export interface ClientScriptItem {
  id: string
  application_id: string
  application_code?: string
  application_name?: string
  script_url: string
  script_origin: string
  script_type: ClientScriptType | string
  sri_hash: string
  observed_sri: string
  status: ClientScriptStatus | string
  justification: string
  approved_by: string
  approved_at?: string | null
  sample_page_path: string
  first_seen_at?: string | null
  last_seen_at?: string | null
  observed_count: number
  created_at: string
  updated_at: string
}

export interface ClientScriptListParams {
  application_id?: string
  status?: string
  keyword?: string
  page?: number
  page_size?: number
}

export interface ClientScriptListResult {
  items: ClientScriptItem[]
  total: number
  page: number
  page_size: number
}

export interface ClientScriptCreateBody {
  application_id: string
  script_url: string
  script_type: ClientScriptType
  sri_hash: string
  status: ClientScriptStatus
  justification: string
}

export interface ClientScriptUpdateBody {
  sri_hash: string
  status: ClientScriptStatus
  justification: string
}

export interface ClientScriptDeleteResult {
  deleted: boolean
  id: string
}

/** 篡改与 CSP 违规告警记录（PCI DSS 4.0 11.6.1） */
export interface ClientSideViolationItem {
  id: string
  application_id: string
  application_code?: string
  application_name?: string
  request_id: string
  occurred_at: string
  violation_type: ClientSideViolationType | string
  script_url: string
  script_origin: string
  expected_sri: string
  observed_sri: string
  page_path: string
  violated_directive: string
  blocked_uri: string
  action_taken: ClientSideActionTaken | string
  reason: string
  client_ip: string
  status: ClientSideViolationStatus | string
  note: string
  handled_by: string
  handled_at?: string | null
  created_at: string
}

export interface ClientSideViolationListParams {
  application_id?: string
  violation_type?: string
  status?: string
  page?: number
  page_size?: number
}

export interface ClientSideViolationListResult {
  items: ClientSideViolationItem[]
  total: number
  page: number
  page_size: number
}

export interface ClientSideViolationStatusBody {
  status: ClientSideViolationStatus
  note: string
}

function normalizePolicy(p: ClientSidePolicy): ClientSidePolicy {
  return {
    ...p,
    mode: p.mode ?? 'OFF',
    version: p.version ?? 0,
    csp_mode: p.csp_mode ?? 'OFF',
    sensitive_paths: p.sensitive_paths ?? [],
    probe_enabled: Boolean(p.probe_enabled),
    strip_unauthorized_scripts: Boolean(p.strip_unauthorized_scripts),
    allowed_script_origins: p.allowed_script_origins ?? [],
    allowed_connect_origins: p.allowed_connect_origins ?? [],
    allowed_form_origins: p.allowed_form_origins ?? [],
    custom_csp_directives: p.custom_csp_directives ?? '',
    updated_by: p.updated_by ?? '',
    created_at: p.created_at ?? '',
    updated_at: p.updated_at ?? '',
  }
}

function normalizeScript(s: ClientScriptItem): ClientScriptItem {
  return {
    ...s,
    script_url: s.script_url ?? '',
    script_origin: s.script_origin ?? '',
    script_type: s.script_type ?? 'EXTERNAL',
    sri_hash: s.sri_hash ?? '',
    observed_sri: s.observed_sri ?? '',
    status: s.status ?? 'DISCOVERED',
    justification: s.justification ?? '',
    approved_by: s.approved_by ?? '',
    sample_page_path: s.sample_page_path ?? '',
    observed_count: s.observed_count ?? 0,
  }
}

function normalizeViolation(v: ClientSideViolationItem): ClientSideViolationItem {
  return {
    ...v,
    request_id: v.request_id ?? '',
    script_url: v.script_url ?? '',
    script_origin: v.script_origin ?? '',
    expected_sri: v.expected_sri ?? '',
    observed_sri: v.observed_sri ?? '',
    page_path: v.page_path ?? '',
    violated_directive: v.violated_directive ?? '',
    blocked_uri: v.blocked_uri ?? '',
    action_taken: v.action_taken ?? 'OBSERVED',
    reason: v.reason ?? '',
    client_ip: v.client_ip ?? '',
    status: v.status ?? 'OPEN',
    note: v.note ?? '',
    handled_by: v.handled_by ?? '',
  }
}

function parseFilenameFromDisposition(disposition: string | null): string | null {
  if (!disposition) return null
  const utf8Match = /filename\*=UTF-8''([^;\s]+)/i.exec(disposition)
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1])
    } catch {
      return utf8Match[1]
    }
  }
  const plainMatch = /filename="?([^";]+)"?/i.exec(disposition)
  return plainMatch?.[1]?.trim() || null
}

/** 构造 PCI DSS 4.0 合规证据 CSV 导出地址 */
export function complianceExportUrl(applicationId?: string): string {
  return buildUrl(
    '/client-side/compliance-export',
    applicationId ? { application_id: applicationId } : undefined,
  )
}

export const clientSideApi = {
  getPolicy: async (appId: string): Promise<ClientSidePolicyGetResult> => {
    const data = await request<ClientSidePolicyGetResult>(
      `/applications/${appId}/client-side-policy`,
    )
    return {
      ...data,
      policy: normalizePolicy(data.policy),
    }
  },

  updatePolicy: async (
    appId: string,
    body: ClientSidePolicyUpdateBody,
  ): Promise<ClientSidePolicy> => {
    const data = await request<{ policy: ClientSidePolicy }>(
      `/applications/${appId}/client-side-policy`,
      { method: 'PUT', body },
    )
    return normalizePolicy(data.policy)
  },

  listScripts: async (
    params: ClientScriptListParams = {},
  ): Promise<ClientScriptListResult> => {
    const data = await request<ClientScriptListResult>('/client-side/scripts', {
      query: { ...params },
    })
    return {
      items: (data?.items ?? []).map(normalizeScript),
      total: data?.total ?? 0,
      page: data?.page ?? params.page ?? 1,
      page_size: data?.page_size ?? params.page_size ?? 20,
    }
  },

  createScript: async (
    body: ClientScriptCreateBody,
  ): Promise<ClientScriptItem> => {
    const data = await request<{ script: ClientScriptItem }>(
      '/client-side/scripts',
      { method: 'POST', body },
    )
    return normalizeScript(data.script)
  },

  updateScript: async (
    id: string,
    body: ClientScriptUpdateBody,
  ): Promise<ClientScriptItem> => {
    const data = await request<{ script: ClientScriptItem }>(
      `/client-side/scripts/${id}`,
      { method: 'PUT', body },
    )
    return normalizeScript(data.script)
  },

  deleteScript: async (id: string): Promise<ClientScriptDeleteResult> => {
    return request<ClientScriptDeleteResult>(`/client-side/scripts/${id}`, {
      method: 'DELETE',
    })
  },

  listViolations: async (
    params: ClientSideViolationListParams = {},
  ): Promise<ClientSideViolationListResult> => {
    const data = await request<ClientSideViolationListResult>(
      '/client-side/violations',
      { query: { ...params } },
    )
    return {
      items: (data?.items ?? []).map(normalizeViolation),
      total: data?.total ?? 0,
      page: data?.page ?? params.page ?? 1,
      page_size: data?.page_size ?? params.page_size ?? 20,
    }
  },

  updateViolationStatus: async (
    id: string,
    body: ClientSideViolationStatusBody,
  ): Promise<ClientSideViolationItem> => {
    const data = await request<{ violation: ClientSideViolationItem }>(
      `/client-side/violations/${id}/status`,
      { method: 'PUT', body },
    )
    return normalizeViolation(data.violation)
  },

  complianceExportUrl,

  /** 拉取 PCI DSS 4.0 合规证据 CSV（Blob 下载，携带登录会话并遵循 401/423 全局处置） */
  downloadComplianceExport: async (
    applicationId?: string,
  ): Promise<{ blob: Blob; filename: string }> => {
    const url = complianceExportUrl(applicationId)
    let resp: Response
    try {
      resp = await fetch(url, {
        method: 'GET',
        credentials: 'include',
        signal: AbortSignal.timeout(60_000),
      })
    } catch (e) {
      if (e instanceof DOMException && e.name === 'TimeoutError') {
        throw new ApiError('请求超时，请稍后重试', 'TIMEOUT', 0)
      }
      throw new ApiError('网络异常，请检查网络连接后重试', 'NETWORK_ERROR', 0)
    }

    if (resp.status === 401) {
      notifySessionExpired()
    }
    if (resp.status === 423) {
      notifyLicenseInvalid()
    }

    if (!resp.ok) {
      let env: ApiEnvelope<null> | null = null
      try {
        env = (await resp.json()) as ApiEnvelope<null>
      } catch {
        env = null
      }
      const code =
        env && typeof env.code === 'string' ? env.code : 'HTTP_ERROR'
      const msg =
        env && typeof env.message === 'string'
          ? env.message
          : `导出失败（HTTP ${resp.status}）`
      throw new ApiError(msg, code, resp.status, env?.request_id, env?.details)
    }

    const blob = await resp.blob()
    const filename =
      parseFilenameFromDisposition(resp.headers.get('Content-Disposition')) ??
      `pci-dss-client-side-compliance-${new Date().toISOString().slice(0, 10)}.csv`
    return { blob, filename }
  },
}
