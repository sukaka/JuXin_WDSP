import { request } from './client'
import type { PageResult } from '../types'

/** 漏洞情报条目（Advisory） */
export interface VulnAdvisory {
  id?: string
  cve_id: string
  title: string
  summary: string
  severity: string
  cvss_score: number | null
  published_at: string | null
  last_modified_at?: string | null
  tech_tags: string[]
  references: string[]
  source: string
  created_at?: string
  updated_at?: string
}

/** 受影响应用（对应后端 VulnIntelAffectedApp） */
export interface VulnAffectedApp {
  application_id: string
  code: string
  name: string
  tech: string
}

/** 情报源同步状态（对应后端 VulnIntelSyncState） */
export interface VulnSyncState {
  source: string
  last_sync_at?: string | null
  last_window_start?: string | null
  last_window_end?: string | null
  records_upserted: number
  status: string
  failure_message: string
  updated_at?: string
}

/** 漏洞情报概览（对应后端 VulnIntelOverviewResponse） */
export interface VulnIntelOverview {
  total: number
  new_last_7d: number
  critical_count: number
  high_count: number
  watch_techs: string[]
  min_severity: string
  sync_enabled: boolean
  sync_state: VulnSyncState | null
}

/** 漏洞详情：条目 + 受影响应用（对应后端 VulnIntelAdvisoryDetailResponse） */
export interface VulnAdvisoryDetail {
  advisory: VulnAdvisory
  affected_apps: VulnAffectedApp[]
}

/** 手动同步结果（对应后端 VulnIntelSyncResponse） */
export interface VulnSyncResult {
  source: string
  window_start: string
  window_end: string
  fetched: number
  upserted: number
  new_advisories: number
  alerts_raised: number
  records_upserted: number
}

/** 手工/离线导入的条目输入（对应后端 VulnIntelImportAdvisory） */
export interface VulnImportAdvisoryInput {
  cve_id: string
  title?: string
  summary?: string
  severity?: string
  cvss_score?: number
  published_at?: string
  last_modified_at?: string
  tech_tags: string[]
  references?: string[]
}

/** 导入逐条校验失败明细（对应后端 VulnIntelImportRowError） */
export interface VulnImportRowError {
  index: number
  cve_id: string
  reason: string
}

/** 导入结果（对应后端 VulnIntelImportResponse） */
export interface VulnImportResult {
  received: number
  inserted: number
  updated: number
  invalid: number
  invalid_entries: VulnImportRowError[]
  alerts_raised: number
}

/** 应用技术栈资产项 */
export interface VulnTechAssetItem {
  application_id: string
  code: string
  name: string
  tech_tags: string[]
}

/** 订阅设置 */
export interface VulnIntelSettings {
  watch_techs: string[]
  min_severity: string
  sync_enabled: boolean
}

export interface VulnAdvisoryListParams {
  keyword?: string
  severity?: string
  tech?: string
  source?: string
  published_start?: string
  published_end?: string
  page: number
  page_size: number
}

const MAX_IMPORT_BATCH = 500
const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i

/** 将导入时间字段规范化为后端 Go time.Time 可解析的 RFC3339 字符串（纯日期 YYYY-MM-DD 自动补全为 T00:00:00Z） */
function normalizeImportTimestamp(value: unknown, field: string, index: number): string | undefined {
  if (value === undefined || value === null) return undefined
  if (typeof value !== 'string') {
    throw new Error(`第 ${index + 1} 条 ${field} 必须是字符串`)
  }
  const trimmed = value.trim()
  if (!trimmed) return undefined
  const isDateOnly = DATE_ONLY_RE.test(trimmed)
  const candidate = isDateOnly ? `${trimmed}T00:00:00Z` : trimmed
  if (!RFC3339_RE.test(candidate) || Number.isNaN(Date.parse(candidate))) {
    throw new Error(
      `第 ${index + 1} 条 ${field} 时间格式非法（支持 YYYY-MM-DD 或 RFC3339，如 2026-10-20T00:00:00Z）`,
    )
  }
  if (isDateOnly && new Date(candidate).toISOString().slice(0, 10) !== trimmed) {
    throw new Error(`第 ${index + 1} 条 ${field} 日期无效：${trimmed}`)
  }
  return candidate
}

/** 导入 JSON 解析：接受数组或 { advisories: [...] } 两种形态；非法输入抛出带中文消息的 Error */
export function parseImportJson(text: string): VulnImportAdvisoryInput[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new Error('JSON 格式不正确，请检查输入内容')
  }
  const raw = Array.isArray(parsed)
    ? parsed
    : (parsed as { advisories?: unknown })?.advisories
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error('请输入包含 advisories 的非空 JSON 数组')
  }
  if (raw.length > MAX_IMPORT_BATCH) {
    throw new Error(`单批导入不能超过 ${MAX_IMPORT_BATCH} 条`)
  }
  return raw.map((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new Error(`第 ${index + 1} 条必须是 JSON 对象`)
    }
    const it = item as Record<string, unknown>
    if (typeof it.cve_id !== 'string' || !it.cve_id.trim()) {
      throw new Error(`第 ${index + 1} 条缺少 cve_id`)
    }
    if (!Array.isArray(it.tech_tags)) {
      throw new Error(`第 ${index + 1} 条缺少 tech_tags（至少提供 1 个技术标签，如 ["php"]）`)
    }
    const techTags = it.tech_tags
      .map((t) => {
        if (typeof t !== 'string') {
          throw new Error(`第 ${index + 1} 条 tech_tags 仅支持字符串`)
        }
        return t.trim().toLowerCase()
      })
      .filter(Boolean)
    if (techTags.length === 0) {
      throw new Error(`第 ${index + 1} 条缺少 tech_tags（至少提供 1 个技术标签，如 ["php"]）`)
    }

    if (it.title !== undefined && it.title !== null && typeof it.title !== 'string') {
      throw new Error(`第 ${index + 1} 条 title 必须是字符串`)
    }
    if (it.summary !== undefined && it.summary !== null && typeof it.summary !== 'string') {
      throw new Error(`第 ${index + 1} 条 summary 必须是字符串`)
    }
    if (it.severity !== undefined && it.severity !== null && typeof it.severity !== 'string') {
      throw new Error(`第 ${index + 1} 条 severity 必须是字符串`)
    }
    if (
      it.cvss_score !== undefined &&
      it.cvss_score !== null &&
      (typeof it.cvss_score !== 'number' || !Number.isFinite(it.cvss_score))
    ) {
      throw new Error(`第 ${index + 1} 条 cvss_score 必须是数字`)
    }
    let references: string[] | undefined
    if (it.references !== undefined && it.references !== null) {
      if (!Array.isArray(it.references) || it.references.some((r) => typeof r !== 'string')) {
        throw new Error(`第 ${index + 1} 条 references 必须是字符串数组`)
      }
      references = it.references as string[]
    }

    const title = typeof it.title === 'string' && it.title.trim() ? it.title.trim() : undefined
    const severity =
      typeof it.severity === 'string' && it.severity.trim()
        ? it.severity.trim().toUpperCase()
        : undefined
    const publishedAt = normalizeImportTimestamp(it.published_at, 'published_at', index)
    const lastModifiedAt = normalizeImportTimestamp(it.last_modified_at, 'last_modified_at', index)

    return {
      cve_id: it.cve_id.trim().toUpperCase(),
      title,
      summary: typeof it.summary === 'string' ? it.summary : undefined,
      severity,
      cvss_score: typeof it.cvss_score === 'number' ? it.cvss_score : undefined,
      published_at: publishedAt,
      last_modified_at: lastModifiedAt,
      tech_tags: techTags,
      references,
    }
  })
}

const normalizeAdvisory = (a: VulnAdvisory): VulnAdvisory => ({
  ...a,
  tech_tags: a.tech_tags ?? [],
  references: a.references ?? [],
})

/**
 * 漏洞情报提醒（PHP 场景闭环）。
 * 权限：vuln_intel.read（查询）/ vuln_intel.manage（同步、导入、设置与技术资产维护，归属运维管理员）。
 */
export const vulnIntelApi = {
  overview: async () => {
    const data = await request<VulnIntelOverview>('/vuln-intel/overview')
    return {
      ...data,
      watch_techs: data.watch_techs ?? [],
      sync_state: data.sync_state ?? null,
    }
  },
  list: async (params: VulnAdvisoryListParams) => {
    const data = await request<PageResult<VulnAdvisory>>('/vuln-intel/advisories', {
      query: { ...params },
    })
    return { ...data, items: (data.items ?? []).map(normalizeAdvisory) }
  },
  get: async (cveId: string) => {
    const data = await request<VulnAdvisoryDetail>(
      `/vuln-intel/advisories/${encodeURIComponent(cveId)}`,
    )
    return {
      advisory: normalizeAdvisory(data.advisory),
      affected_apps: data.affected_apps ?? [],
    }
  },
  sync: () => request<VulnSyncResult>('/vuln-intel/sync', { method: 'POST' }),
  importAdvisories: async (advisories: VulnImportAdvisoryInput[]) => {
    const data = await request<VulnImportResult>('/vuln-intel/import', {
      method: 'POST',
      body: { advisories },
    })
    return {
      ...data,
      invalid_entries: data.invalid_entries ?? [],
    }
  },
  techAssets: async () => {
    const data = await request<{ items: VulnTechAssetItem[] | null }>('/vuln-intel/tech-assets')
    return (data.items ?? []).map((item) => ({ ...item, tech_tags: item.tech_tags ?? [] }))
  },
  updateTechAssets: (items: { application_id: string; tech_tags: string[] }[]) =>
    request<{ apps: number; tags: number }>('/vuln-intel/tech-assets', {
      method: 'PUT',
      body: { items },
    }),
  settings: async () => {
    const data = await request<VulnIntelSettings>('/vuln-intel/settings')
    return { ...data, watch_techs: data.watch_techs ?? [] }
  },
  updateSettings: (body: VulnIntelSettings) =>
    request<VulnIntelSettings>('/vuln-intel/settings', { method: 'PUT', body }),
}
