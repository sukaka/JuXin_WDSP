import { request } from './client'
import type { PageResult } from '../types'

/** 漏洞情报条目（Advisory） */
export interface VulnAdvisory {
  cve_id: string
  title: string
  summary: string
  severity: string
  cvss_score: number | null
  published_at: string
  last_modified_at?: string | null
  tech_tags: string[]
  references: string[]
  source: string
}

/** 受影响应用 */
export interface VulnAffectedApp {
  application_id: string
  code: string
  name: string
}

/** 情报源同步状态 */
export interface VulnSyncSourceStatus {
  source: string
  status: string
  last_sync_at?: string | null
  records_upserted: number
  failure_message?: string | null
}

/** 漏洞情报概览 */
export interface VulnIntelOverview {
  total: number
  recent_7d: number
  critical: number
  high: number
  sources: VulnSyncSourceStatus[]
}

/** 漏洞详情：条目 + 受影响应用 */
export interface VulnAdvisoryDetail {
  advisory: VulnAdvisory
  applications: VulnAffectedApp[]
}

/** 手动同步结果 */
export interface VulnSyncResult {
  status: string
  records_upserted: number
  message?: string
}

/** 手工/离线导入的条目输入 */
export interface VulnImportAdvisoryInput {
  cve_id: string
  title: string
  summary?: string
  severity: string
  cvss_score?: number
  published_at: string
  tech_tags?: string[]
  references?: string[]
}

/** 导入结果 */
export interface VulnImportResult {
  imported: number
  added: number
  updated: number
  alerts: number
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
  return raw.map((item, index) => {
    const it = item as Partial<VulnImportAdvisoryInput>
    if (!it || typeof it.cve_id !== 'string' || !it.cve_id.trim()) {
      throw new Error(`第 ${index + 1} 条缺少 cve_id`)
    }
    if (!it.title || typeof it.title !== 'string') {
      throw new Error(`第 ${index + 1} 条缺少 title`)
    }
    if (!it.severity || typeof it.severity !== 'string') {
      throw new Error(`第 ${index + 1} 条缺少 severity`)
    }
    if (!it.published_at || typeof it.published_at !== 'string') {
      throw new Error(`第 ${index + 1} 条缺少 published_at`)
    }
    return {
      cve_id: it.cve_id.trim().toUpperCase(),
      title: it.title,
      summary: typeof it.summary === 'string' ? it.summary : undefined,
      severity: it.severity.toUpperCase(),
      cvss_score: typeof it.cvss_score === 'number' ? it.cvss_score : undefined,
      published_at: it.published_at,
      tech_tags: Array.isArray(it.tech_tags) ? it.tech_tags : undefined,
      references: Array.isArray(it.references) ? it.references : undefined,
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
 * 权限：vuln_intel.read（查询）/ vuln_intel.manage（同步、导入、设置与技术资产维护，仅 SYSTEM_ADMIN）。
 */
export const vulnIntelApi = {
  overview: async () => {
    const data = await request<VulnIntelOverview>('/vuln-intel/overview')
    return { ...data, sources: data.sources ?? [] }
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
      applications: data.applications ?? [],
    }
  },
  sync: () => request<VulnSyncResult>('/vuln-intel/sync', { method: 'POST' }),
  importAdvisories: (advisories: VulnImportAdvisoryInput[]) =>
    request<VulnImportResult>('/vuln-intel/import', {
      method: 'POST',
      body: { advisories },
    }),
  techAssets: async () => {
    const data = await request<{ items: VulnTechAssetItem[] | null }>('/vuln-intel/tech-assets')
    return (data.items ?? []).map((item) => ({ ...item, tech_tags: item.tech_tags ?? [] }))
  },
  updateTechAssets: (items: { application_id: string; tech_tags: string[] }[]) =>
    request<{ message?: string }>('/vuln-intel/tech-assets', {
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
