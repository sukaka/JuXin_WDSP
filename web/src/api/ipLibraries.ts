import { request, upload, type UploadProgress } from './client'
import type { PageResult } from '../types'

/* ==================== 出站代理与镜像白名单设置 ==================== */

export type IpLibrarySourceMode = 'OFFLINE_ONLY' | 'OFFICIAL' | 'CUSTOM_URL'

/** GET /api/v1/ip-libraries/outbound-settings 响应载荷（绝不回显代理密码明文） */
export interface OutboundSettings {
  outbound_allowlist: string
  allow_insecure_http_mirror: boolean
  proxy_url: string
  has_proxy_auth: boolean
  http_timeout_seconds: number
}

/** PUT /api/v1/ip-libraries/outbound-settings 请求载荷 */
export interface UpdateOutboundSettingsBody {
  outbound_allowlist: string
  allow_insecure_http_mirror: boolean
  proxy_url: string
  /** 仅写入（user:pass），留空表示不修改现有认证凭据 */
  proxy_auth?: string
  /** 为 true 时清除已保存的代理认证凭据 */
  clear_proxy_auth?: boolean
  http_timeout_seconds: number
}

/* ==================== GeoIP 归属地库 ==================== */

export type GeoIpSlotKey = 'ip2region_v4' | 'ip2region_v6' | 'dbip_city' | 'city_ipv6' | 'country'

export interface GeoIpBackupEntry {
  backup_id: string
  filename: string
  sha256: string
  size_bytes: number
  created_at: string
}

export interface GeoIpSlotStatus {
  slot: GeoIpSlotKey | string
  display_name: string
  canonical_file: string
  format: string
  max_bytes: number
  enabled: boolean
  source_mode: IpLibrarySourceMode | string
  official_preset: string
  custom_url: string
  active_origin: 'runtime' | 'builtin' | 'missing' | string
  active_filename: string
  active_source_type: string
  sha256: string
  size_bytes: number
  updated_at?: string | null
  last_status: string
  last_error: string
  backups: GeoIpBackupEntry[]
}

export interface GeoIpScheduleSummary {
  auto_update_enabled: boolean
  schedule_cron: string
  ha_sync_enabled: boolean
  maxmind_account_id: string
  has_maxmind_license_key: boolean
}

export interface GeoIpHANodeSyncResult {
  node_id?: string
  node_name: string
  status: string
  sha256?: string
  error?: string
}

export interface GeoIpHANodeSlotDigest {
  filename: string
  sha256: string
  size_bytes: number
}

export interface GeoIpHANodeStatus {
  node_id?: string
  node_name: string
  reachable: boolean
  geoip_ready: boolean
  consistent: boolean
  revision: string
  updated_at?: string | null
  slots?: Record<string, GeoIpHANodeSlotDigest>
  error?: string
}

export interface GeoIpPresetInfo {
  id: string
  slot: string
  name: string
  license?: string
  url_template?: string
  requires_maxmind_auth?: boolean
  monthly_fallback?: boolean
}

export interface GeoIpStatusResponse {
  geo_enabled: boolean
  sources: string[]
  loaded_at?: string | null
  revision: string
  schedule: GeoIpScheduleSummary
  slots: GeoIpSlotStatus[]
  ha_nodes: GeoIpHANodeStatus[]
  presets: GeoIpPresetInfo[]
}

export interface GeoIpSlotSettingInput {
  slot: string
  enabled: boolean
  source_mode: IpLibrarySourceMode | string
  official_preset: string
  custom_url: string
}

export interface UpdateGeoIpSettingsBody {
  auto_update_enabled?: boolean
  schedule_cron?: string
  ha_sync_enabled?: boolean
  maxmind_account_id?: string
  /** 仅写入，留空表示不修改已保存密钥 */
  maxmind_license_key?: string
  /** 为 true 时清除已保存的 MaxMind License Key */
  clear_maxmind_license_key?: boolean
  slots?: GeoIpSlotSettingInput[]
}

export interface GeoIpInstallResult {
  slot: string
  filename: string
  previous_sha256: string
  new_sha256: string
  size_bytes: number
  revision: string
  unchanged: boolean
  loaded_sources: string[]
  ha_results?: GeoIpHANodeSyncResult[]
}

export interface GeoIpSyncRun {
  id: string
  slot: string
  trigger_type: string
  status: string
  source_label: string
  previous_sha256: string
  new_sha256: string
  file_size_bytes: number
  ha_results: GeoIpHANodeSyncResult[]
  error_message: string
  operator_id?: string | null
  started_at: string
  finished_at: string
}

/** POST /api/v1/geoip/sync 与 POST /api/v1/geoip/ha-resync 统一响应体 */
export interface GeoIpSyncActionResponse {
  runs: GeoIpSyncRun[]
  succeeded: number
  skipped: number
  partial_ha_failed: number
  failed: number
}

export type GeoIpSyncResponse = GeoIpSyncActionResponse
export type GeoIpHAResyncResponse = GeoIpSyncActionResponse

export interface GeoIpRunsParams {
  slot?: string
  trigger_type?: string
  status?: string
  page: number
  page_size: number
}

/* ==================== 威胁情报 IP 黑名单库 ==================== */

export interface ThreatIntelSettings {
  auto_update_enabled: boolean
  circuit_threshold: number
}

export interface ThreatIntelSummary {
  enabled_count: number
  total_active_rules: number
  circuit_open_count: number
}

export interface ThreatIntelPresetInfo {
  key: string
  name: string
  description?: string
  url?: string
  format: 'text' | 'csv' | string
  license: string
  default_ttl_days?: number
  default_cron?: string
  allow_cidr?: boolean
}

export interface ThreatIntelFeed {
  id: string
  feed_key: string
  name: string
  description: string
  is_builtin: boolean
  enabled: boolean
  source_mode: IpLibrarySourceMode | string
  official_preset: string
  custom_url: string
  format: 'text' | 'csv' | string
  allow_cidr: boolean
  ttl_days: number
  schedule_cron: string
  min_entries_guard: boolean
  max_drop_ratio: number
  etag?: string
  last_modified?: string
  last_content_sha256?: string
  active_rule_count: number
  consecutive_failures: number
  circuit_open: boolean
  last_sync_at?: string | null
  last_status: string
  last_error: string
  created_at?: string
  updated_at?: string
}

export interface ThreatIntelFeedsResponse {
  settings: ThreatIntelSettings
  summary: ThreatIntelSummary
  presets: ThreatIntelPresetInfo[]
  feeds: ThreatIntelFeed[]
}

export interface ThreatIntelFeedBody {
  feed_key?: string
  name: string
  description?: string
  enabled: boolean
  source_mode: IpLibrarySourceMode | string
  official_preset?: string
  custom_url?: string
  format: 'text' | 'csv'
  allow_cidr: boolean
  ttl_days: number
  schedule_cron: string
  min_entries_guard: boolean
  max_drop_ratio: number
}

export interface ThreatIntelSyncRun {
  id: string
  feed_key: string
  trigger_type: string
  batch_id: string
  status: string
  total_parsed: number
  added: number
  refreshed: number
  expired: number
  skipped_conflict: number
  invalid_count: number
  published: boolean
  error_message: string
  operator_id?: string | null
  started_at: string
  finished_at: string
}

/** POST /api/v1/threat-intel/feeds/{id}/sync 响应载荷 */
export interface ThreatIntelSyncFeedResult {
  run: ThreatIntelSyncRun | null
  feed: ThreatIntelFeed | null
  guard_triggered: boolean
  guard_reason?: string
  circuit_opened: boolean
  changed_rules: number
}

export interface ThreatIntelDeleteFeedResult {
  deleted: boolean
  id: string
  feed_key: string
}

export interface ThreatIntelImportBody {
  feed: string
  format: 'text' | 'csv'
  ttl_days: number
  content: string
}

export interface ThreatIntelConflictItem {
  address: string
  reason: string
}

export interface ThreatIntelRowError {
  line: number
  content: string
  error: string
}

export interface ThreatIntelImportResult {
  batch_id: string
  feed: string
  ttl_days: number
  total_parsed: number
  added: number
  refreshed: number
  expired: number
  skipped_conflict: number
  invalid: number
  truncated: boolean
  conflicts: ThreatIntelConflictItem[]
  invalid_entries: ThreatIntelRowError[]
}

export interface ThreatIntelRunsParams {
  feed_key?: string
  trigger_type?: string
  status?: string
  page: number
  page_size: number
}

function normalizeGeoSlot(slot: GeoIpSlotStatus): GeoIpSlotStatus {
  return {
    ...slot,
    backups: slot.backups ?? [],
  }
}

function normalizeGeoRun(run: GeoIpSyncRun): GeoIpSyncRun {
  return {
    ...run,
    ha_results: run.ha_results ?? [],
  }
}

/**
 * IP 库（GeoIP 归属地库 + 威胁情报 IP 黑名单库）管理 API。
 * 权限：
 * - 出站设置：geoip.read 或 threat_intel.read（查）/ geoip.manage（改）
 * - GeoIP：geoip.read / geoip.manage
 * - 威胁情报：threat_intel.read / threat_intel.manage / access_rules.import（离线导入）
 */
export const ipLibrariesApi = {
  /* ---- 出站代理与镜像白名单 ---- */
  getOutboundSettings: () =>
    request<OutboundSettings>('/ip-libraries/outbound-settings'),

  updateOutboundSettings: (body: UpdateOutboundSettingsBody) =>
    request<OutboundSettings>('/ip-libraries/outbound-settings', {
      method: 'PUT',
      body,
    }),

  /* ---- GeoIP 归属地库 ---- */
  getGeoIpStatus: async (): Promise<GeoIpStatusResponse> => {
    const data = await request<GeoIpStatusResponse>('/geoip/status')
    return {
      ...data,
      sources: data.sources ?? [],
      slots: (data.slots ?? []).map(normalizeGeoSlot),
      ha_nodes: data.ha_nodes ?? [],
      presets: data.presets ?? [],
    }
  },

  updateGeoIpSettings: (body: UpdateGeoIpSettingsBody) =>
    request<GeoIpStatusResponse>('/geoip/settings', {
      method: 'PUT',
      body,
    }),

  syncGeoIp: async (slot = ''): Promise<GeoIpSyncActionResponse> => {
    const data = await request<GeoIpSyncActionResponse>('/geoip/sync', {
      method: 'POST',
      body: { slot },
      timeoutMs: 300_000,
    })
    return {
      ...data,
      runs: (data.runs ?? []).map(normalizeGeoRun),
    }
  },

  /** 离线上传 GeoIP 库（multipart/form-data，复用 upload() 自动附带 X-CSRF-Token） */
  uploadGeoIp: (
    slot: string,
    file: File,
    expectedSha256?: string,
    onProgress?: (progress: UploadProgress) => void,
  ) => {
    const form = new FormData()
    form.append('slot', slot)
    form.append('file', file)
    const trimmedSha = expectedSha256?.trim()
    if (trimmedSha) {
      form.append('expected_sha256', trimmedSha)
    }
    return upload<GeoIpInstallResult>('/geoip/upload', form, { onProgress })
  },

  rollbackGeoIp: (slot: string, backup_id: string) =>
    request<GeoIpInstallResult>('/geoip/rollback', {
      method: 'POST',
      body: { slot, backup_id },
    }),

  haResyncGeoIp: async (slot = ''): Promise<GeoIpSyncActionResponse> => {
    const data = await request<GeoIpSyncActionResponse>('/geoip/ha-resync', {
      method: 'POST',
      body: { slot },
      timeoutMs: 300_000,
    })
    return {
      ...data,
      runs: (data.runs ?? []).map(normalizeGeoRun),
    }
  },

  listGeoIpRuns: async (params: GeoIpRunsParams): Promise<PageResult<GeoIpSyncRun>> => {
    const data = await request<PageResult<GeoIpSyncRun>>('/geoip/runs', {
      query: { ...params },
    })
    return {
      ...data,
      items: (data.items ?? []).map(normalizeGeoRun),
    }
  },

  /* ---- 威胁情报 IP 黑名单库 ---- */
  listThreatIntelFeeds: async (): Promise<ThreatIntelFeedsResponse> => {
    const data = await request<ThreatIntelFeedsResponse>('/threat-intel/feeds')
    return {
      ...data,
      presets: data.presets ?? [],
      feeds: data.feeds ?? [],
    }
  },

  updateThreatIntelSettings: (body: ThreatIntelSettings) =>
    request<ThreatIntelSettings>('/threat-intel/settings', {
      method: 'PUT',
      body,
    }),

  createThreatIntelFeed: (body: ThreatIntelFeedBody) =>
    request<ThreatIntelFeed>('/threat-intel/feeds', {
      method: 'POST',
      body,
    }),

  updateThreatIntelFeed: (id: string, body: ThreatIntelFeedBody) =>
    request<ThreatIntelFeed>(`/threat-intel/feeds/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body,
    }),

  deleteThreatIntelFeed: (id: string) =>
    request<ThreatIntelDeleteFeedResult>(`/threat-intel/feeds/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    }),

  syncThreatIntelFeed: (id: string, force_ignore_guard = false) =>
    request<ThreatIntelSyncFeedResult>(`/threat-intel/feeds/${encodeURIComponent(id)}/sync`, {
      method: 'POST',
      body: { force_ignore_guard },
      timeoutMs: 180_000,
    }),

  importThreatIntelSnapshot: async (body: ThreatIntelImportBody): Promise<ThreatIntelImportResult> => {
    const data = await request<ThreatIntelImportResult>('/threat-intel/import', {
      method: 'POST',
      body,
      timeoutMs: 180_000,
    })
    return {
      ...data,
      conflicts: data.conflicts ?? [],
      invalid_entries: data.invalid_entries ?? [],
    }
  },

  listThreatIntelRuns: async (
    params: ThreatIntelRunsParams,
  ): Promise<PageResult<ThreatIntelSyncRun>> => {
    const data = await request<PageResult<ThreatIntelSyncRun>>('/threat-intel/runs', {
      query: { ...params },
    })
    return {
      ...data,
      items: data.items ?? [],
    }
  },
}
