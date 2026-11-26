import { request } from './client'

/**
 * eBPF/XDP 内核级高速丢包加速管理面客户端（WDSP Phase 9D-2）。
 * 路由：
 * - GET  /xdp-acceleration/config（读取 XDP 加速全局配置）
 * - PUT  /xdp-acceleration/config（保存 XDP 加速配置并尽最大努力同步至守护进程）
 * - GET  /xdp-acceleration/status（通过本地 Unix Socket 探测 xdpguard 实时状态与丢包计数）
 * - POST /xdp-acceleration/sync（立即触发全局 IP 黑名单与全局临时封禁同步至 XDP）
 * 权限：xdp_accel.read（只读）/ xdp_accel.manage（编辑保存与手动同步）。
 */

export type XdpAttachMode = 'auto' | 'native' | 'generic'
export type XdpRuntimeMode = 'xdp_native' | 'xdp_generic' | 'fallback_userspace'
export type XdpDaemonStatus =
  | 'ok'
  | 'degraded'
  | 'unavailable'
  | 'invalid_socket_path'

/** 前后端与 xdpguard 守护进程严格对齐的校验上限常量 */
export const XDP_ACCEL_LIMITS = Object.freeze({
  defaultSocketPath: '/var/run/caddy/sidecars/xdpguard.sock',
  allowedSocketPrefixes: Object.freeze([
    '/var/run/caddy/sidecars/',
    '/run/jiuzhang/',
  ] as const),
  maxSocketPathLen: 256,
  maxInterfaces: 16,
  minSyncIntervalSec: 1,
  maxSyncIntervalSec: 300,
  defaultSyncIntervalSec: 5,
  defaultAttachMode: 'auto' as XdpAttachMode,
  maxReasonLen: 500,
} as const)

/** GET /xdp-acceleration/config 响应结构 */
export interface XdpAccelConfig {
  enabled: boolean
  socket_path: string
  interfaces: string[]
  attach_mode: XdpAttachMode
  sync_interval_seconds: number
  version: number
  updated_at: string
}

/** PUT /xdp-acceleration/config 请求体 */
export interface XdpAccelConfigUpdateBody {
  enabled: boolean
  socket_path: string
  interfaces: string[]
  attach_mode: XdpAttachMode
  sync_interval_seconds: number
  reason?: string
}

/** POST /xdp-acceleration/sync 响应结构 */
export interface XdpAccelSyncResult {
  synced: boolean
  mode: XdpRuntimeMode | string
  kernel_attached: boolean
  attached_interfaces: string[]
  synced_v4_cidrs: number
  synced_v6_cidrs: number
  excluded_protected_count: number
  control_plane_excluded_count?: number
  invalid_cidrs_skipped?: number
  last_sync_at: string
  error?: string
}

/** PUT /xdp-acceleration/config 响应结构 */
export interface XdpAccelConfigUpdateResult {
  config: XdpAccelConfig
  sync_warning?: string
  sync_result?: XdpAccelSyncResult
}

/** 单网卡 XDP 挂载状态 */
export interface XdpInterfaceStatus {
  name: string
  attached: boolean
  mode: XdpRuntimeMode | string
  error?: string
}

/** GET /xdp-acceleration/status 响应结构 */
export interface XdpAccelStatus {
  available: boolean
  status: XdpDaemonStatus | string
  mode: XdpRuntimeMode | string
  kernel_attached: boolean
  socket_path: string
  attach_mode_requested: XdpAttachMode | string
  interfaces: XdpInterfaceStatus[]
  dropped_v4_packets: number
  dropped_v6_packets: number
  passed_packets: number
  synced_v4_cidrs: number
  synced_v6_cidrs: number
  excluded_protected_count: number
  last_sync_at: string
  error?: string
}

function toSafeCount(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? value
    : 0
}

function normalizeAttachMode(value: unknown): XdpAttachMode {
  if (value === 'native' || value === 'generic' || value === 'auto') {
    return value
  }
  return XDP_ACCEL_LIMITS.defaultAttachMode
}

function normalizeStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean)
}

function normalizeConfig(c?: Partial<XdpAccelConfig> | null): XdpAccelConfig {
  const interval =
    typeof c?.sync_interval_seconds === 'number' &&
    Number.isFinite(c.sync_interval_seconds) &&
    c.sync_interval_seconds >= XDP_ACCEL_LIMITS.minSyncIntervalSec &&
    c.sync_interval_seconds <= XDP_ACCEL_LIMITS.maxSyncIntervalSec
      ? Math.trunc(c.sync_interval_seconds)
      : XDP_ACCEL_LIMITS.defaultSyncIntervalSec

  return {
    enabled: Boolean(c?.enabled),
    socket_path:
      typeof c?.socket_path === 'string' && c.socket_path.trim()
        ? c.socket_path.trim()
        : XDP_ACCEL_LIMITS.defaultSocketPath,
    interfaces: normalizeStringList(c?.interfaces),
    attach_mode: normalizeAttachMode(c?.attach_mode),
    sync_interval_seconds: interval,
    version: toSafeCount(c?.version),
    updated_at: typeof c?.updated_at === 'string' ? c.updated_at : '',
  }
}

function normalizeInterfaceStatus(
  item: Partial<XdpInterfaceStatus>,
): XdpInterfaceStatus {
  return {
    name: typeof item.name === 'string' ? item.name : '',
    attached: Boolean(item.attached),
    mode:
      typeof item.mode === 'string' && item.mode.trim()
        ? item.mode.trim()
        : 'fallback_userspace',
    ...(typeof item.error === 'string' && item.error.trim()
      ? { error: item.error }
      : {}),
  }
}

function normalizeStatus(s?: Partial<XdpAccelStatus> | null): XdpAccelStatus {
  const available = Boolean(s?.available)
  return {
    available,
    status:
      typeof s?.status === 'string' && s.status.trim()
        ? s.status.trim()
        : available
          ? 'ok'
          : 'unavailable',
    mode:
      typeof s?.mode === 'string' && s.mode.trim()
        ? s.mode.trim()
        : 'fallback_userspace',
    kernel_attached: Boolean(s?.kernel_attached),
    socket_path:
      typeof s?.socket_path === 'string' && s.socket_path.trim()
        ? s.socket_path.trim()
        : XDP_ACCEL_LIMITS.defaultSocketPath,
    attach_mode_requested:
      typeof s?.attach_mode_requested === 'string' &&
      s.attach_mode_requested.trim()
        ? s.attach_mode_requested.trim()
        : XDP_ACCEL_LIMITS.defaultAttachMode,
    interfaces: Array.isArray(s?.interfaces)
      ? s.interfaces.map(normalizeInterfaceStatus)
      : [],
    dropped_v4_packets: toSafeCount(s?.dropped_v4_packets),
    dropped_v6_packets: toSafeCount(s?.dropped_v6_packets),
    passed_packets: toSafeCount(s?.passed_packets),
    synced_v4_cidrs: toSafeCount(s?.synced_v4_cidrs),
    synced_v6_cidrs: toSafeCount(s?.synced_v6_cidrs),
    excluded_protected_count: toSafeCount(s?.excluded_protected_count),
    last_sync_at: typeof s?.last_sync_at === 'string' ? s.last_sync_at : '',
    ...(typeof s?.error === 'string' && s.error.trim()
      ? { error: s.error }
      : {}),
  }
}

function normalizeSyncResult(
  r?: Partial<XdpAccelSyncResult> | null,
): XdpAccelSyncResult {
  return {
    synced: Boolean(r?.synced),
    mode:
      typeof r?.mode === 'string' && r.mode.trim()
        ? r.mode.trim()
        : 'fallback_userspace',
    kernel_attached: Boolean(r?.kernel_attached),
    attached_interfaces: normalizeStringList(r?.attached_interfaces),
    synced_v4_cidrs: toSafeCount(r?.synced_v4_cidrs),
    synced_v6_cidrs: toSafeCount(r?.synced_v6_cidrs),
    excluded_protected_count: toSafeCount(r?.excluded_protected_count),
    ...(typeof r?.control_plane_excluded_count === 'number'
      ? {
          control_plane_excluded_count: toSafeCount(
            r.control_plane_excluded_count,
          ),
        }
      : {}),
    ...(typeof r?.invalid_cidrs_skipped === 'number'
      ? { invalid_cidrs_skipped: toSafeCount(r.invalid_cidrs_skipped) }
      : {}),
    last_sync_at: typeof r?.last_sync_at === 'string' ? r.last_sync_at : '',
    ...(typeof r?.error === 'string' && r.error.trim()
      ? { error: r.error }
      : {}),
  }
}

export const xdpAccelApi = {
  getConfig: async (): Promise<XdpAccelConfig> => {
    const data = await request<XdpAccelConfig>('/xdp-acceleration/config')
    return normalizeConfig(data)
  },

  updateConfig: async (
    body: XdpAccelConfigUpdateBody,
  ): Promise<XdpAccelConfigUpdateResult> => {
    const data = await request<XdpAccelConfigUpdateResult>(
      '/xdp-acceleration/config',
      {
        method: 'PUT',
        body,
      },
    )
    return {
      config: normalizeConfig(data?.config),
      ...(typeof data?.sync_warning === 'string' && data.sync_warning.trim()
        ? { sync_warning: data.sync_warning }
        : {}),
      ...(data?.sync_result
        ? { sync_result: normalizeSyncResult(data.sync_result) }
        : {}),
    }
  },

  getStatus: async (): Promise<XdpAccelStatus> => {
    const data = await request<XdpAccelStatus>('/xdp-acceleration/status')
    return normalizeStatus(data)
  },

  sync: async (): Promise<XdpAccelSyncResult> => {
    const data = await request<XdpAccelSyncResult>('/xdp-acceleration/sync', {
      method: 'POST',
    })
    return normalizeSyncResult(data)
  },
}
