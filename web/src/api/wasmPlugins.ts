import { request } from './client'

/**
 * Wasm 热插拔自定义检测插件沙箱管理面客户端（WDSP Phase 9D-1）。
 * 路由：
 * - GET    /wasm-plugins（查询：application_id?, mode?, keyword?, page?, page_size?）
 * - POST   /wasm-plugins（上传并创建插件 v1）
 * - GET    /wasm-plugins/{id}（插件详情与不可变历史版本列表）
 * - PUT    /wasm-plugins/{id}（更新配置或替换 .wasm 二进制，expected_version 乐观锁）
 * - POST   /wasm-plugins/{id}/rollback（一键回滚至历史版本，克隆为 version+1）
 * - DELETE /wasm-plugins/{id}（删除插件）
 * 权限：wasm_plugins.read（只读）/ wasm_plugins.manage（上传/编辑/回滚/删除）。
 * 注意：REST GET/LIST 响应永不返回原始 wasm_binary / wasm_base64。
 */

export type WasmPluginMode = 'OFF' | 'OBSERVE' | 'PROTECT'
export type WasmPluginFailPolicy = 'FAIL_OPEN' | 'FAIL_CLOSED'
export type WasmPluginAbiVersion = 'wdsp_v1'
export type WasmPluginEventType =
  | 'WASM_PLUGIN_OBSERVED'
  | 'WASM_PLUGIN_BLOCK'
  | 'WASM_PLUGIN_RATE_LIMIT'
  | 'WASM_PLUGIN_ERROR'

/** 前后端与网关严格对齐的校验上限常量（与 server/internal/wasmplugins 及 gateway wasmplugin/policy.go 一致） */
export const WASM_PLUGIN_LIMITS = {
  abiVersion: 'wdsp_v1' as const,
  maxPluginsPerScope: 16,
  maxBinaryBytes: 4 * 1024 * 1024,
  minPriority: 0,
  maxPriority: 10000,
  defaultPriority: 100,
  minTimeoutMs: 1,
  maxTimeoutMs: 50,
  defaultTimeoutMs: 2,
  minMaxMemoryKb: 256,
  maxMaxMemoryKb: 16384,
  defaultMaxMemoryKb: 4096,
  minMaxBodyBytes: 0,
  maxMaxBodyBytes: 65536,
  defaultMaxBodyBytes: 65536,
  maxPathPrefixes: 32,
  maxPathLen: 256,
  maxNameLen: 128,
  maxReasonLen: 500,
} as const

/** 全局作用域查询哨兵值（过滤 application_id IS NULL 的全局插件） */
export const WASM_PLUGIN_GLOBAL_SCOPE_QUERY = 'global'

/** Wasm 检测插件元数据（不含原始 wasm_binary / wasm_base64） */
export interface WasmPluginItem {
  id: string
  application_id?: string | null
  name: string
  description: string
  version: number
  abi_version: WasmPluginAbiVersion | string
  mode: WasmPluginMode
  sha256: string
  wasm_size: number
  priority: number
  timeout_ms: number
  max_memory_kb: number
  max_body_bytes: number
  fail_policy: WasmPluginFailPolicy
  path_prefixes: string[]
  updated_by: string
  created_at: string
  updated_at: string
}

/** Wasm 检测插件不可变版本历史条目（不含原始二进制） */
export interface WasmPluginVersionItem {
  id: string
  plugin_id?: string
  version: number
  abi_version: WasmPluginAbiVersion | string
  mode: WasmPluginMode
  sha256: string
  wasm_size: number
  reason: string
  created_by: string
  created_at: string
}

export interface WasmPluginListParams {
  /** 省略=全部；'global'=仅全局；UUID=指定应用 */
  application_id?: string
  mode?: WasmPluginMode | string
  keyword?: string
  page?: number
  page_size?: number
}

export interface WasmPluginListResult {
  items: WasmPluginItem[]
  total: number
  page: number
  page_size: number
}

export interface WasmPluginDetailResult {
  plugin: WasmPluginItem
  versions: WasmPluginVersionItem[]
}

export interface WasmPluginCreateBody {
  name: string
  application_id?: string | null
  description: string
  mode: WasmPluginMode
  wasm_base64: string
  expected_sha256?: string
  priority: number
  timeout_ms: number
  max_memory_kb: number
  max_body_bytes: number
  fail_policy: WasmPluginFailPolicy
  path_prefixes: string[]
  reason: string
}

export interface WasmPluginUpdateBody {
  expected_version: number
  description?: string
  mode: WasmPluginMode
  wasm_base64?: string
  expected_sha256?: string
  priority: number
  timeout_ms: number
  max_memory_kb: number
  max_body_bytes: number
  fail_policy: WasmPluginFailPolicy
  path_prefixes: string[]
  reason: string
}

export interface WasmPluginRollbackBody {
  target_version: number
  expected_version: number
  reason: string
}

export interface WasmPluginDeleteResult {
  deleted: boolean
  id: string
}

function normalizePlugin(p: WasmPluginItem): WasmPluginItem {
  const mode: WasmPluginMode =
    p.mode === 'OBSERVE' || p.mode === 'PROTECT' ? p.mode : 'OFF'
  const failPolicy: WasmPluginFailPolicy =
    p.fail_policy === 'FAIL_CLOSED' ? 'FAIL_CLOSED' : 'FAIL_OPEN'

  return {
    ...p,
    application_id: p.application_id ?? null,
    description: p.description ?? '',
    version: p.version ?? 1,
    abi_version: p.abi_version || WASM_PLUGIN_LIMITS.abiVersion,
    mode,
    sha256: p.sha256 ?? '',
    wasm_size: typeof p.wasm_size === 'number' ? p.wasm_size : 0,
    priority:
      typeof p.priority === 'number'
        ? p.priority
        : WASM_PLUGIN_LIMITS.defaultPriority,
    timeout_ms:
      typeof p.timeout_ms === 'number' && p.timeout_ms > 0
        ? p.timeout_ms
        : WASM_PLUGIN_LIMITS.defaultTimeoutMs,
    max_memory_kb:
      typeof p.max_memory_kb === 'number' && p.max_memory_kb > 0
        ? p.max_memory_kb
        : WASM_PLUGIN_LIMITS.defaultMaxMemoryKb,
    max_body_bytes:
      typeof p.max_body_bytes === 'number' && p.max_body_bytes >= 0
        ? p.max_body_bytes
        : WASM_PLUGIN_LIMITS.defaultMaxBodyBytes,
    fail_policy: failPolicy,
    path_prefixes: Array.isArray(p.path_prefixes) ? p.path_prefixes : [],
    updated_by: p.updated_by ?? '',
    created_at: p.created_at ?? '',
    updated_at: p.updated_at ?? '',
  }
}

function normalizeVersion(v: WasmPluginVersionItem): WasmPluginVersionItem {
  const mode: WasmPluginMode =
    v.mode === 'OBSERVE' || v.mode === 'PROTECT' ? v.mode : 'OFF'
  return {
    ...v,
    abi_version: v.abi_version || WASM_PLUGIN_LIMITS.abiVersion,
    mode,
    sha256: v.sha256 ?? '',
    wasm_size: typeof v.wasm_size === 'number' ? v.wasm_size : 0,
    reason: v.reason ?? '',
    created_by: v.created_by ?? '',
    created_at: v.created_at ?? '',
  }
}

export const wasmPluginsApi = {
  list: async (
    params: WasmPluginListParams = {},
  ): Promise<WasmPluginListResult> => {
    const data = await request<WasmPluginListResult>('/wasm-plugins', {
      query: { ...params },
    })
    return {
      items: (data?.items ?? []).map(normalizePlugin),
      total: data?.total ?? 0,
      page: data?.page ?? params.page ?? 1,
      page_size: data?.page_size ?? params.page_size ?? 20,
    }
  },

  create: async (body: WasmPluginCreateBody): Promise<WasmPluginItem> => {
    const data = await request<{ plugin: WasmPluginItem }>('/wasm-plugins', {
      method: 'POST',
      body,
    })
    return normalizePlugin(data.plugin)
  },

  get: async (id: string): Promise<WasmPluginDetailResult> => {
    const data = await request<WasmPluginDetailResult>(`/wasm-plugins/${id}`)
    return {
      plugin: normalizePlugin(data.plugin),
      versions: (data.versions ?? []).map(normalizeVersion),
    }
  },

  update: async (
    id: string,
    body: WasmPluginUpdateBody,
  ): Promise<WasmPluginItem> => {
    const data = await request<{ plugin: WasmPluginItem }>(
      `/wasm-plugins/${id}`,
      { method: 'PUT', body },
    )
    return normalizePlugin(data.plugin)
  },

  rollback: async (
    id: string,
    body: WasmPluginRollbackBody,
  ): Promise<WasmPluginItem> => {
    const data = await request<{ plugin: WasmPluginItem }>(
      `/wasm-plugins/${id}/rollback`,
      { method: 'POST', body },
    )
    return normalizePlugin(data.plugin)
  },

  remove: (id: string): Promise<WasmPluginDeleteResult> =>
    request<WasmPluginDeleteResult>(`/wasm-plugins/${id}`, {
      method: 'DELETE',
    }),
}
