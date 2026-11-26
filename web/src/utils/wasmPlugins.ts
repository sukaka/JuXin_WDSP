import { WASM_PLUGIN_LIMITS } from '../api/wasmPlugins'

/**
 * Wasm 热插拔自定义检测插件沙箱（WDSP Phase 9D-1）
 * 中文枚举元数据、客户端 WASM 魔数与大小校验、ArrayBuffer→Base64 编码及字段错误路径映射。
 */

export interface WasmPluginLabelMeta {
  color: string
  label: string
}

/** 插件运行模式：OFF 关闭 / OBSERVE 观察中 / PROTECT 强制执行 */
export const WASM_PLUGIN_MODE_META: Record<string, WasmPluginLabelMeta> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察中' },
  PROTECT: { color: 'green', label: '强制执行' },
}

/** 异常降级策略：FAIL_OPEN 故障放行 / FAIL_CLOSED 故障闭环（503） */
export const WASM_PLUGIN_FAIL_POLICY_META: Record<string, WasmPluginLabelMeta> =
  {
    FAIL_OPEN: { color: 'blue', label: '故障放行（Fail-Open）' },
    FAIL_CLOSED: {
      color: 'volcano',
      label: '故障闭环（Fail-Closed，返回 503）',
    },
  }

/** 表格紧凑展示用的降级策略短标签 */
export const WASM_PLUGIN_FAIL_POLICY_SHORT_META: Record<
  string,
  WasmPluginLabelMeta
> = {
  FAIL_OPEN: { color: 'blue', label: 'Fail-Open' },
  FAIL_CLOSED: { color: 'volcano', label: 'Fail-Closed' },
}

/** Wasm 检测插件访问控制事件类型 */
export const WASM_PLUGIN_EVENT_TYPE_META: Record<string, WasmPluginLabelMeta> =
  {
    WASM_PLUGIN_OBSERVED: { color: 'blue', label: 'Wasm 插件观测' },
    WASM_PLUGIN_BLOCK: { color: 'red', label: 'Wasm 插件阻断' },
    WASM_PLUGIN_RATE_LIMIT: { color: 'volcano', label: 'Wasm 插件限速' },
    WASM_PLUGIN_ERROR: { color: 'orange', label: 'Wasm 插件执行异常' },
  }

/** 标准 WebAssembly 1.0 二进制魔数 + 版本头（\x00asm\x01\x00\x00\x00） */
export const WASM_MAGIC_HEADER = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
])

export const WASM_PLUGIN_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/
export const WASM_SHA256_HEX_RE = /^[a-fA-F0-9]{64}$/
// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\r\n\u0000-\u001f\u007f]/

function toUint8Array(input: ArrayBuffer | Uint8Array): Uint8Array {
  return input instanceof Uint8Array ? input : new Uint8Array(input)
}

/** 客户端校验 WebAssembly 1.0 二进制头（\x00asm\x01\x00\x00\x00） */
export function hasValidWasmMagicHeader(
  input: ArrayBuffer | Uint8Array,
): boolean {
  const bytes = toUint8Array(input)
  if (bytes.byteLength < WASM_MAGIC_HEADER.length) return false
  for (let i = 0; i < WASM_MAGIC_HEADER.length; i += 1) {
    if (bytes[i] !== WASM_MAGIC_HEADER[i]) return false
  }
  return true
}

/** 客户端校验上传的 .wasm 字节流：非空、<= 4 MiB、且魔数与版本头合法 */
export function validateWasmBinaryBuffer(
  input: ArrayBuffer | Uint8Array,
): string | null {
  const bytes = toUint8Array(input)
  if (bytes.byteLength === 0) {
    return 'Wasm 文件内容不能为空'
  }
  if (bytes.byteLength > WASM_PLUGIN_LIMITS.maxBinaryBytes) {
    return `Wasm 二进制大小不能超过 ${Math.round(WASM_PLUGIN_LIMITS.maxBinaryBytes / (1024 * 1024))} MiB`
  }
  if (
    bytes.byteLength < 4 ||
    bytes[0] !== 0x00 ||
    bytes[1] !== 0x61 ||
    bytes[2] !== 0x73 ||
    bytes[3] !== 0x6d
  ) {
    return '无效的 WebAssembly 二进制文件（缺少 \\0asm 魔数头）'
  }
  if (!hasValidWasmMagicHeader(bytes)) {
    return '仅支持 WebAssembly 1.0 二进制模块（版本头须为 0x01000000）'
  }
  return null
}

/** 将 ArrayBuffer / Uint8Array 分块编码为标准 Base64（避免大文件展开参数触发调用栈溢出） */
export function arrayBufferToBase64(input: ArrayBuffer | Uint8Array): string {
  const bytes = toUint8Array(input)
  if (bytes.byteLength === 0) return ''
  const chunkSize = 0x8000
  const chunks: string[] = []
  for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
    const slice = bytes.subarray(
      offset,
      Math.min(offset + chunkSize, bytes.byteLength),
    )
    let str = ''
    for (let i = 0; i < slice.length; i += 1) {
      str += String.fromCharCode(slice[i])
    }
    chunks.push(str)
  }
  return btoa(chunks.join(''))
}

/** 截断展示插件 SHA-256 摘要（默认前 12 位） */
export function formatShortSha256(sha256?: string, prefixLen = 12): string {
  const v = (sha256 ?? '').trim()
  if (!v) return '-'
  if (v.length <= prefixLen + 2) return v
  return `${v.slice(0, prefixLen)}…`
}

/** 以 KiB 格式化 Wasm 二进制体积 */
export function formatWasmSizeKiB(bytes?: number | null): string {
  if (
    bytes === null ||
    bytes === undefined ||
    !Number.isFinite(bytes) ||
    bytes < 0
  ) {
    return '-'
  }
  const kib = bytes / 1024
  if (kib >= 100) return `${kib.toFixed(0)} KiB`
  if (kib >= 10) return `${kib.toFixed(1)} KiB`
  return `${kib.toFixed(2)} KiB`
}

/** 校验插件名称（与后端 ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$ 严格对齐） */
export function validateWasmPluginName(raw?: string): string | null {
  const v = (raw ?? '').trim()
  if (!v) return '请输入插件名称'
  if (v.length > WASM_PLUGIN_LIMITS.maxNameLen) {
    return `插件名称不能超过 ${WASM_PLUGIN_LIMITS.maxNameLen} 字符`
  }
  if (!WASM_PLUGIN_NAME_RE.test(v)) {
    return '插件名称须以字母或数字开头，仅允许字母、数字、点、下划线和短横线'
  }
  return null
}

/** 校验可选预期 SHA-256 摘要（留空跳过，非空须为 64 位十六进制） */
export function validateExpectedSha256(raw?: string): string | null {
  const v = (raw ?? '').trim()
  if (!v) return null
  if (!WASM_SHA256_HEX_RE.test(v)) {
    return '预期 SHA-256 须为 64 位十六进制字符'
  }
  return null
}

/** 规范化并去重路径前缀列表 */
export function normalizePathPrefixes(items?: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const raw of items ?? []) {
    const trimmed = raw.trim()
    if (!trimmed || seen.has(trimmed)) continue
    seen.add(trimmed)
    out.push(trimmed)
  }
  return out
}

/** 校验生效路径前缀列表（<= 32 条，须以 / 开头，不含 ?#、空白或控制字符，长度 <= 256） */
export function validateWasmPathPrefixes(prefixes?: string[]): string | null {
  const list = normalizePathPrefixes(prefixes)
  if (list.length > WASM_PLUGIN_LIMITS.maxPathPrefixes) {
    return `生效路径前缀最多允许 ${WASM_PLUGIN_LIMITS.maxPathPrefixes} 条`
  }
  for (const p of list) {
    if (!p.startsWith('/')) {
      return `路径前缀「${p}」必须以 / 开头`
    }
    if (p.length > WASM_PLUGIN_LIMITS.maxPathLen) {
      return `路径前缀长度不能超过 ${WASM_PLUGIN_LIMITS.maxPathLen} 字符`
    }
    if (/[?#\s]/.test(p) || CONTROL_CHAR_RE.test(p)) {
      return `路径前缀「${p}」不能包含查询参数（?）、片段（#）、空白或控制字符`
    }
  }
  return null
}

/** 后端字段级校验错误路径 → Antd Form 字段路径 */
export function mapWasmPluginFieldErrorPath(
  field: string,
): (string | number)[] | null {
  const trimmed = field.trim()
  switch (trimmed) {
    case 'name':
    case 'application_id':
    case 'description':
    case 'mode':
    case 'wasm_base64':
    case 'expected_sha256':
    case 'priority':
    case 'timeout_ms':
    case 'max_memory_kb':
    case 'max_body_bytes':
    case 'fail_policy':
    case 'path_prefixes':
    case 'reason':
    case 'expected_version':
    case 'target_version':
      return [trimmed]
    default:
      break
  }
  const indexed = /^path_prefixes\[\d+\]$/.exec(trimmed)
  if (indexed) {
    return ['path_prefixes']
  }
  return null
}
