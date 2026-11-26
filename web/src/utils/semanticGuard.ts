import { SEMANTIC_GUARD_LIMITS } from '../api/semanticGuard'

/**
 * 本地离线 ONNX/SLM 语义防火墙（WDSP Phase 9C-2）
 * 中文枚举元数据、前后端对齐校验器与后端字段错误路径映射。
 */

export interface SemanticGuardLabelMeta {
  color: string
  label: string
}

/** 策略运行模式：OFF 关闭 / OBSERVE 观察中 / PROTECT 强制执行 */
export const SEMANTIC_GUARD_MODE_META: Record<string, SemanticGuardLabelMeta> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察中' },
  PROTECT: { color: 'green', label: '强制执行' },
}

/** 策略草稿/发布状态摘要 */
export const SEMANTIC_GUARD_STATE_META: Record<string, SemanticGuardLabelMeta> =
  {
    NOT_CONFIGURED: { color: 'default', label: '未配置' },
    DRAFT_PENDING: { color: 'gold', label: '草稿待发布' },
    PUBLISHED: { color: 'green', label: '已发布' },
  }

/** Sidecar 异常降级策略：FAIL_OPEN 故障放行 / FAIL_CLOSED 故障闭环（503） */
export const SEMANTIC_GUARD_FAIL_POLICY_META: Record<
  string,
  SemanticGuardLabelMeta
> = {
  FAIL_OPEN: { color: 'blue', label: '故障放行（Fail-Open）' },
  FAIL_CLOSED: { color: 'volcano', label: '故障闭环（Fail-Closed，返回 503）' },
}

/** Sidecar 推理后端类型 */
export const SEMANTIC_GUARD_BACKEND_META: Record<
  string,
  SemanticGuardLabelMeta
> = {
  onnxruntime: { color: 'green', label: 'ONNX Runtime 本地推理' },
  heuristic_fallback: { color: 'gold', label: '启发式降级引擎' },
}

/** 本地语义防火墙安全事件类型 */
export const SEMANTIC_GUARD_EVENT_TYPE_META: Record<
  string,
  SemanticGuardLabelMeta
> = {
  SEMANTIC_OBSERVED: { color: 'blue', label: '本地语义防火墙观测' },
  SEMANTIC_BLOCKED: { color: 'red', label: '本地语义防火墙阻断' },
  SEMANTIC_UNAVAILABLE: { color: 'orange', label: '本地语义推理引擎不可用' },
}

/** 本地语义防火墙规则 ID 元数据 */
export const SEMANTIC_GUARD_RULE_ID_META: Record<
  string,
  SemanticGuardLabelMeta
> = {
  'semantic.prompt_injection': { color: 'red', label: '语义提示词注入' },
  'semantic.jailbreak': { color: 'volcano', label: '语义越狱攻击' },
  'semantic.indirect_injection': {
    color: 'magenta',
    label: '语义间接提示词注入',
  },
  'semantic.web_payload': { color: 'orange', label: 'Web 灰区语义恶意载荷' },
  'semantic.sidecar_unavailable': {
    color: 'gold',
    label: '语义推理引擎不可用',
  },
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\r\n\u0000-\u001f\u007f]/
const URI_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/

/** 截断展示模型 SHA-256 指纹（保留前 12 位 hex） */
export function formatShortSha256(sha256?: string, prefixLen = 12): string {
  const v = (sha256 ?? '').trim()
  if (!v) return '-'
  if (v.length <= prefixLen + 2) return v
  return `${v.slice(0, prefixLen)}…`
}

/**
 * 校验本地语义 Sidecar Unix Socket 路径：
 * 严格限定在 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 之下，
 * 拒绝路径穿越（.. / .）、多斜杠、目录尾斜杠、控制字符、空白、反斜杠以及任何 HTTP/TCP 等 URI Scheme。
 */
export function validateSemanticSocketPath(raw?: string): string | null {
  const v = (raw ?? '').trim()
  if (!v) {
    return '请填写本地 Unix Socket 路径'
  }
  if (v.length > SEMANTIC_GUARD_LIMITS.maxSocketPathLen) {
    return `Socket 路径长度不能超过 ${SEMANTIC_GUARD_LIMITS.maxSocketPathLen} 字符`
  }
  if (CONTROL_CHAR_RE.test(v) || /\s/.test(v) || v.includes('\\')) {
    return 'Socket 路径不能包含空白、反斜杠或控制字符'
  }
  if (v.includes('://') || URI_SCHEME_RE.test(v)) {
    return '仅支持本地 Unix Socket 绝对路径，禁止 HTTP/TCP 等网络地址'
  }
  if (v.includes('..')) {
    return 'Socket 路径不能包含上级目录穿越片段（..）'
  }
  if (v.includes('//') || v.endsWith('/')) {
    return 'Socket 路径须为规范的文件路径，不能包含重复斜杠或以 / 结尾'
  }
  const matchedPrefix = SEMANTIC_GUARD_LIMITS.allowedSocketPrefixes.find(
    (prefix) => v.startsWith(prefix),
  )
  if (!matchedPrefix || v.length <= matchedPrefix.length) {
    return 'Socket 路径必须以 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 开头并指定文件名'
  }
  const restSegments = v.slice(matchedPrefix.length).split('/')
  if (restSegments.some((seg) => !seg || seg === '.' || seg === '..')) {
    return 'Socket 路径包含非法目录片段'
  }
  return null
}

/** 校验观察阈值与阻断阈值范围及跨字段约束（observe_threshold <= block_threshold） */
export function validateSemanticThresholds(
  observeThreshold?: number,
  blockThreshold?: number,
): string | null {
  if (
    typeof observeThreshold !== 'number' ||
    Number.isNaN(observeThreshold) ||
    observeThreshold < SEMANTIC_GUARD_LIMITS.minObserveThreshold ||
    observeThreshold > SEMANTIC_GUARD_LIMITS.maxObserveThreshold
  ) {
    return `观察阈值须在 ${SEMANTIC_GUARD_LIMITS.minObserveThreshold.toFixed(2)} 到 ${SEMANTIC_GUARD_LIMITS.maxObserveThreshold.toFixed(2)} 之间`
  }
  if (
    typeof blockThreshold !== 'number' ||
    Number.isNaN(blockThreshold) ||
    blockThreshold < SEMANTIC_GUARD_LIMITS.minBlockThreshold ||
    blockThreshold > SEMANTIC_GUARD_LIMITS.maxBlockThreshold
  ) {
    return `阻断阈值须在 ${SEMANTIC_GUARD_LIMITS.minBlockThreshold.toFixed(2)} 到 ${SEMANTIC_GUARD_LIMITS.maxBlockThreshold.toFixed(2)} 之间`
  }
  if (observeThreshold > blockThreshold) {
    return '观察阈值不能高于阻断阈值'
  }
  return null
}

/** 后端字段级校验错误路径 → 表单字段路径 */
export function mapSemanticGuardFieldErrorPath(
  field: string,
): (string | number)[] | null {
  const trimmed = field.trim()
  switch (trimmed) {
    case 'mode':
    case 'socket_path':
    case 'timeout_ms':
    case 'max_concurrency':
    case 'max_input_runes':
    case 'observe_threshold':
    case 'block_threshold':
    case 'fail_policy':
    case 'inspect_llm_prompts':
    case 'inspect_mcp_content':
    case 'inspect_web_grayzone':
    case 'circuit_failure_threshold':
    case 'circuit_open_seconds':
    case 'reason':
      return [trimmed]
    default:
      return null
  }
}
