import {
  CLIENT_SIDE_LIMITS,
  type ClientScriptItem,
  type ClientSideCspMode,
  type ClientSideMode,
} from '../api/clientSide'

/**
 * 客户端供应链安全（WDSP Phase 9B / PCI DSS 4.0 6.4.3 & 11.6.1）
 * 中文枚举映射、CSP 预览编译、前后端一致校验器与表单错误路径映射。
 */

export interface ClientSideLabelMeta {
  color: string
  label: string
}

/** 策略模式：OFF 关闭 / OBSERVE 观察中 / PROTECT 强制执行 */
export const CLIENT_SIDE_MODE_META: Record<string, ClientSideLabelMeta> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察中' },
  PROTECT: { color: 'green', label: '强制执行' },
}

/** 策略发布状态摘要 */
export const CLIENT_SIDE_STATE_META: Record<string, ClientSideLabelMeta> = {
  NOT_CONFIGURED: { color: 'default', label: '未配置' },
  DRAFT_PENDING: { color: 'gold', label: '草稿待发布' },
  PUBLISHED: { color: 'green', label: '已发布' },
}

/** CSP 响应头注入模式 */
export const CLIENT_SIDE_CSP_MODE_META: Record<string, ClientSideLabelMeta> = {
  OFF: { color: 'default', label: '关闭' },
  REPORT_ONLY: { color: 'blue', label: '学习上报（Report-Only）' },
  ENFORCE: { color: 'green', label: '强制执行（Enforce）' },
}

/** 脚本资产类型 */
export const CLIENT_SCRIPT_TYPE_META: Record<string, ClientSideLabelMeta> = {
  EXTERNAL: { color: 'geekblue', label: '外部脚本' },
  INLINE_HASH: { color: 'purple', label: '内联哈希' },
}

/** 脚本审批状态（PCI DSS 4.0 6.4.3） */
export const CLIENT_SCRIPT_STATUS_META: Record<string, ClientSideLabelMeta> = {
  DISCOVERED: { color: 'gold', label: '新发现待审' },
  AUTHORIZED: { color: 'green', label: '已授权' },
  BLOCKED: { color: 'red', label: '已封禁' },
}

/** 违规告警类型（PCI DSS 4.0 11.6.1） */
export const CLIENT_SIDE_VIOLATION_TYPE_META: Record<
  string,
  ClientSideLabelMeta
> = {
  UNAUTHORIZED_SCRIPT: { color: 'orange', label: '未授权脚本' },
  SCRIPT_TAMPERED: { color: 'red', label: '脚本篡改（SRI 异常）' },
  CSP_VIOLATION: { color: 'volcano', label: 'CSP 违规上报' },
  PROBE_ALERT: { color: 'magenta', label: '防窃取探针告警' },
}

/** 违规告警处置状态 */
export const CLIENT_SIDE_VIOLATION_STATUS_META: Record<
  string,
  ClientSideLabelMeta
> = {
  OPEN: { color: 'red', label: '待处置' },
  ACKNOWLEDGED: { color: 'gold', label: '已确认' },
  RESOLVED: { color: 'green', label: '已解决' },
  FALSE_POSITIVE: { color: 'default', label: '误报' },
}

/** 网关实际采取的动作 */
export const CLIENT_SIDE_ACTION_TAKEN_META: Record<
  string,
  ClientSideLabelMeta
> = {
  OBSERVED: { color: 'blue', label: '观测记录' },
  REPORTED: { color: 'gold', label: '客户端上报' },
  STRIPPED: { color: 'red', label: '已剥离脚本' },
  CSP_ENFORCED: { color: 'green', label: 'CSP 强制拦截' },
}

export type SriComparisonState =
  | 'UNPINNED'
  | 'MATCHED'
  | 'MISMATCH'
  | 'MISSING_OBSERVED'
  | 'PENDING_OBSERVATION'

/** 比对固定 SRI（sri_hash）与网关观测 SRI（observed_sri） */
export function getScriptSriComparison(
  script: Pick<ClientScriptItem, 'sri_hash' | 'observed_sri' | 'observed_count'>,
): SriComparisonState {
  const pinned = (script.sri_hash ?? '').trim()
  const observed = (script.observed_sri ?? '').trim()
  if (!pinned) return 'UNPINNED'
  if (observed) {
    return pinned === observed ? 'MATCHED' : 'MISMATCH'
  }
  return script.observed_count > 0 ? 'MISSING_OBSERVED' : 'PENDING_OBSERVATION'
}

export interface CspPreviewInput {
  mode: ClientSideMode
  csp_mode: ClientSideCspMode
  probe_enabled: boolean
  allowed_script_origins: string[]
  allowed_connect_origins: string[]
  allowed_form_origins: string[]
  custom_csp_directives: string
}

export interface CspPreviewResult {
  active: boolean
  headerName:
    | 'Content-Security-Policy'
    | 'Content-Security-Policy-Report-Only'
    | null
  headerValue: string
  note?: string
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\r\n\u0000-\u001f\u007f]/
const SRI_HASH_RE = /^(sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}$/
const CSP_KEYWORD_TOKENS = new Set([
  "'self'",
  "'none'",
  "'unsafe-inline'",
  "'unsafe-eval'",
  "'unsafe-hashes'",
  "'strict-dynamic'",
  "'wasm-unsafe-eval'",
  "'report-sample'",
])
const CSP_SCHEME_RE = /^[a-z][a-z0-9+.-]*:$/i
const CSP_ORIGIN_OR_HOST_RE =
  /^(?:(?:https?|wss?):\/\/)?(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::(?:\d+|\*))?(?:\/[^\s;,]*)?$/i
const CSP_NONCE_OR_HASH_RE =
  /^'(?:nonce-[A-Za-z0-9+/_-]+={0,2}|(?:sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2})'$/

export function hasControlChars(value: string): boolean {
  return CONTROL_CHAR_RE.test(value)
}

function normalizeTokens(items: string[] | undefined): string[] {
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

/** 校验单条敏感路径（必须以 / 开头、不含 ?# 与空白、长度 <= 512） */
export function validateSensitivePaths(
  paths: string[] | undefined,
): string | null {
  const list = normalizeTokens(paths)
  if (list.length > CLIENT_SIDE_LIMITS.maxSensitivePaths) {
    return `敏感路径最多允许 ${CLIENT_SIDE_LIMITS.maxSensitivePaths} 条`
  }
  for (const p of list) {
    if (!p.startsWith('/')) {
      return `路径「${p}」必须以 / 开头`
    }
    if (p.length > CLIENT_SIDE_LIMITS.maxPathLen) {
      return `路径长度不能超过 ${CLIENT_SIDE_LIMITS.maxPathLen} 字符`
    }
    if (/[?#\s]/.test(p) || hasControlChars(p)) {
      return `路径「${p}」不能包含查询参数（?）、片段（#）、空白或控制字符`
    }
  }
  return null
}

/** 校验单个 CSP 来源令牌（无 CR/LF/分号/空白，合法来源格式） */
export function isValidCspOriginToken(token: string): boolean {
  const v = token.trim()
  if (!v || v.length > CLIENT_SIDE_LIMITS.maxOriginLen) return false
  if (hasControlChars(v) || /[;\s,"<>\\`]/.test(v)) return false
  if (v === '*') return true
  if (v.startsWith("'") || v.endsWith("'")) {
    if (!v.startsWith("'") || !v.endsWith("'") || v.length < 3) return false
    return CSP_KEYWORD_TOKENS.has(v.toLowerCase()) || CSP_NONCE_OR_HASH_RE.test(v)
  }
  if (CSP_SCHEME_RE.test(v)) return true
  if (/[?#@]/.test(v)) return false
  return CSP_ORIGIN_OR_HOST_RE.test(v)
}

/** 校验 CSP 允许来源列表（上限 64 条） */
export function validateCspOrigins(
  origins: string[] | undefined,
  fieldLabel: string,
): string | null {
  const list = normalizeTokens(origins)
  if (list.length > CLIENT_SIDE_LIMITS.maxOrigins) {
    return `${fieldLabel}最多允许 ${CLIENT_SIDE_LIMITS.maxOrigins} 条`
  }
  for (const origin of list) {
    if (!isValidCspOriginToken(origin)) {
      return `${fieldLabel}包含非法来源「${origin}」（不允许换行、分号或空白，示例：'self'、https://cdn.example.com）`
    }
  }
  return null
}

/** 校验自定义 CSP 指令（长度 <= 2048，禁止 CR/LF 及控制字符防响应头注入） */
export function validateCustomCspDirectives(raw: string | undefined): string | null {
  const v = raw ?? ''
  if (v.length > CLIENT_SIDE_LIMITS.maxCustomDirectivesLen) {
    return `自定义 CSP 指令不能超过 ${CLIENT_SIDE_LIMITS.maxCustomDirectivesLen} 字符`
  }
  if (hasControlChars(v)) {
    return '自定义 CSP 指令不允许包含换行或控制字符（防止响应头注入）'
  }
  return null
}

/** 校验 SRI 完整性哈希（可留空，非空时须符合 sha256-/sha384-/sha512- base64 格式） */
export function validateSriHash(raw: string | undefined): string | null {
  const v = (raw ?? '').trim()
  if (!v) return null
  if (v.length > 256 || !SRI_HASH_RE.test(v)) {
    return 'SRI 哈希须为 sha256- / sha384- / sha512- 开头的合法 Base64 摘要'
  }
  return null
}

/**
 * 实时编译预览将由网关下发的 CSP 响应头（与 gateway clientside/csp.go 保持同口径）：
 * - mode=OFF 或 csp_mode=OFF 时不下发；
 * - probe_enabled=true 时自动为 script-src 与 connect-src 保障 'self'（移除互斥的 'none'）；
 * - 始终附带 report-uri /_wdsp/csp/v1/report。
 */
export function buildCspPreview(input: CspPreviewInput): CspPreviewResult {
  if (input.csp_mode === 'OFF') {
    return {
      active: false,
      headerName: null,
      headerValue: '',
      note: '当前 CSP 模式为「关闭」，网关不会注入 Content-Security-Policy 响应头。',
    }
  }
  if (input.mode === 'OFF') {
    return {
      active: false,
      headerName: null,
      headerValue: '',
      note: '当前主运行模式为「关闭」，切换为「观察」或「强制执行」后网关才会实际注入 CSP 响应头。',
    }
  }

  const headerName =
    input.csp_mode === 'ENFORCE'
      ? 'Content-Security-Policy'
      : 'Content-Security-Policy-Report-Only'

  const compileSources = (raw: string[] | undefined, ensureSelf: boolean): string[] => {
    const seen = new Set<string>()
    const out: string[] = []
    for (const item of raw ?? []) {
      const tok = item.trim()
      if (!tok || hasControlChars(tok) || tok.includes(';')) continue
      if (ensureSelf && tok.toLowerCase() === "'none'") continue
      const key = tok.toLowerCase()
      if (!seen.has(key)) {
        seen.add(key)
        out.push(tok)
      }
    }
    if (out.length === 0) {
      out.push("'self'")
      seen.add("'self'")
    }
    if (ensureSelf && !seen.has("'self'")) {
      out.unshift("'self'")
    }
    return out
  }

  const scriptOrigins = compileSources(
    input.allowed_script_origins,
    input.probe_enabled,
  )
  const connectOrigins = compileSources(
    input.allowed_connect_origins,
    input.probe_enabled,
  )
  const formOrigins = compileSources(input.allowed_form_origins, false)

  const directives: string[] = [
    `script-src ${scriptOrigins.join(' ')}`,
    `connect-src ${connectOrigins.join(' ')}`,
    `form-action ${formOrigins.join(' ')}`,
  ]

  const custom = (input.custom_csp_directives ?? '')
    .trim()
    .replace(/^[;\s]+|[;\s]+$/g, '')
  if (custom && !hasControlChars(custom)) {
    directives.push(custom)
  }

  directives.push(`report-uri ${CLIENT_SIDE_LIMITS.cspReportEndpoint}`)

  return {
    active: true,
    headerName,
    headerValue: directives.join('; '),
  }
}

/** 后端字段级校验错误路径 → 表单字段路径 */
export function mapClientSideFieldErrorPath(
  field: string,
): (string | number)[] | null {
  const trimmed = field.trim()
  switch (trimmed) {
    case 'mode':
    case 'csp_mode':
    case 'sensitive_paths':
    case 'probe_enabled':
    case 'strip_unauthorized_scripts':
    case 'allowed_script_origins':
    case 'allowed_connect_origins':
    case 'allowed_form_origins':
    case 'custom_csp_directives':
    case 'reason':
    case 'application_id':
    case 'script_url':
    case 'script_type':
    case 'sri_hash':
    case 'status':
    case 'justification':
    case 'note':
      return [trimmed]
    default:
      break
  }

  const indexed =
    /^(sensitive_paths|allowed_script_origins|allowed_connect_origins|allowed_form_origins)\[\d+\]$/.exec(
      trimmed,
    )
  if (indexed?.[1]) {
    return [indexed[1]]
  }
  return null
}
