import { API_A2A_LIMITS } from '../api/apiA2a'

/**
 * A2A 协议安全网关与 Agent 物料清单（AgBOM）（WDSP Phase 9C-1）
 * 中文枚举元数据、前后端对齐校验器与后端字段错误路径映射。
 */

export interface A2aLabelMeta {
  color: string
  label: string
}

/** 策略运行模式：OFF 关闭 / OBSERVE 观察中 / PROTECT 强制执行 */
export const A2A_MODE_META: Record<string, A2aLabelMeta> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察中' },
  PROTECT: { color: 'green', label: '强制执行' },
}

/** 策略草稿/发布状态摘要 */
export const A2A_STATE_META: Record<string, A2aLabelMeta> = {
  NOT_CONFIGURED: { color: 'default', label: '未配置' },
  DRAFT_PENDING: { color: 'gold', label: '草稿待发布' },
  PUBLISHED: { color: 'green', label: '已发布' },
}

/** AgBOM Agent 审批状态 */
export const A2A_AGENT_STATUS_META: Record<string, A2aLabelMeta> = {
  DISCOVERED: { color: 'gold', label: '自动发现待审' },
  APPROVED: { color: 'green', label: '已批准' },
  BLOCKED: { color: 'red', label: '已封禁' },
}

/** A2A 安全事件类型 */
export const A2A_EVENT_TYPE_META: Record<string, A2aLabelMeta> = {
  A2A_AGENT_CARD_DISCOVERED: { color: 'cyan', label: '发现 Agent Card' },
  A2A_OBSERVED: { color: 'blue', label: 'A2A 观测告警' },
  A2A_BLOCKED: { color: 'red', label: 'A2A 策略阻断' },
  A2A_LOOP_KILLED: { color: 'volcano', label: '递归循环熔断' },
  A2A_LETHAL_TRIFECTA: { color: 'magenta', label: '致命三要素阻断' },
}

/** A2A 网关规则 ID 元数据 */
export const A2A_RULE_ID_META: Record<string, A2aLabelMeta> = {
  'a2a.caller_agent_denied': { color: 'red', label: '调用方 Agent 未授权' },
  'a2a.delegation_depth_exceeded': { color: 'volcano', label: '委派链深度超限' },
  'a2a.delegation_scope_escalation': { color: 'magenta', label: '委派权限越界/提权' },
  'a2a.recursive_loop_detected': { color: 'orange', label: '检测到递归循环调用' },
  'a2a.lethal_trifecta_blocked': { color: 'red', label: '命中致命三要素外泄链' },
}

/** A2A 事件网关实际动作 */
export const A2A_ACTION_TAKEN_META: Record<string, A2aLabelMeta> = {
  OBSERVED: { color: 'blue', label: '观测记录' },
  BLOCKED: { color: 'red', label: '已阻断' },
  BLOCK: { color: 'red', label: '已阻断' },
  KILLED: { color: 'volcano', label: '已熔断' },
  RATE_LIMITED: { color: 'volcano', label: '循环限流熔断' },
  DISCOVERED: { color: 'cyan', label: '已发现登记' },
  ALLOWED: { color: 'green', label: '已放行' },
}

/** 默认 A2A 路径前缀与默认三要素模式（与网关冻结契约一致） */
export const A2A_DEFAULT_PATH_PREFIXES = [
  '/a2a',
  '/.well-known/agent.json',
  '/.well-known/agent-card.json',
] as const

export const A2A_DEFAULT_CONFIDENTIAL_READ_PATTERNS = [
  '/api/v1/secrets',
  '/api/v1/customers',
  'read_secret',
  'query_pii',
] as const

export const A2A_DEFAULT_EXTERNAL_EGRESS_PATTERNS = [
  'send_email',
  'webhook',
  'http_post',
  'upload_external',
] as const

// eslint-disable-next-line no-control-regex
const CONTROL_CHAR_RE = /[\r\n\u0000-\u001f\u007f]/

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

/** 校验 A2A 路径前缀列表（最多 32 条，必须以 / 开头、不含 ?# 或空白/控制字符、长度 <= 256） */
export function validateA2aPathPrefixes(
  paths: string[] | undefined,
): string | null {
  const list = normalizeTokens(paths)
  if (list.length > API_A2A_LIMITS.maxPathPrefixes) {
    return `A2A 路径前缀最多允许 ${API_A2A_LIMITS.maxPathPrefixes} 条`
  }
  for (const p of list) {
    if (!p.startsWith('/')) {
      return `路径前缀「${p}」必须以 / 开头`
    }
    if (p.length > API_A2A_LIMITS.maxPathLen) {
      return `路径前缀长度不能超过 ${API_A2A_LIMITS.maxPathLen} 字符`
    }
    if (/[?#\s]/.test(p) || CONTROL_CHAR_RE.test(p)) {
      return `路径前缀「${p}」不能包含查询参数（?）、片段（#）、空白或控制字符`
    }
  }
  return null
}

/** 校验允许调用方 Agent 白名单（最多 64 条，长度 <= 128，不含控制字符） */
export function validateAllowedCallerAgents(
  agents: string[] | undefined,
): string | null {
  const list = normalizeTokens(agents)
  if (list.length > API_A2A_LIMITS.maxAllowedAgents) {
    return `允许调用方 Agent 最多 ${API_A2A_LIMITS.maxAllowedAgents} 条`
  }
  for (const name of list) {
    if (name.length > API_A2A_LIMITS.maxAgentNameLen) {
      return `Agent 标识「${name}」不能超过 ${API_A2A_LIMITS.maxAgentNameLen} 字符`
    }
    if (CONTROL_CHAR_RE.test(name)) {
      return `Agent 标识「${name}」不能包含换行或控制字符`
    }
  }
  return null
}

/** 校验致命三要素匹配模式列表（最多 64 条，每条长度 <= 256，不含控制字符） */
export function validateA2aPatterns(
  patterns: string[] | undefined,
  fieldLabel: string,
): string | null {
  const list = normalizeTokens(patterns)
  if (list.length > API_A2A_LIMITS.maxPatterns) {
    return `${fieldLabel}最多允许 ${API_A2A_LIMITS.maxPatterns} 条`
  }
  for (const pat of list) {
    if (pat.length > API_A2A_LIMITS.maxPatternLen) {
      return `${fieldLabel}单条长度不能超过 ${API_A2A_LIMITS.maxPatternLen} 字符`
    }
    if (CONTROL_CHAR_RE.test(pat)) {
      return `${fieldLabel}不能包含换行或控制字符`
    }
  }
  return null
}

/** 校验 AgBOM Agent 地址（可选；非空须为合法 http(s) URL（不含内嵌凭据）或单 / 开头相对路径，拒绝 // 协议相对地址） */
export function validateAgentUrl(raw?: string): string | null {
  const v = (raw ?? '').trim()
  if (!v) return null
  if (v.length > API_A2A_LIMITS.maxAgentUrlLen) {
    return `Agent 地址不能超过 ${API_A2A_LIMITS.maxAgentUrlLen} 字符`
  }
  if (CONTROL_CHAR_RE.test(v) || /\s/.test(v)) {
    return 'Agent 地址不得包含空白或控制字符'
  }
  if (v.startsWith('/') && !v.startsWith('//')) {
    return null
  }
  try {
    const parsed = new URL(v)
    if (
      (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
      parsed.hostname &&
      !parsed.username &&
      !parsed.password
    ) {
      return null
    }
  } catch {
    // fallthrough
  }
  return 'Agent 地址须为合法 http(s) URL（不含内嵌凭据）或单 / 开头的相对路径'
}

/** 后端字段级校验错误路径 → 表单字段路径 */
export function mapA2aFieldErrorPath(
  field: string,
): (string | number)[] | null {
  const trimmed = field.trim()
  switch (trimmed) {
    case 'mode':
    case 'card_discovery_enabled':
    case 'a2a_path_prefixes':
    case 'allowed_caller_agents':
    case 'max_delegation_depth':
    case 'enforce_scope_attenuation':
    case 'loop_window_seconds':
    case 'max_calls_per_task_window':
    case 'lethal_trifecta_enabled':
    case 'confidential_read_patterns':
    case 'external_egress_patterns':
    case 'reason':
    case 'application_id':
    case 'agent_name':
    case 'agent_url':
    case 'agent_version':
    case 'status':
    case 'description':
    case 'skills':
    case 'allowed_skills':
    case 'auth_schemes':
      return [trimmed]
    default:
      break
  }

  const indexed =
    /^(a2a_path_prefixes|allowed_caller_agents|confidential_read_patterns|external_egress_patterns|skills|allowed_skills|auth_schemes)\[\d+\]$/.exec(
      trimmed,
    )
  if (indexed?.[1]) {
    return [indexed[1]]
  }
  return null
}
