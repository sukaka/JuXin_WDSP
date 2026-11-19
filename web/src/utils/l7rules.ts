/* ==================== L7 访问控制 展示元数据 / 条件序列化 / 表单校验（纯函数，可单测） ==================== */

import type {
  L7ConditionOp,
  L7ConditionType,
  L7RuleAction,
  L7RuleActionConfig,
  L7RuleCondition,
} from '../types'
import { validateIPOrCIDR } from './stage5'

/** 条件类型中文标签 */
export const L7_CONDITION_TYPE_META: Record<L7ConditionType, { label: string }> = {
  uri: { label: '访问URI' },
  method: { label: '请求方法' },
  header: { label: '请求头' },
  cookie: { label: 'Cookie' },
  query: { label: 'Query参数' },
  client_ip: { label: '来源IP' },
  request_body: { label: '请求体' },
  response_header: { label: '返回头' },
  response_body: { label: '返回体' },
}

/** 条件运算符中文标签 */
export const L7_CONDITION_OP_META: Record<string, { label: string }> = {
  eq: { label: '等于' },
  ne: { label: '不等于' },
  prefix: { label: '前缀匹配' },
  contains: { label: '包含' },
  regex: { label: '正则匹配' },
  exists: { label: '存在' },
  not_exists: { label: '不存在' },
  in: { label: '属于' },
}

/** 规则动作中文标签与颜色 */
export const L7_RULE_ACTION_META: Record<string, { color: string; label: string }> = {
  block: { color: 'red', label: '阻止' },
  allow: { color: 'green', label: '允许' },
  redirect: { color: 'blue', label: '重定向' },
  custom_page: { color: 'purple', label: '自定义页面' },
}

/** 各条件类型可用的运算符（method/client_ip 走 values 数组，等价 in，不单独选运算符） */
export const L7_OPS_BY_TYPE: Record<L7ConditionType, L7ConditionOp[]> = {
  uri: ['eq', 'ne', 'prefix', 'contains', 'regex'],
  method: [],
  header: ['eq', 'ne', 'prefix', 'contains', 'regex', 'exists', 'not_exists'],
  cookie: ['eq', 'ne', 'prefix', 'contains', 'regex', 'exists', 'not_exists'],
  query: ['eq', 'ne', 'prefix', 'contains', 'regex', 'exists', 'not_exists'],
  client_ip: [],
  request_body: ['contains', 'eq', 'ne', 'prefix', 'regex'],
  response_header: ['eq', 'ne', 'prefix', 'contains', 'regex', 'exists', 'not_exists'],
  response_body: ['contains', 'eq', 'ne', 'prefix', 'regex'],
}

/** 需要「名称」输入的条件类型 */
export const L7_NAMED_TYPES: readonly L7ConditionType[] = ['header', 'cookie', 'query', 'response_header']

/** 使用多值数组（values）的条件类型 */
export const L7_MULTI_VALUE_TYPES: readonly L7ConditionType[] = ['method', 'client_ip']

/** 常见请求方法预设（多选下拉，可自由输入） */
export const L7_METHOD_PRESETS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

/** 单规则条件数量上限（与服务端校验一致） */
export const L7_MAX_CONDITIONS = 10
/** 自定义页面内容上限 64KB（UTF-8 字节） */
export const L7_MAX_BODY_BYTES = 64 * 1024
/** 正则匹配值长度上限（与服务端校验一致） */
export const L7_MAX_REGEX_LENGTH = 512

export const L7_DEFAULT_BLOCK_STATUS = 403
export const L7_DEFAULT_REDIRECT_STATUS = 302
export const L7_DEFAULT_CUSTOM_STATUS = 403
export const L7_DEFAULT_CONTENT_TYPE = 'text/html; charset=utf-8'

/** 条件构建器中的行（表单态，与 L7RuleCondition 互相转换） */
export interface L7ConditionFormRow {
  type: L7ConditionType
  name?: string
  op?: L7ConditionOp
  value?: string
  values?: string[]
}

/** 表单动作字段（按动作取对应组） */
export interface L7ActionFormValues {
  action: L7RuleAction
  block_status?: number | null
  block_message?: string
  redirect_status?: number
  redirect_url?: string
  custom_status?: number | null
  custom_content_type?: string
  custom_body?: string
}

/**
 * 条件行 → 契约 JSON：
 * - method/client_ip 仅保留 { type, values }（等价 op=in）；
 * - header/cookie/query 携带 name；exists/not_exists 不带 value。
 */
export function rowToCondition(row: L7ConditionFormRow): L7RuleCondition {
  const type = row.type
  if (L7_MULTI_VALUE_TYPES.includes(type)) {
    return { type, values: row.values ?? [] }
  }
  const cond: L7RuleCondition = { type }
  if (L7_NAMED_TYPES.includes(type)) cond.name = (row.name ?? '').trim()
  const op = row.op ?? 'eq'
  cond.op = op
  if (op !== 'exists' && op !== 'not_exists') cond.value = row.value ?? ''
  return cond
}

/** 契约 JSON → 条件行（编辑回显；未收录的 op/type 原样保留，由表单校验拦截） */
export function conditionToRow(cond: L7RuleCondition): L7ConditionFormRow {
  return {
    type: cond.type,
    name: cond.name,
    op: cond.op,
    value: cond.value,
    values: cond.values ? [...cond.values] : undefined,
  }
}

/** 表单动作字段 → 契约 action_config（全键输出，未用字段取空/默认值） */
export function buildActionConfig(values: L7ActionFormValues): L7RuleActionConfig {
  const cfg: L7RuleActionConfig = {
    status: L7_DEFAULT_BLOCK_STATUS,
    message: '',
    redirect_url: '',
    redirect_status: L7_DEFAULT_REDIRECT_STATUS,
    content_type: L7_DEFAULT_CONTENT_TYPE,
    body: '',
  }
  switch (values.action) {
    case 'block':
      cfg.status = values.block_status ?? L7_DEFAULT_BLOCK_STATUS
      cfg.message = values.block_message ?? ''
      break
    case 'redirect':
      cfg.redirect_url = (values.redirect_url ?? '').trim()
      cfg.redirect_status = values.redirect_status ?? L7_DEFAULT_REDIRECT_STATUS
      break
    case 'custom_page':
      cfg.status = values.custom_status ?? L7_DEFAULT_CUSTOM_STATUS
      cfg.content_type = (values.custom_content_type ?? '').trim() || L7_DEFAULT_CONTENT_TYPE
      cfg.body = values.custom_body ?? ''
      break
    case 'allow':
      break
  }
  return cfg
}

/** 契约 action_config → 表单动作字段（编辑回显） */
export function actionConfigToFormValues(
  action: L7RuleAction,
  cfg: L7RuleActionConfig | undefined,
): L7ActionFormValues {
  const c = cfg ?? {}
  return {
    action,
    block_status: action === 'block' ? (c.status ?? L7_DEFAULT_BLOCK_STATUS) : L7_DEFAULT_BLOCK_STATUS,
    block_message: action === 'block' ? (c.message ?? '') : '',
    redirect_status: action === 'redirect' ? (c.redirect_status ?? L7_DEFAULT_REDIRECT_STATUS) : L7_DEFAULT_REDIRECT_STATUS,
    redirect_url: action === 'redirect' ? (c.redirect_url ?? '') : '',
    custom_status: action === 'custom_page' ? (c.status ?? L7_DEFAULT_CUSTOM_STATUS) : L7_DEFAULT_CUSTOM_STATUS,
    custom_content_type:
      action === 'custom_page' ? (c.content_type ?? L7_DEFAULT_CONTENT_TYPE) : L7_DEFAULT_CONTENT_TYPE,
    custom_body: action === 'custom_page' ? (c.body ?? '') : '',
  }
}

/** 校验正则匹配值：可编译且长度 ≤ 512，返回 null 表示合法 */
export function validateL7Regex(pattern: string): string | null {
  if (pattern.length > L7_MAX_REGEX_LENGTH) {
    return `正则长度不能超过 ${L7_MAX_REGEX_LENGTH} 个字符`
  }
  try {
    new RegExp(pattern)
    return null
  } catch {
    return '正则表达式无法编译，请检查语法'
  }
}

/** 校验重定向 URL：仅允许 http/https，返回 null 表示合法 */
export function validateL7RedirectUrl(raw: string): string | null {
  const s = raw.trim()
  if (s === '') return '请输入重定向 URL'
  if (s.length > 2048) return 'URL 长度不能超过 2048 个字符'
  let u: URL
  try {
    u = new URL(s)
  } catch {
    return 'URL 格式非法，需为完整 URL（如 https://example.com/path）'
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    return '仅支持 http/https 协议的重定向 URL'
  }
  return null
}

/** 统计 UTF-8 字节数（自定义页面 64KB 上限按字节计） */
export function utf8ByteLength(s: string): number {
  return new TextEncoder().encode(s).length
}

/** 校验单行条件，返回 null 表示合法（表单提交前统一调用） */
export function validateConditionRow(row: L7ConditionFormRow): string | null {
  if (L7_MULTI_VALUE_TYPES.includes(row.type)) {
    const values = (row.values ?? []).map((v) => v.trim()).filter((v) => v !== '')
    if (values.length === 0) return '请至少填写一个取值'
    if (row.type === 'method') {
      const bad = values.find((m) => !/^[A-Z]{2,10}$/.test(m))
      if (bad) return `请求方法须为 2-10 位大写字母：${bad}`
    }
    if (row.type === 'client_ip') {
      for (const ip of values) {
        const err = validateIPOrCIDR(ip)
        if (err) return err
      }
    }
    return null
  }
  if (L7_NAMED_TYPES.includes(row.type) && (row.name ?? '').trim() === '') {
    return '请输入名称'
  }
  const op = row.op ?? 'eq'
  if (!L7_OPS_BY_TYPE[row.type].includes(op)) return '该运算符不适用于当前条件类型'
  if (op === 'exists' || op === 'not_exists') return null
  const value = row.value ?? ''
  if (value === '') return '请输入匹配值'
  if (row.type === 'uri' && (op === 'eq' || op === 'ne' || op === 'prefix') && !value.startsWith('/')) {
    return 'URI 须以 / 开头'
  }
  if (op === 'regex') return validateL7Regex(value)
  return null
}

/** 单条条件的中文摘要 */
export function summarizeCondition(cond: L7RuleCondition): string {
  const typeLabel = L7_CONDITION_TYPE_META[cond.type]?.label ?? cond.type
  if (L7_MULTI_VALUE_TYPES.includes(cond.type)) {
    return `${typeLabel} ∈ [${(cond.values ?? []).join(', ')}]`
  }
  const opLabel = cond.op ? (L7_CONDITION_OP_META[cond.op]?.label ?? cond.op) : ''
  const name = cond.name ? `${cond.name} ` : ''
  if (cond.op === 'exists' || cond.op === 'not_exists') {
    return `${typeLabel} ${name}${opLabel}`
  }
  return `${typeLabel} ${name}${opLabel} ${cond.value ?? ''}`
}

/** 条件列表摘要（多条件 AND；超过 max 条折叠计数） */
export function summarizeConditions(conds: L7RuleCondition[], max = 2): string {
  if (!conds || conds.length === 0) return '无条件（匹配全部请求）'
  const parts = conds.slice(0, max).map(summarizeCondition)
  const suffix = conds.length > max ? ` 等 ${conds.length} 个条件` : ''
  return parts.join(' 且 ') + suffix
}
