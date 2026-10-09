import type { StrongFlowStep, StrongFlowSuccessRule } from '../api/strongFlow'

/* ==================== NG-FLOW 强流程：词表与纯函数（docs/nextgen/NG-FLOW-strong-flow.md） ==================== */

/** §9.4 红线文案（INDETERMINATE 实例固定警示条；逐字不美化） */
export const UNKNOWN_NOT_CONFIRMED_MESSAGE = '未知，不显示安全通过'

/** UNKNOWN 恒不阻断（D6 红线：任何形态不把 UNKNOWN 映射为 403） */
export const UNKNOWN_NEVER_BLOCKS_FLOW = 'UNKNOWN 恒不阻断'

/** 定义状态词表（DRAFT/ACTIVE/RETIRED；RETIRED 单向终态） */
export const STRONG_FLOW_STATUS_META: Record<
  string,
  { color: string; label: string }
> = {
  DRAFT: { color: 'gold', label: '草稿' },
  ACTIVE: { color: 'green', label: '已激活' },
  RETIRED: { color: 'default', label: '已停用' },
}

/** 定义模式词表（缺省 OBSERVE——NG-T-C01 零变化） */
export const STRONG_FLOW_MODE_META: Record<
  string,
  { color: string; label: string }
> = {
  OBSERVE: { color: 'default', label: '观测（OBSERVE）' },
  PROTECT: { color: 'red', label: '实断（PROTECT）' },
}

/** 步骤可重试语义词表（异常策略） */
export const RETRY_SEMANTICS_META: Record<
  string,
  { label: string; hint: string }
> = {
  IDEMPOTENT: { label: '幂等可重试', hint: '同键同摘要重试幂等返回既有结果' },
  NOT_RETRYABLE: { label: '不可重试', hint: '重走已完成步骤按违规处置' },
  REQUIRES_REVIEW: { label: '需人工复核', hint: '重试前须经管理面对账确认' },
}

/** 实例五态词表（§1.2 冻结；INDETERMINATE=未知待对账，不显示安全通过） */
export const INSTANCE_STATUS_META: Record<
  string,
  { color: string; label: string }
> = {
  ACTIVE: { color: 'processing', label: '进行中' },
  CONFIRMED: { color: 'green', label: '已确认完成' },
  INDETERMINATE: { color: 'orange', label: '未知待对账' },
  CANCELLED: { color: 'default', label: '已取消' },
  FAILED: { color: 'red', label: '明确业务失败' },
}

/** 恢复三 action 词表（§1.5/D5；CONFIRM_NOT_EXECUTED→FAILED 为明确证据进终态） */
export const RESOLVE_ACTION_META: Record<
  string,
  { label: string; hint: string }
> = {
  CONFIRM_SUCCEEDED: {
    label: '确认业务已执行',
    hint: '实例推进为已确认完成（CONFIRMED 终态）',
  },
  CONFIRM_NOT_EXECUTED: {
    label: '确认业务未执行',
    hint: '实例推进为明确业务失败（FAILED 终态）',
  },
  KEEP_UNKNOWN: {
    label: '保持未知',
    hint: '不推进状态，仅留对账审计与 RESOLVE 事件（未知不显示安全通过）',
  },
}

/** 步骤事件结果词表 */
export const STEP_EVENT_RESULT_META: Record<
  string,
  { color: string; label: string }
> = {
  OK: { color: 'green', label: 'OK' },
  CONFLICT: { color: 'orange', label: '冲突' },
  REJECTED: { color: 'red', label: '拒绝' },
  UNKNOWN: { color: 'gold', label: 'UNKNOWN' },
}

/** 实例状态机允许转换说明（§1.2 五态 + §1.5 管理对账推进；固定文案不美化） */
export const INSTANCE_TRANSITIONS_NOTE =
  '允许转换：进行中（ACTIVE）→ 已确认完成 / 未知待对账 / 已取消 / 明确业务失败；未知待对账（INDETERMINATE）经管理对账 → 已确认完成（确认已执行）/ 明确业务失败（确认未执行）/ 保持未知不推进；已确认完成 / 已取消 / 明确业务失败为终态，不可再转换（终态拒绝重复恢复）。'

/** 终态判定（CONFIRMED/CANCELLED/FAILED 已定案） */
export function isTerminalInstance(status?: string): boolean {
  return status === 'CONFIRMED' || status === 'CANCELLED' || status === 'FAILED'
}

/** 恢复操作可用判定（仅 ACTIVE/INDETERMINATE 非终态可操作） */
export function canResolveInstance(status?: string): boolean {
  return status === 'ACTIVE' || status === 'INDETERMINATE'
}

/** 实例键截断展示（sfref: 前缀域隔离 HMAC，长键头尾保留） */
export function shortInstanceKey(value?: string | null): string {
  if (!value) return '-'
  return value.length > 24 ? `${value.slice(0, 14)}…${value.slice(-8)}` : value
}

/** 成功判定式可读化（三形态可组合与；无配置如实显示「未配置」——该步骤恒 UNKNOWN） */
export function successRuleText(rule?: StrongFlowSuccessRule | null): string {
  if (!rule) return '未配置（该步骤恒 UNKNOWN）'
  const parts: string[] = []
  if (rule.status_codes && rule.status_codes.length > 0) {
    parts.push(`状态码 ∈ [${rule.status_codes.join(', ')}]`)
  }
  if (rule.body_jsonpath_equals) {
    const v = rule.body_jsonpath_equals.value
    parts.push(
      `${rule.body_jsonpath_equals.path} == ${typeof v === 'string' ? `"${v}"` : JSON.stringify(v)}`,
    )
  }
  if (rule.graphql_errors_empty) {
    parts.push('GraphQL errors 为空')
  }
  return parts.length > 0 ? parts.join(' 且 ') : '未配置（该步骤恒 UNKNOWN）'
}

/**
 * 步骤集结构校验（与 server/internal/strongflow validate.go 同口径镜像——返回首个违规，空串=合法）。
 * 词表/夹紧由字段级规则承载；本函数承载结构规则：step_key 唯一、sequence 唯一、
 * 首步唯一最小、parallel_group 至少两步且 sequence 相邻、success_rule 至少一形态。
 */
export function validateStrongFlowSteps(steps: StrongFlowStep[]): string {
  if (steps.length === 0) return '定义至少包含一个步骤'
  if (steps.length > 64) return '步骤数超上限 64'
  const seenKey = new Set<string>()
  const seenSeq = new Set<number>()
  let minSeq = 0
  let minCount = 0
  const parallelSeqs = new Map<string, number[]>()
  for (let i = 0; i < steps.length; i++) {
    const st = steps[i]
    const key = (st.step_key ?? '').trim()
    if (!key) return `steps[${i}].step_key 必填`
    if (seenKey.has(key)) return `step_key "${key}" 重复（定义内唯一）`
    seenKey.add(key)
    if (!Number.isInteger(st.sequence) || st.sequence < 1)
      return `steps[${i}].sequence 必须 ≥1`
    if (seenSeq.has(st.sequence))
      return `sequence ${st.sequence} 重复（定义内唯一——严格递增即首步唯一最小的承载）`
    seenSeq.add(st.sequence)
    if (minCount === 0 || st.sequence < minSeq) {
      minSeq = st.sequence
      minCount = 1
    } else if (st.sequence === minSeq) {
      minCount++
    }
    if (!(st.endpoint_key ?? '').trim()) return `steps[${i}].endpoint_key 必填`
    const ruleMsg = validateStrongFlowSuccessRule(st.success_rule)
    if (ruleMsg) return `steps[${i}].success_rule：${ruleMsg}`
    if (st.timeout_seconds < 15 || st.timeout_seconds > 600)
      return `steps[${i}].timeout_seconds 词表外（15~600；词表外拒收不夹紧猜义）`
    if (st.lease_seconds < 15 || st.lease_seconds > 300)
      return `steps[${i}].lease_seconds 词表外（15~300；词表外拒收不夹紧猜义）`
    const g = (st.parallel_group ?? '').trim()
    if (g) {
      const list = parallelSeqs.get(g) ?? []
      list.push(st.sequence)
      parallelSeqs.set(g, list)
    }
  }
  if (minCount !== 1)
    return `首步须唯一（sequence 最小值恰一步；当前最小值 ${minSeq} 出现 ${minCount} 次）`
  for (const [g, seqs] of parallelSeqs) {
    if (seqs.length < 2)
      return `parallel_group "${g}" 仅一步（并行组至少两步；单步请置空串行）`
    const sorted = [...seqs].sort((a, b) => a - b)
    for (let i = 1; i < sorted.length; i++) {
      if (sorted[i] - sorted[i - 1] !== 1)
        return `parallel_group "${g}" 步骤 sequence 不相邻（同组须连续区间）`
    }
  }
  return ''
}

/** 成功判定式校验（镜像 server validateSuccessRule；空串=合法） */
export function validateStrongFlowSuccessRule(
  rule?: StrongFlowSuccessRule | null,
): string {
  if (!rule)
    return '必填（无成功判定式的步骤恒 UNKNOWN——判定式必须显式配置，§9.3）'
  let has = false
  if (rule.status_codes && rule.status_codes.length > 0) {
    has = true
    for (const c of rule.status_codes) {
      if (!Number.isInteger(c) || c < 100 || c > 599)
        return 'status_codes 元素须为合法 HTTP 状态码（100~599）'
    }
  }
  if (rule.body_jsonpath_equals) {
    has = true
    if (
      !/^\$\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(
        rule.body_jsonpath_equals.path ?? '',
      )
    ) {
      return 'body_jsonpath_equals.path 形态非法（仅点路径子集 $.a.b；非法形态拒收）'
    }
    if (
      rule.body_jsonpath_equals.value === undefined ||
      rule.body_jsonpath_equals.value === null ||
      rule.body_jsonpath_equals.value === ''
    ) {
      return 'body_jsonpath_equals.value 必填（等值目标）'
    }
  }
  if (rule.graphql_errors_empty) has = true
  if (!has)
    return '至少配置一种成功判定形态（status_codes / body_jsonpath_equals / graphql_errors_empty）'
  return ''
}

/** 实例引用来源形态校验（query:<非空名> / path:<非负段序>，与 server 同纪律） */
export function validInstanceKeyParam(v: string): boolean {
  const value = (v ?? '').trim()
  if (!value || value.length > 128) return false
  if (value.startsWith('query:')) {
    const name = value.slice('query:'.length).trim()
    return name !== '' && !/[ \t\r\n]/.test(name)
  }
  if (value.startsWith('path:')) {
    const pos = value.slice('path:'.length).trim()
    return pos !== '' && /^\d+$/.test(pos)
  }
  return false
}

/** 恢复 409 归类（版本冲突 / 实例已终态 / 其他——精确提示不混用） */
export function classifyResolveConflict(
  message: string,
): 'version' | 'terminal' | 'other' {
  const m = message.toLowerCase()
  if (m.includes('terminal') || message.includes('终态')) return 'terminal'
  if (
    m.includes('version conflict') ||
    message.includes('乐观锁') ||
    message.includes('版本冲突')
  )
    return 'version'
  return 'other'
}
