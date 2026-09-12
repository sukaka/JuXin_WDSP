import dayjs from 'dayjs'
import type { RateLimitPolicyBody } from '../../api/rateLimitPolicies'
import type { RateLimitPolicyItem } from '../../types'
import {
  RATE_LIMIT_ACTION_META,
  RATE_LIMIT_ALGORITHM_META,
  RATE_LIMIT_DIMENSION_META,
  RATE_LIMIT_SCOPE_META,
  RATE_LIMIT_URI_MATCH_META,
} from '../../utils/stage5'

export interface PolicyFormValues {
  name: string
  description?: string
  scope_type: string
  application_id?: string
  uri_match_type: string
  uri_pattern?: string
  dimension: string
  algorithm: string
  requests_limit: number
  window_seconds: number
  burst_capacity?: number
  action: string
  block_duration_seconds?: number
  observe_only?: boolean
  priority: number
  effective_range?: [dayjs.Dayjs | null, dayjs.Dayjs | null]
}

export const optionsOf = (meta: Record<string, { label: string }>) =>
  Object.entries(meta).map(([value, m]) => ({ value, label: m.label }))

export interface WizardStep {
  title: string
  description: string
  /** 进入下一步前需要校验的表单字段（末步为空，提交时整体校验） */
  fields: (keyof PolicyFormValues)[]
}

export const WIZARD_STEPS: WizardStep[] = [
  {
    title: '基本范围',
    description: '名称、应用与路径',
    fields: [
      'name',
      'description',
      'priority',
      'effective_range',
      'scope_type',
      'application_id',
      'uri_match_type',
      'uri_pattern',
    ],
  },
  {
    title: '阈值与窗口',
    description: '统计维度与限速参数',
    fields: ['dimension', 'algorithm', 'requests_limit', 'window_seconds', 'burst_capacity'],
  },
  {
    title: '处置动作',
    description: '超阈值动作与封禁时长',
    fields: ['action', 'block_duration_seconds'],
  },
  { title: '确认摘要', description: '核对配置后提交', fields: [] },
]

/** 编辑态回填：策略记录 → 向导表单值 */
export function policyToFormValues(record: RateLimitPolicyItem): PolicyFormValues {
  return {
    name: record.name,
    description: record.description || undefined,
    scope_type: record.scope_type,
    application_id: record.application_id ?? undefined,
    uri_match_type: record.uri_match_type,
    uri_pattern: record.uri_pattern || undefined,
    dimension: record.dimension,
    algorithm: record.algorithm,
    requests_limit: record.requests_limit,
    window_seconds: record.window_seconds,
    burst_capacity: record.burst_capacity,
    action: record.action,
    block_duration_seconds: record.block_duration_seconds || undefined,
    observe_only: record.observe_only,
    priority: record.priority,
    effective_range: [
      record.effective_from ? dayjs(record.effective_from) : null,
      record.effective_until ? dayjs(record.effective_until) : null,
    ],
  }
}

/** 向导表单值 → 创建/更新请求体（按范围/匹配/动作裁剪冗余字段） */
export function buildPolicyBody(values: PolicyFormValues): RateLimitPolicyBody {
  const [from, until] = values.effective_range ?? [null, null]
  return {
    name: values.name,
    description: values.description ?? '',
    scope_type: values.scope_type,
    application_id: values.scope_type === 'GLOBAL' ? null : values.application_id,
    uri_match_type: values.uri_match_type,
    uri_pattern: values.uri_match_type === 'ALL' ? '' : (values.uri_pattern ?? ''),
    dimension: values.dimension,
    algorithm: values.algorithm,
    requests_limit: values.requests_limit,
    window_seconds: values.window_seconds,
    burst_capacity: values.burst_capacity ?? 0,
    action: values.action,
    block_duration_seconds:
      values.action === 'TEMP_BLOCK' ? (values.block_duration_seconds ?? 0) : 0,
    observe_only: values.observe_only ?? false,
    priority: values.priority,
    effective_from: from ? from.toISOString() : null,
    effective_until: until ? until.toISOString() : null,
  }
}

export interface SummaryItem {
  label: string
  value: string
}

/** 末步确认摘要数据组装（appLabel 用于把 application_id 转成可读名称） */
export function buildSummaryItems(
  values: PolicyFormValues,
  appLabel?: (id: string) => string | undefined,
): SummaryItem[] {
  const [from, until] = values.effective_range ?? [null, null]
  const scopeLabel = RATE_LIMIT_SCOPE_META[values.scope_type]?.label ?? values.scope_type
  const scopeValue =
    values.scope_type === 'GLOBAL'
      ? scopeLabel
      : `${scopeLabel}：${(values.application_id && appLabel?.(values.application_id)) || values.application_id || '-'}`

  const matchLabel =
    RATE_LIMIT_URI_MATCH_META[values.uri_match_type]?.label ?? values.uri_match_type
  const uriValue =
    values.uri_match_type === 'ALL'
      ? matchLabel
      : `${matchLabel}：${values.uri_pattern ?? ''}`

  const burst = values.burst_capacity && values.burst_capacity > 0
    ? values.burst_capacity
    : values.requests_limit

  const actionLabel = RATE_LIMIT_ACTION_META[values.action]?.label ?? values.action
  const actionValue =
    values.action === 'TEMP_BLOCK'
      ? `${actionLabel}（${values.block_duration_seconds ?? 0} 秒）`
      : actionLabel

  return [
    { label: '策略名称', value: values.name },
    { label: '描述', value: values.description || '—' },
    { label: '优先级', value: String(values.priority) },
    { label: '仅观察', value: values.observe_only ? '是（命中只记录不阻断）' : '否' },
    {
      label: '生效时间',
      value:
        from || until
          ? `${from ? from.format('YYYY-MM-DD HH:mm') : '立即'} 至 ${until ? until.format('YYYY-MM-DD HH:mm') : '长期'}`
          : '长期生效',
    },
    { label: '作用范围', value: scopeValue },
    { label: '路径匹配', value: uriValue },
    {
      label: '统计维度',
      value: RATE_LIMIT_DIMENSION_META[values.dimension]?.label ?? values.dimension,
    },
    {
      label: '限速算法',
      value: RATE_LIMIT_ALGORITHM_META[values.algorithm]?.label ?? values.algorithm,
    },
    {
      label: '限速参数',
      value: `${values.requests_limit} 次 / ${values.window_seconds} 秒，突发容量 ${burst}`,
    },
    { label: '超阈值动作', value: actionValue },
  ]
}
