import type { AiAnalyzeBody } from '../../../api/ai'

/** What-If 模拟场景（§19.1 八种，与 server analyze_context.go 白名单一致） */
export type WhatIfScenario =
  | 'disable_rule'
  | 'enable_rule'
  | 'anomaly_threshold'
  | 'pl_switch'
  | 'add_exception'
  | 'remove_exception'
  | 'cc_threshold'
  | 'block_duration'

/** What-If 表单值（各场景按需取用字段） */
export interface WhatIfFormValues {
  scenario: WhatIfScenario
  rule_id?: number
  cc_threshold?: number
  block_duration_seconds?: number
  anomaly_threshold?: number
  paranoia_level?: number
  exception_id?: string
  time_range?: string
}

/** What-If 场景选项（antd Select options） */
export const WHAT_IF_SCENARIO_OPTIONS: { value: WhatIfScenario; label: string }[] = [
  { value: 'disable_rule', label: '关闭规则' },
  { value: 'enable_rule', label: '启用规则' },
  { value: 'anomaly_threshold', label: '修改异常阈值' },
  { value: 'pl_switch', label: '切换 CRS 执行等级' },
  { value: 'add_exception', label: '新增例外' },
  { value: 'remove_exception', label: '删除例外' },
  { value: 'cc_threshold', label: '修改 CC 阈值' },
  { value: 'block_duration', label: '调整封禁时长' },
]

/** CRS 执行等级选项（pl_switch，1-4） */
export const WHAT_IF_PARANOIA_LEVEL_OPTIONS = [
  { value: 1, label: 'PL1（默认，误报最少）' },
  { value: 2, label: 'PL2（更严格）' },
  { value: 3, label: 'PL3（严格，误报增多）' },
  { value: 4, label: 'PL4（最严格，仅限高安全场景）' },
]

/** What-If 估算统计区间选项（与后端 time_range 白名单一致） */
export const WHAT_IF_TIME_RANGE_OPTIONS = [
  { value: '24h', label: '近 24 小时' },
  { value: '7d', label: '近 7 天' },
  { value: '30d', label: '近 30 天' },
]

/** 需要选择规则的场景（rule_id 必填且 >0） */
const RULE_SCENARIOS: WhatIfScenario[] = ['disable_rule', 'enable_rule', 'add_exception']

/** 支持历史数据区间（time_range）的场景（disable_rule 为事件回放口径，不支持） */
export function whatIfSupportsTimeRange(scenario: WhatIfScenario): boolean {
  return scenario !== 'disable_rule'
}

/**
 * 组装 What-If 提交载荷（防御性校验，越界/缺失抛中文错误；
 * 表单层仍由 antd rules 做必填与范围校验，二者口径一致）。
 */
export function buildWhatIfBody(v: WhatIfFormValues): AiAnalyzeBody {
  const body: AiAnalyzeBody = { scenario: v.scenario }
  if (RULE_SCENARIOS.includes(v.scenario)) {
    if (!v.rule_id || v.rule_id <= 0 || !Number.isInteger(v.rule_id)) {
      throw new Error('请输入有效的规则 ID（正整数）')
    }
    body.rule_id = v.rule_id
  }
  switch (v.scenario) {
    case 'anomaly_threshold':
      if (
        !v.anomaly_threshold ||
        !Number.isInteger(v.anomaly_threshold) ||
        v.anomaly_threshold < 1 ||
        v.anomaly_threshold > 10000
      ) {
        throw new Error('请输入有效的异常阈值（1-10000 的整数）')
      }
      body.anomaly_threshold = v.anomaly_threshold
      break
    case 'pl_switch':
      if (!v.paranoia_level || v.paranoia_level < 1 || v.paranoia_level > 4) {
        throw new Error('请选择 CRS 执行等级（1-4）')
      }
      body.paranoia_level = v.paranoia_level
      break
    case 'remove_exception':
      if (!v.exception_id || !v.exception_id.trim()) {
        throw new Error('请选择要模拟删除的例外')
      }
      body.exception_id = v.exception_id.trim()
      break
    case 'cc_threshold':
      if (
        !v.cc_threshold ||
        !Number.isInteger(v.cc_threshold) ||
        v.cc_threshold < 1 ||
        v.cc_threshold > 1000000
      ) {
        throw new Error('请输入有效的 CC 阈值（1-1000000 的整数）')
      }
      body.cc_threshold = v.cc_threshold
      break
    case 'block_duration':
      if (
        !v.block_duration_seconds ||
        !Number.isInteger(v.block_duration_seconds) ||
        v.block_duration_seconds < 60 ||
        v.block_duration_seconds > 2592000
      ) {
        throw new Error('请输入有效的封禁时长（60-2592000 秒的整数）')
      }
      body.block_duration_seconds = v.block_duration_seconds
      break
    default:
      break
  }
  if (whatIfSupportsTimeRange(v.scenario) && v.time_range) {
    body.time_range = v.time_range
  }
  return body
}
