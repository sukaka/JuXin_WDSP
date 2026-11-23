import { ApiError } from '../../api/client'
import type { L7RuleBody } from '../../api/l7Rules'
import {
  L7_DEFAULT_BLOCK_STATUS,
  L7_DEFAULT_CUSTOM_STATUS,
  L7_MAX_BODY_BYTES,
  L7_MAX_CONDITIONS,
  actionConfigToFormValues,
  buildActionConfig,
  conditionToRow,
  rowToCondition,
  utf8ByteLength,
  validateConditionRow,
  type L7ActionFormValues,
  type L7ConditionFormRow,
} from '../../utils/l7rules'
import type { L7RuleItem } from '../../types'

/** L7 规则编辑抽屉的表单值（基础信息 + 条件行 + 动作字段） */
export interface L7RuleFormValues extends L7ActionFormValues {
  name: string
  priority: number
  enabled: boolean
  conditions: L7ConditionFormRow[]
}

/** 规则记录 → 表单值（编辑/复制回显） */
export function ruleToFormValues(rule: L7RuleItem): L7RuleFormValues {
  return {
    name: rule.name,
    priority: rule.priority,
    enabled: rule.enabled,
    conditions: (rule.conditions ?? []).map(conditionToRow),
    ...actionConfigToFormValues(rule.action, rule.action_config),
  }
}

/** 表单值 → 契约请求体（提交前逐行校验，非法时抛 ApiError） */
export function formValuesToBody(values: L7RuleFormValues): L7RuleBody {
  const rows = values.conditions ?? []
  if (rows.length === 0) {
    throw new ApiError('至少需要 1 条匹配条件', 'INVALID', 0)
  }
  if (rows.length > L7_MAX_CONDITIONS) {
    throw new ApiError(`单条规则最多 ${L7_MAX_CONDITIONS} 个条件`, 'INVALID', 0)
  }
  for (let i = 0; i < rows.length; i++) {
    const err = validateConditionRow(rows[i])
    if (err) throw new ApiError(`第 ${i + 1} 个条件：${err}`, 'INVALID', 0)
  }
  if (values.action === 'block') {
    const status = values.block_status ?? L7_DEFAULT_BLOCK_STATUS
    if (!Number.isInteger(status) || status < 400 || status > 599) {
      throw new ApiError('阻止状态码必须在 400~599 之间', 'INVALID', 0)
    }
  }
  if (values.action === 'custom_page') {
    const status = values.custom_status ?? L7_DEFAULT_CUSTOM_STATUS
    if (!Number.isInteger(status) || status < 200 || status > 599) {
      throw new ApiError('自定义页面状态码必须在 200~599 之间', 'INVALID', 0)
    }
    const body = values.custom_body ?? ''
    if (body === '') {
      throw new ApiError('自定义页面内容不能为空', 'INVALID', 0)
    }
    if (utf8ByteLength(body) > L7_MAX_BODY_BYTES) {
      throw new ApiError('自定义页面内容超过 64KB 上限', 'INVALID', 0)
    }
  }
  return {
    name: values.name,
    priority: values.priority,
    enabled: values.enabled,
    conditions: rows.map(rowToCondition),
    action: values.action,
    action_config: buildActionConfig(values),
  }
}
