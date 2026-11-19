import type { RiskPolicy, RiskPolicyBody } from '../../api/riskPolicy'
import { COMMON_DETAIL_FIELD_LABELS } from '../../utils/i18nLabels'
import { SIGNAL_META } from '../../utils/identitySecurity'

const RISK_POLICY_FIELD_LABELS: Record<string, string> = {
  block_threshold: '阻断阈值',
  rate_limit_threshold: '限速阈值',
  challenge_threshold: '挑战阈值',
  rate_limit_rps: '限速速率',
  signal_window_seconds: '统计窗口',
  shared_device_account_limit: '同设备账号观察阈值',
  'risk_levels.medium': '中风险下限',
  'risk_levels.high': '高风险下限',
  'risk_levels.critical': '严重风险下限',
  risk_levels: '风险等级划分',
  scores: '信号分值',
}

/** 将风险策略校验错误字段名转为中文展示（未知字段回退原值） */
export function formatRiskPolicyField(field?: string): string {
  if (!field) return ''
  if (field.startsWith('scores.')) {
    const key = field.slice('scores.'.length)
    return `信号分值（${SIGNAL_META[key]?.label ?? key}）`
  }
  return RISK_POLICY_FIELD_LABELS[field] ?? COMMON_DETAIL_FIELD_LABELS[field] ?? field
}

export interface ScoreEntry {
  key?: string
  value?: number
}

export interface PolicyFormValues {
  enabled: boolean
  mode: string
  block_threshold: number
  rate_limit_threshold: number
  challenge_threshold: number
  rate_limit_rps: number
  signal_window_seconds: number
  shared_device_account_limit?: number
  risk_levels: { medium: number; high: number; critical: number }
  score_entries?: ScoreEntry[]
}

export function policyToFormValues(policy: RiskPolicy): PolicyFormValues {
  return {
    enabled: policy.enabled,
    mode: policy.mode,
    block_threshold: policy.block_threshold,
    rate_limit_threshold: policy.rate_limit_threshold,
    challenge_threshold: policy.challenge_threshold ?? 0,
    rate_limit_rps: policy.rate_limit_rps,
    signal_window_seconds: policy.signal_window_seconds,
    shared_device_account_limit: policy.shared_device_account_limit ?? 0,
    risk_levels: { ...policy.risk_levels },
    score_entries: Object.entries(policy.scores).map(([key, value]) => ({
      key,
      value,
    })),
  }
}

export function formValuesToBody(
  values: PolicyFormValues,
  scope: string,
  version: number,
): RiskPolicyBody {
  const scores: Record<string, number> = {}
  for (const entry of values.score_entries ?? []) {
    if (entry.key && entry.value !== undefined && entry.value !== null) {
      scores[entry.key] = entry.value
    }
  }
  const body: RiskPolicyBody = {
    scope,
    enabled: values.enabled ?? false,
    mode: values.mode ?? 'OBSERVE',
    version,
    block_threshold: values.block_threshold,
    rate_limit_threshold: values.rate_limit_threshold,
    challenge_threshold: values.challenge_threshold,
    rate_limit_rps: values.rate_limit_rps,
    signal_window_seconds: values.signal_window_seconds,
    scores,
    risk_levels: values.risk_levels,
  }
  if (scope === 'APPLICATION') {
    body.shared_device_account_limit = values.shared_device_account_limit ?? 0
  }
  return body
}

export function duplicateScoreKeys(
  entries: ScoreEntry[] | undefined,
): string[] {
  const counts = new Map<string, number>()
  for (const entry of entries ?? []) {
    if (entry.key) counts.set(entry.key, (counts.get(entry.key) ?? 0) + 1)
  }
  return [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([key]) => key)
    .sort()
}
