/**
 * 安全回归（WDSP P1-04 R4a）词表中文映射与可用性预判。
 * 配色对齐 utils/botPolicy 惯例；词表与 server/internal/regression
 * （types.go / gate.go / import.go）一一对应。
 * 未知枚举一律回退原值展示（StatusTag 兜底），不得吞掉或伪造语义。
 */

import type {
  SecurityRegressionPolicy,
  SecurityRegressionRun,
} from '../api/securityRegression'

/** 运行级别（级别序 SMOKE<FULL<RELEASE：低级别证据不支撑高级别发布） */
export const REG_LEVEL_META: Record<string, { color: string; label: string }> = {
  SMOKE: { color: 'default', label: '冒烟' },
  FULL: { color: 'blue', label: '全量' },
  RELEASE: { color: 'purple', label: '发布级' },
}

/** 服务端独立核验结论（唯一可采信状态） */
export const REG_VERIFY_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'gold', label: '待核验' },
  PASSED: { color: 'green', label: '核验通过' },
  FAILED: { color: 'red', label: '核验失败' },
}

/** 验证服务声明状态（仅登记，不采信——REG-016） */
export const REG_DECLARED_META: Record<string, { color: string; label: string }> = {
  PASS: { color: 'green', label: '声明通过' },
  FAIL: { color: 'red', label: '声明失败' },
  SKIP: { color: 'default', label: '声明跳过' },
  BLOCKED: { color: 'orange', label: '声明阻塞' },
  NOT_RUN: { color: 'default', label: '声明未运行' },
}

/** 用例状态 */
export const REG_CASE_STATUS_META: Record<string, { color: string; label: string }> = {
  PASS: { color: 'green', label: '通过' },
  FAIL: { color: 'red', label: '失败' },
  SKIP: { color: 'default', label: '跳过' },
  BLOCKED: { color: 'orange', label: '阻塞' },
  NOT_RUN: { color: 'default', label: '未运行' },
}

/** 用例真值 */
export const REG_TRUTH_META: Record<string, { color: string; label: string }> = {
  BENIGN: { color: 'blue', label: '正常' },
  ATTACK: { color: 'red', label: '攻击' },
  UNKNOWN: { color: 'default', label: '未知' },
}

/** 强制级别（强制用例未全过阻断 ENFORCE 发布） */
export const REG_CRITICALITY_META: Record<string, { color: string; label: string }> = {
  MANDATORY: { color: 'volcano', label: '强制' },
  OPTIONAL: { color: 'default', label: '可选' },
}

/** 门禁模式（OFF 不检查 / OBSERVE 只记录 / ENFORCE 拒绝不合规发布） */
export const REG_GATE_MODE_META: Record<string, { color: string; label: string }> = {
  OFF: { color: 'default', label: '关闭（不检查）' },
  OBSERVE: { color: 'blue', label: '观察（只记录不阻断）' },
  ENFORCE: { color: 'green', label: '强制（不合规拒绝发布）' },
}

/** 发布失败码（publisher_gate.go；版本标 FAILED） */
export const REG_GATE_FAILURE_CODES = [
  'REGRESSION_GATE_REJECTED',
  'REGRESSION_GATE_UNAVAILABLE',
] as const

export function isRegressionGateFailure(code?: string | null): boolean {
  return !!code && (REG_GATE_FAILURE_CODES as readonly string[]).includes(code)
}

/** 从发布失败消息中提取候选指纹（cfgfpv1:<hex>，门禁理由携带），用于深链回归列表过滤 */
export function extractFingerprintFromGateMessage(message?: string | null): string | undefined {
  if (!message) return undefined
  const m = /cfgfpv1:[0-9a-fA-F]{8,64}/.exec(message)
  return m ? m[0] : undefined
}

/** 级别序（与 server levelRank 一致；未知级别按 0 处理，不冒充 SMOKE） */
export function regressionLevelRank(level: string): number {
  switch (level) {
    case 'SMOKE':
      return 1
    case 'FULL':
      return 2
    case 'RELEASE':
      return 3
    default:
      return 0
  }
}

/**
 * 列表「发布可用性预判」：按当前门禁策略对证据本身做客户端预评估
 * （usable=false 时给出全部文字原因）。注意这不替代发布器门禁终判——
 * 证据还须绑定发布时实际构建的候选指纹（cfgfpv1），终判以发布任务/详情页
 * gate_assessment 为准。
 */
export function previewPublishUsability(
  run: SecurityRegressionRun,
  policy: SecurityRegressionPolicy | undefined,
  nowMs: number,
): { usable: boolean; reasons: string[] } {
  const reasons: string[] = []
  if (run.verification_status !== 'PASSED') {
    reasons.push(
      run.verification_status === 'PENDING'
        ? '服务端核验未完成（待核验）'
        : '服务端核验未通过',
    )
  }
  if (run.declared_status !== 'PASS') {
    const declaredLabel = REG_DECLARED_META[run.declared_status]?.label ?? run.declared_status
    reasons.push(`回归声明状态为「${declaredLabel}」（非通过）`)
  }
  if (run.counts.executed === 0) {
    reasons.push('回归执行数为 0（执行不完整）')
  }
  if (run.counts.mandatory_failed > 0) {
    reasons.push(`强制用例未全部通过（失败 ${run.counts.mandatory_failed} 项）`)
  }
  if (policy) {
    if (regressionLevelRank(run.level) < regressionLevelRank(policy.required_level)) {
      const runLevelLabel = REG_LEVEL_META[run.level]?.label ?? run.level
      const reqLevelLabel = REG_LEVEL_META[policy.required_level]?.label ?? policy.required_level
      reasons.push(`证据级别（${runLevelLabel}）低于门禁要求（${reqLevelLabel}）`)
    }
    if (policy.required_corpus_id && run.corpus_id !== policy.required_corpus_id) {
      reasons.push(`证据语料 ${run.corpus_id} 与门禁要求语料 ${policy.required_corpus_id} 不一致`)
    }
    if (policy.evidence_max_age_seconds > 0) {
      const ageSeconds = Math.floor((nowMs - Date.parse(run.created_at)) / 1000)
      if (ageSeconds > policy.evidence_max_age_seconds) {
        reasons.push(`证据已超有效期 ${policy.evidence_max_age_seconds} 秒`)
      }
    }
  }
  return { usable: reasons.length === 0, reasons }
}

/** 差异类型（§8 筛选维度；按真值+前后动作推导，不确定归 OTHER 原样展示） */
export type RegressionDiffKind =
  | 'NEW_FALSE_POSITIVE'
  | 'LOST_DETECTION'
  | 'ACTION_CHANGE'
  | 'OTHER'

export const REG_DIFF_KIND_META: Record<RegressionDiffKind, { color: string; label: string }> = {
  NEW_FALSE_POSITIVE: { color: 'orange', label: '新增误报' },
  LOST_DETECTION: { color: 'red', label: '丢失检测' },
  ACTION_CHANGE: { color: 'gold', label: '动作变化' },
  OTHER: { color: 'default', label: '其他' },
}

/** 从用例真值/状态/差异摘要推导差异类型（diff_summary 字段名为服务端脱敏结构，
 * 预期/实际动作键按 manifest CaseResult 契约 expected_action/observed_action） */
export function classifyCaseDiff(c: {
  truth: string
  status: string
  diff_summary?: Record<string, unknown> | null
}): RegressionDiffKind {
  if (c.status === 'FAIL') {
    if (c.truth === 'BENIGN') return 'NEW_FALSE_POSITIVE'
    if (c.truth === 'ATTACK') return 'LOST_DETECTION'
  }
  const d = c.diff_summary
  if (d) {
    const expected = d['expected_action']
    const observed = d['observed_action']
    if (
      typeof expected === 'string' &&
      typeof observed === 'string' &&
      expected !== observed
    ) {
      return 'ACTION_CHANGE'
    }
    if (typeof d['action_change'] === 'string' && d['action_change']) {
      return 'ACTION_CHANGE'
    }
  }
  return 'OTHER'
}

/** 差异摘要值纯文本化（一律字符串化，渲染层不执行任何标记；REG-023 XSS 纪律） */
export function diffValueToText(value: unknown): string {
  if (value === null || value === undefined) return '-'
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2) ?? String(value)
  } catch {
    return String(value)
  }
}

/** 门禁理由 → 恢复动作提示（§8：每个不可用原因都要有文字原因与恢复动作） */
export function gateReasonAdvice(reason: string): string {
  if (reason.includes('缺少绑定') || reason.includes('回归证据')) {
    return '恢复动作：按当前候选配置重新执行回归并导入已签名证据（imports API / CI 受信通道）。'
  }
  if (reason.includes('级别')) {
    return '恢复动作：以门禁要求的更高级别（全量/发布级）重新执行回归。'
  }
  if (reason.includes('语料')) {
    return '恢复动作：使用门禁要求的语料重新执行回归，或核对门禁语料配置。'
  }
  if (reason.includes('有效期') || reason.includes('超期') || reason.includes('过期')) {
    return '恢复动作：证据已过期，需重新执行回归生成新鲜证据；已知良好恢复通道不受此项阻断。'
  }
  if (reason.includes('强制用例')) {
    return '恢复动作：定位强制用例失败项（用例差异页按失败筛选），修复后重新回归。'
  }
  if (reason.includes('执行数为 0') || reason.includes('执行不完整')) {
    return '恢复动作：检查执行环境与计划，确保用例真实执行后重新导入。'
  }
  if (reason.includes('密钥') || reason.includes('撤销')) {
    return '恢复动作：签名密钥已撤销或未登记，需以受信密钥重新签名导入。'
  }
  if (reason.includes('证据对象') || reason.includes('清理')) {
    return '恢复动作：原始证据已被清理，需从受控存储重新导入完整证据对象。'
  }
  if (reason.includes('声明状态')) {
    return '恢复动作：回归声明结果非通过，修复后重新执行；声明不采信，以服务端核验为准。'
  }
  return '恢复动作：按门禁要求重新执行回归并导入证据后重试发布。'
}
