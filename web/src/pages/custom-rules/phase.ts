/** 依赖请求体的检测变量基础名（与后端 customrules.InferPhase 保持严格一致） */
const BODY_PHASE_VARIABLES = new Set([
  'REQUEST_BODY',
  'ARGS_POST',
  'ARGS',
  'ARGS_NAMES',
])

/**
 * 根据检测变量自动推导自定义规则执行阶段（与后端 customrules.InferPhase 严格一致）：
 * - 包含任一请求体变量（REQUEST_BODY / ARGS_POST / ARGS / ARGS_NAMES，支持 :selector 后缀）→ 2（请求体）
 * - 其余请求头/请求行/URI/Cookie 等变量（或为空时）→ 1（请求头）
 */
export function inferCustomRulePhase(targetVariables?: string[]): 1 | 2 {
  if (!targetVariables || targetVariables.length === 0) return 1
  for (const variable of targetVariables) {
    const base = variable.split(':')[0] ?? ''
    if (BODY_PHASE_VARIABLES.has(base)) {
      return 2
    }
  }
  return 1
}

const PHASE_LABELS: Record<number, string> = {
  1: '阶段 1（请求头）',
  2: '阶段 2（请求体）',
  3: '阶段 3（响应头）',
  4: '阶段 4（响应体）',
  5: '阶段 5（日志）',
}

/** 格式化执行阶段中文标签（兼容历史 1-5 阶段记录） */
export function formatCustomRulePhase(phase?: number): string {
  if (phase === undefined || phase === null) return '-'
  return PHASE_LABELS[phase] ?? `阶段 ${phase}`
}

/** 表单内面向用户的自动生效时机提示文案 */
export function getAutoPhaseNotice(targetVariables?: string[]): {
  phase: 1 | 2
  text: string
} {
  const phase = inferCustomRulePhase(targetVariables)
  if (phase === 2) {
    return {
      phase: 2,
      text: '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
    }
  }
  return {
    phase: 1,
    text: '自动生效时机：请求头阶段（优先于内置防护规则生效）',
  }
}
