/* ==================== AI 定时运营任务 展示元数据（与 server/internal/apiops 词表一致） ==================== */

/** 任务类型中文名（与 apiops.TaskTypeInfos 口径一致；接口 /task-types 返回同名词表） */
export const AI_TASK_TYPE_META: Record<string, { label: string; description: string }> = {
  API_ASSET_DIGEST: { label: '资产变化摘要', description: '新增/确认 API 与影子/僵尸未闭环计数' },
  SHADOW_REVIEW: { label: '影子 API 运营', description: '未闭环影子 API 清单与纳管建议' },
  WEAKNESS_FOLLOW: { label: '弱点整改跟进', description: '超期与临近到期弱点清单与催办建议' },
  RISK_DIGEST: { label: '高风险发现摘要', description: '高/严重未闭环发现分布与清单' },
  SENSITIVE_DIGEST: { label: '涉敏概览变化', description: '涉敏 API/字段总量与窗口新增清单' },
}

/** 执行记录状态 */
export const AI_RUN_STATUS_META: Record<string, { color: string; label: string }> = {
  RUNNING: { color: 'processing', label: '执行中' },
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
}

/** 任务类型中文名（未命中词表时原样展示） */
export function taskTypeLabel(taskType: string): string {
  return AI_TASK_TYPE_META[taskType]?.label ?? taskType
}

/** cron 宏（与 server apiops.cronMacros 一致） */
const CRON_MACROS = ['@hourly', '@daily', '@midnight', '@weekly', '@monthly', '@yearly', '@annually']

/** 单段允许字符：数字 * , - / （后端为标准 Vixie 子集，仅数字，不支持名字） */
const CRON_FIELD_RE = /^[0-9*,/-]+$/

/**
 * cron 表达式前端预检（仅提示，后端为权威校验）：
 * 五段（分 时 日 月 周）或宏；返回错误文案，合法返回 null。
 */
export function validateCronExpr(expr: string): string | null {
  const v = expr.trim().toLowerCase()
  if (!v) return '请输入 cron 表达式'
  if (CRON_MACROS.includes(v)) return null
  const fields = v.split(/\s+/)
  if (fields.length !== 5) {
    return `cron 表达式须为五段（分 时 日 月 周）或 ${CRON_MACROS[0]} 等宏，实际 ${fields.length} 段`
  }
  if (fields.some((f) => !CRON_FIELD_RE.test(f))) {
    return 'cron 表达式仅支持数字与 * , - / 字符（不支持 JAN/MON 等名字）'
  }
  return null
}

/** 执行耗时（started_at → finished_at；未完结返回占位符） */
export function runDuration(run: { started_at: string; finished_at?: string | null }): string {
  if (!run.finished_at) return '-'
  const ms = new Date(run.finished_at).getTime() - new Date(run.started_at).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '-'
  if (ms < 1000) return `${ms} ms`
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(1)} s`
  return `${Math.floor(s / 60)} m ${Math.round(s % 60)} s`
}
