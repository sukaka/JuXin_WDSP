// 阶段7 AI 模块通用展示元数据（状态/类型 → 中文标签 + 颜色）
import type { AiSseEvent } from '../api/ai'

export const AI_TASK_TYPE_META: Record<string, { color: string; label: string }> = {
  EVENT_ANALYSIS: { color: 'red', label: '事件分析' },
  FALSE_POSITIVE_ANALYSIS: { color: 'orange', label: '误报分析' },
  RULE_EXPLANATION: { color: 'blue', label: '规则解释' },
  ATTACK_PROFILE: { color: 'volcano', label: '攻击画像' },
  ATTACK_CHAIN: { color: 'purple', label: '攻击链' },
  ROOT_CAUSE_ANALYSIS: { color: 'geekblue', label: '根因分析' },
  LOG_QUERY: { color: 'cyan', label: '日志查询' },
  STATISTICS_QUERY: { color: 'cyan', label: '统计查询' },
  POLICY_RECOMMENDATION: { color: 'gold', label: '策略建议' },
  WHAT_IF_ANALYSIS: { color: 'gold', label: '情景模拟' },
  DRAFT_EXCEPTION: { color: 'lime', label: '例外草稿' },
  DRAFT_BLACKLIST: { color: 'lime', label: '黑名单草稿' },
  DRAFT_CC_POLICY: { color: 'lime', label: '频率策略草稿' },
  DRAFT_CUSTOM_RULE: { color: 'lime', label: '自定义规则草稿' },
  REPORT_SUMMARY: { color: 'green', label: '报告总结' },
  GENERAL_SECURITY_QA: { color: 'blue', label: '安全问答' },
}

export const AI_TASK_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '等待中' },
  PLANNING: { color: 'processing', label: '规划中' },
  RUNNING: { color: 'processing', label: '执行中' },
  WAITING_TOOL: { color: 'processing', label: '等待工具' },
  COMPOSING: { color: 'processing', label: '生成回答' },
  SUCCESS: { color: 'success', label: '成功' },
  PARTIAL_SUCCESS: { color: 'warning', label: '部分成功' },
  FAILED: { color: 'error', label: '失败' },
  CANCELLED: { color: 'default', label: '已取消' },
}

export const AI_RISK_META: Record<string, { color: string; label: string }> = {
  LOW: { color: 'green', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
  CRITICAL: { color: 'volcano', label: '严重' },
}

export const AI_DRAFT_TYPE_META: Record<string, { color: string; label: string }> = {
  EXCEPTION: { color: 'blue', label: '例外策略' },
  BLACKLIST: { color: 'red', label: '黑名单' },
  CC_POLICY: { color: 'orange', label: '频率策略' },
  CUSTOM_RULE: { color: 'purple', label: '自定义规则' },
  POLICY_CHANGE: { color: 'gold', label: '策略变更' },
  REPORT_SUMMARY: { color: 'green', label: '报告总结' },
}

export const AI_DRAFT_STATUS_META: Record<string, { color: string; label: string }> = {
  DRAFT: { color: 'warning', label: '草稿未生效' },
  PENDING_REVIEW: { color: 'processing', label: '待审核' },
  ACCEPTED: { color: 'success', label: '已采纳' },
  REJECTED: { color: 'default', label: '已废弃' },
  EXPIRED: { color: 'default', label: '已过期' },
}

export const AI_PROMPT_TYPE_META: Record<string, { color: string; label: string }> = {
  SYSTEM: { color: 'geekblue', label: '系统' },
  ORCHESTRATOR: { color: 'purple', label: '编排器' },
  AGENT: { color: 'blue', label: '智能体' },
  TOOL: { color: 'cyan', label: '工具' },
  TASK: { color: 'gold', label: '任务' },
  SAFETY: { color: 'red', label: '安全' },
  EVALUATION: { color: 'green', label: '评估' },
}

export const AI_TOOL_RISK_META: Record<string, { color: string; label: string }> = {
  READ_ONLY: { color: 'green', label: '只读' },
  DRAFT_ONLY: { color: 'orange', label: '仅草稿' },
  REQUIRES_CONFIRMATION: { color: 'red', label: '需确认' },
  PROHIBITED: { color: 'volcano', label: '禁止' },
}

export const AI_MEMORY_SCOPE_META: Record<string, { color: string; label: string }> = {
  SESSION: { color: 'cyan', label: '会话' },
  PROJECT: { color: 'blue', label: '项目' },
  LONG_TERM: { color: 'purple', label: '长期' },
}

export const AI_MEMORY_CONFIDENCE_META: Record<string, { color: string; label: string }> = {
  USER_CONFIRMED: { color: 'green', label: '用户确认' },
  SYSTEM_CONFIRMED: { color: 'blue', label: '系统确认' },
  AI_INFERRED: { color: 'orange', label: '智能推测' },
}

export const AI_PROVIDER_TYPE_META: Record<string, { color: string; label: string }> = {
  openai_compatible: { color: 'blue', label: '开放兼容协议' },
  anthropic: { color: 'purple', label: 'Anthropic 协议' },
  ollama: { color: 'green', label: '本地推理服务' },
  local: { color: 'cyan', label: '本地模型' },
}

export const AI_AGENT_NAMES: Record<string, string> = {
  dispatcher: '总调度智能体',
  security_event: '安全事件智能体',
  log_analysis: '日志分析智能体',
  waf_policy: '防护策略智能体',
  asset: '资产智能体',
  ops_diagnostic: '运维诊断智能体',
  report: '报告智能体',
  knowledge: '知识库智能体',
}

/** SSE 步骤事件类型 → 展示元数据 */
export const AI_STEP_META: Record<string, { color: string; label: string }> = {
  plan: { color: 'blue', label: '任务计划' },
  agent_start: { color: 'processing', label: '智能体开始' },
  agent_done: { color: 'green', label: '智能体完成' },
  composing: { color: 'processing', label: '生成回答' },
  tool: { color: 'cyan', label: '工具调用' },
  error: { color: 'red', label: '错误' },
  compressed: { color: 'orange', label: '上下文压缩' },
  answer: { color: 'green', label: '回答就绪' },
}

/** 过滤出可展示的过程步骤（done/answer 正文不在过程区重复展示） */
export function visibleSteps(events: AiSseEvent[]): AiSseEvent[] {
  return events.filter((e) => e.type !== 'done' && e.type !== 'answer')
}
