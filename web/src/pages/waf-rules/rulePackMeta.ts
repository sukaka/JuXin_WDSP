import {
  PUBLISH_FAILURE_CODE_LABELS,
  RULEPACK_FAILURE_CODE_LABELS,
} from '../../utils/i18nLabels'
import type {
  RulePackJob,
  RulePackNodePrecheckStatus,
  RulePackPreviewReport,
  WafRuleSyncReport,
} from '../../types'

/** 规则包上传体积上限：64 MiB（与后端 rulepacks.MaxArchiveBytes 一致） */
export const RULEPACK_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

/** 默认任务轮询间隔（1.5 秒） */
export const RULEPACK_DEFAULT_POLL_INTERVAL_MS = 1500

/** 规则包档案状态元数据 */
export const RULEPACK_STATUS_META: Record<string, { color: string; label: string }> = {
  APPLIED: { color: 'green', label: '当前生效' },
  VERIFIED: { color: 'blue', label: '待应用' },
  SUPERSEDED: { color: 'default', label: '历史版本' },
  ROLLED_BACK: { color: 'orange', label: '已回滚' },
  REJECTED: { color: 'red', label: '已拒绝' },
}

/** 规则包执行任务状态元数据 */
export const RULEPACK_JOB_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '等待执行' },
  STAGING_LOCAL: { color: 'processing', label: '主节点解包' },
  STAGING_STANDBY: { color: 'processing', label: '备节点落盘' },
  PUBLISHING: { color: 'processing', label: '网关发布校验' },
  ACTIVATING: { color: 'processing', label: '切换激活版本' },
  SYNCING_METADATA: { color: 'processing', label: '同步规则元数据' },
  SUCCESS: { color: 'green', label: '执行成功' },
  ROLLING_BACK: { color: 'orange', label: '回滚中' },
  ROLLED_BACK: { color: 'orange', label: '已回滚' },
  FAILED: { color: 'red', label: '执行失败' },
}

/** 逐节点执行阶段状态元数据 */
export const RULEPACK_NODE_STEP_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '待执行' },
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
  SKIPPED: { color: 'default', label: '已跳过' },
}

/** 客户策略影响预警分类元数据 */
export const RULEPACK_POLICY_WARNING_KIND_META: Record<string, { color: string; label: string }> = {
  OVERRIDE_RULE_REMOVED: { color: 'red', label: '规则覆盖 · 规则已移除' },
  OVERRIDE_RULE_UPDATED: { color: 'orange', label: '规则覆盖 · 规则已更新' },
  EXCEPTION_RULE_REMOVED: { color: 'red', label: '例外策略 · 规则已移除' },
  EXCEPTION_RULE_UPDATED: { color: 'orange', label: '例外策略 · 规则已更新' },
  EXCEPTION_TAG_NEW_RULES: { color: 'gold', label: '例外标签 · 新增规则' },
}

/** 判断规则包执行任务是否已到达终态 */
export function isTerminalRulePackJobStatus(status?: string | null): boolean {
  return status === 'SUCCESS' || status === 'FAILED' || status === 'ROLLED_BACK'
}

/** 安全解析预检差异报告（内置基线或空 JSONB 返回 null） */
export function parsePreviewReport(raw: unknown): RulePackPreviewReport | null {
  if (!raw || typeof raw !== 'object') return null
  const obj = raw as Partial<RulePackPreviewReport>
  if (!obj.target_version && !obj.diff) return null
  const diff = obj.diff ?? {
    total_rules: 0,
    added_count: 0,
    updated_count: 0,
    removed_count: 0,
    unchanged_count: 0,
  }
  return {
    verified_at: obj.verified_at ?? '',
    signature_verified: Boolean(obj.signature_verified),
    integrity_verified: Boolean(obj.integrity_verified),
    static_gate_passed: Boolean(obj.static_gate_passed),
    previous_version: obj.previous_version ?? '',
    previous_crs_version: obj.previous_crs_version ?? '',
    target_version: obj.target_version ?? '',
    target_crs_version: obj.target_crs_version ?? '',
    changelog: Array.isArray(obj.changelog) ? obj.changelog : [],
    highlighted_cves: Array.isArray(obj.highlighted_cves) ? obj.highlighted_cves : [],
    diff: {
      total_rules: diff.total_rules ?? 0,
      added_count: diff.added_count ?? 0,
      updated_count: diff.updated_count ?? 0,
      removed_count: diff.removed_count ?? 0,
      unchanged_count: diff.unchanged_count ?? 0,
      by_source: diff.by_source ?? {},
      by_attack_type: diff.by_attack_type ?? {},
      added_samples: Array.isArray(diff.added_samples) ? diff.added_samples : [],
      updated_samples: Array.isArray(diff.updated_samples) ? diff.updated_samples : [],
      removed_samples: Array.isArray(diff.removed_samples) ? diff.removed_samples : [],
    },
    policy_warnings: Array.isArray(obj.policy_warnings) ? obj.policy_warnings : [],
    node_prechecks: Array.isArray(obj.node_prechecks) ? obj.node_prechecks : [],
    disk_free_bytes: typeof obj.disk_free_bytes === 'number' ? obj.disk_free_bytes : -1,
    disk_ok: obj.disk_ok !== false,
    split_brain_detected: Boolean(obj.split_brain_detected),
    active_upgrade_job: Boolean(obj.active_upgrade_job),
  }
}

/** 安全解析规则包生效后自动同步的 WafRuleSyncReport */
export function parseSyncReport(raw: unknown): WafRuleSyncReport | null {
  if (!raw || typeof raw !== 'object') return null
  const obj = raw as Partial<WafRuleSyncReport>
  if (typeof obj.total_in_db !== 'number' && typeof obj.total_parsed !== 'number') {
    return null
  }
  return {
    total_parsed: obj.total_parsed ?? 0,
    total_in_db: obj.total_in_db ?? 0,
    added: obj.added ?? 0,
    updated: obj.updated ?? 0,
    unchanged: obj.unchanged ?? 0,
    missing: obj.missing ?? 0,
    parse_failed: obj.parse_failed ?? 0,
    conflicts: obj.conflicts ?? 0,
    failed_rules: Array.isArray(obj.failed_rules) ? obj.failed_rules : [],
  }
}

/** 检查是否存在不可达或未就绪的 HA 备节点 */
export function hasUnreadyStandby(nodes?: RulePackNodePrecheckStatus[] | null): boolean {
  return (nodes ?? []).some(
    (n) => n.role === 'STANDBY' && (!n.reachable || !n.rulepack_ready),
  )
}

/** 格式化规则包执行失败码为中文 + 原始码 */
export function formatRulePackFailureCode(code?: string | null): string {
  if (!code) return '未知错误'
  const label = RULEPACK_FAILURE_CODE_LABELS[code] ?? PUBLISH_FAILURE_CODE_LABELS[code]
  return label ? `${label}（${code}）` : code
}

/** 根据任务状态/失败码计算 5 阶段步骤条当前索引（0..4；SUCCESS 返回 5） */
export function resolveRulePackStepIndex(job: RulePackJob): number {
  switch (job.status) {
    case 'PENDING':
    case 'STAGING_LOCAL':
      return 0
    case 'STAGING_STANDBY':
      return 1
    case 'PUBLISHING':
      return 2
    case 'ACTIVATING':
      return 3
    case 'SYNCING_METADATA':
      return 4
    case 'SUCCESS':
      return 5
    default: {
      switch (job.failure_code) {
        case 'STAGE_LOCAL_FAILED':
        case 'ARCHIVE_MISSING':
        case 'LOCK_BUSY':
          return 0
        case 'HA_NODE_LIST_FAILED':
        case 'STANDBY_STAGE_FAILED':
          return 1
        case 'GATEWAY_PUBLISH_FAILED':
          return 2
        case 'ACTIVATE_FAILED':
        case 'ACTIVATE_DB_FAILED':
        case 'SYMLINK_SWITCH_FAILED':
        case 'STANDBY_ACTIVATE_FAILED':
          return 3
        case 'METADATA_SYNC_FAILED':
          return 4
        default: {
          if (job.progress < 25) return 0
          if (job.progress < 45) return 1
          if (job.progress < 70) return 2
          if (job.progress < 85) return 3
          return 4
        }
      }
    }
  }
}
