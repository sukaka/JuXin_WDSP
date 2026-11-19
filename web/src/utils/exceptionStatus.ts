import type { ExceptionItem } from '../types'
import { EXCEPTION_ACTION_META } from './stage4'

/**
 * 例外派生状态（P0-04 §8）：由草稿字段 + 有效期时间 + （可获得的）发布/节点回执数据计算。
 * 展示值必须来自真实数据，不得凭前端计时器假装全节点一致——
 * 取不到发布/节点数据时返回 ENABLED_NOT_PUBLISHED（页面显示「未发布/未知」）。
 */
export type ExceptionDerivedStatus =
  | 'DRAFT'
  | 'NEEDS_REVIEW'
  | 'ENABLED_NOT_PUBLISHED'
  | 'PUBLISHING'
  | 'PARTIALLY_EFFECTIVE'
  | 'EFFECTIVE'
  | 'EXPIRED'
  | 'DISABLED'

/** 派生状态展示元数据 */
export const EXCEPTION_DERIVED_STATUS_META: Record<
  ExceptionDerivedStatus,
  { color: string; label: string }
> = {
  DRAFT: { color: 'default', label: '草稿' },
  NEEDS_REVIEW: { color: 'red', label: '待审查' },
  ENABLED_NOT_PUBLISHED: { color: 'gold', label: '未发布/未知' },
  PUBLISHING: { color: 'processing', label: '发布中' },
  PARTIALLY_EFFECTIVE: { color: 'orange', label: '部分节点生效' },
  EFFECTIVE: { color: 'green', label: '已生效' },
  EXPIRED: { color: 'orange', label: '已过期' },
  DISABLED: { color: 'default', label: '已停用' },
}

/** 发布/节点回执数据（来自既有发布数据；无数据时为 undefined） */
export interface ExceptionPublishState {
  /** 发布侧状态：NOT_PUBLISHED / PUBLISHING / PUBLISHED / PARTIAL */
  state?: string | null
  /** 目标节点总数（有节点回执明细时非空） */
  nodes_total?: number | null
  /** 已回执（实际生效）节点数 */
  nodes_acknowledged?: number | null
}

export interface ExceptionStatusInput {
  /** 后端原始状态（ENABLED / DISABLED / EXPIRED / DRAFT…） */
  status?: string | null
  /** 校验状态（VALID / NEEDS_REVIEW） */
  validation_status?: string | null
  /** 失效时间（RFC3339；半开区间上界，now >= until 即过期） */
  effective_until?: string | null
  /** 发布/节点回执数据；取不到时传 undefined，不得伪造 */
  publish?: ExceptionPublishState | null
  /** 当前时间（毫秒，UTC）；测试注入受控时钟，默认 Date.now() */
  now?: number
}

/**
 * 计算例外派生状态。优先级：
 * 1. 时间事实：启用中且 now >= effective_until → EXPIRED（到期不依赖再发布）
 * 2. 后端明示 EXPIRED → EXPIRED
 * 3. validation_status=NEEDS_REVIEW → NEEDS_REVIEW（历史危险配置醒目标记，禁止启用）
 * 4. DISABLED → DISABLED
 * 5. 非 ENABLED（DRAFT 等）→ DRAFT
 * 6. ENABLED 后按发布/节点回执推导；无回执数据一律 ENABLED_NOT_PUBLISHED（「未发布/未知」）
 */
export function computeExceptionDerivedStatus(input: ExceptionStatusInput): ExceptionDerivedStatus {
  const now = input.now ?? Date.now()
  const until = input.effective_until ? Date.parse(input.effective_until) : Number.NaN
  const untilMs = Number.isNaN(until) ? null : until

  if (input.status === 'ENABLED' && untilMs !== null && now >= untilMs) return 'EXPIRED'
  if (input.status === 'EXPIRED') return 'EXPIRED'
  if (input.validation_status === 'NEEDS_REVIEW') return 'NEEDS_REVIEW'
  if (input.status === 'DISABLED') return 'DISABLED'
  if (input.status !== 'ENABLED') return 'DRAFT'

  const pub = input.publish
  if (!pub || !pub.state || pub.state === 'NOT_PUBLISHED') return 'ENABLED_NOT_PUBLISHED'
  if (pub.state === 'PUBLISHING') return 'PUBLISHING'

  const total = pub.nodes_total
  const acked = pub.nodes_acknowledged
  if (typeof total === 'number' && total > 0 && typeof acked === 'number') {
    return acked >= total ? 'EFFECTIVE' : 'PARTIALLY_EFFECTIVE'
  }
  if (pub.state === 'PARTIAL') return 'PARTIALLY_EFFECTIVE'
  // 发布完成但无节点回执明细：不能凭发布动作假装全节点一致
  return 'ENABLED_NOT_PUBLISHED'
}

/** 从例外记录计算派生状态（无发布数据时 publish 传 undefined） */
export function deriveExceptionStatus(
  record: Pick<
    ExceptionItem,
    'status' | 'validation_status' | 'effective_until'
  >,
  publish?: ExceptionPublishState | null,
  now?: number,
): ExceptionDerivedStatus {
  return computeExceptionDerivedStatus({
    status: record.status,
    validation_status: record.validation_status,
    effective_until: record.effective_until,
    publish,
    now,
  })
}

/** P0-04 §3：WAF 引擎不支持新启用的历史动作（禁止整请求 DetectionOnly 替代语义） */
export const UNSUPPORTED_WAF_ACTIONS: readonly string[] = ['LOG_ONLY', 'ADJUST_SCORE']

/** 动作是否支持新启用（按目标引擎；历史记录保留可读但拒绝启用） */
export function isActionSupportedForNewEnable(engine: string | undefined, action: string): boolean {
  if ((engine ?? 'WAF') === 'API') return action === 'OBSERVE_RULE'
  return !UNSUPPORTED_WAF_ACTIONS.includes(action)
}

/**
 * 计算「启用」阻断原因列表（空数组 = 可启用）。
 * 口径与后端启用门禁一致（S4 §4），前端仅作提示，最终以服务端校验为准：
 * - NEEDS_REVIEW 记录禁止启用，逐条列出 unsupported_reasons 说明缺什么；
 * - 历史不支持动作（WAF LOG_ONLY/ADJUST_SCORE、API 非 OBSERVE_RULE）拒绝新启用。
 */
export function getExceptionEnableBlockers(
  record: Pick<
    ExceptionItem,
    'validation_status' | 'unsupported_reasons' | 'target_engine' | 'exception_action'
  >,
): string[] {
  const blockers: string[] = []
  if (record.validation_status === 'NEEDS_REVIEW') {
    const reasons = (record.unsupported_reasons ?? []).filter((r) => !!r)
    blockers.push(
      reasons.length > 0
        ? `待审查记录禁止启用，请先修改达标：${reasons.join('；')}`
        : '待审查记录禁止启用，请先补全范围与规则配置',
    )
  }
  if (!isActionSupportedForNewEnable(record.target_engine, record.exception_action)) {
    const actionLabel = EXCEPTION_ACTION_META[record.exception_action]?.label ?? record.exception_action
    const recommendedLabel = EXCEPTION_ACTION_META.REMOVE_VAR_DETECTION?.label ?? '移除变量检测'
    blockers.push(
      `动作「${actionLabel}」不支持新启用，请改为精确目标排除（如「${recommendedLabel}」）`,
    )
  }
  return blockers
}
