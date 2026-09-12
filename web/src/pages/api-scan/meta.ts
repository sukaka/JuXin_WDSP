/* ==================== API 主动扫描 展示元数据（与 server/internal/apiscan 词表一致） ==================== */

import type { ApiScanAuthorization, ApiScanJobStatus } from '../../api/apiScan'

/** 目标状态 */
export const SCAN_TARGET_STATUS_META: Record<string, { color: string; label: string }> = {
  ENABLED: { color: 'green', label: '启用' },
  DISABLED: { color: 'default', label: '停用' },
}

/** 任务状态 */
export const SCAN_JOB_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'gold', label: '待启动' },
  RUNNING: { color: 'processing', label: '执行中' },
  PAUSED: { color: 'gold', label: '已暂停' },
  STOPPED: { color: 'default', label: '已停止' },
  COMPLETED: { color: 'green', label: '已完成' },
  FAILED: { color: 'red', label: '失败' },
}

/** 发现状态 */
export const SCAN_FINDING_STATUS_META: Record<string, { color: string; label: string }> = {
  NEW: { color: 'red', label: '待复核' },
  CONFIRMED: { color: 'volcano', label: '已确认' },
  FALSE_POSITIVE: { color: 'default', label: '误报' },
  RETIRED: { color: 'default', label: '已退役' },
}

/** 内置探针集（与 server 词表注释口径一致） */
export const SCAN_PROBE_SET_META: Record<string, string> = {
  AUTH_REQUIRED: '未认证访问检测',
  DEPRECATED_ALIVE: '下线 API 存活检测',
  SENSITIVE_EXPOSURE: '敏感字段暴露检测',
  SCHEMA_CONFORM: '边界参数校验检测',
  BOLA_COMPARE: '对象级响应差异比对',
  METHOD_ENUM: '允许方法枚举',
}

/** 发现分类（在弱点中心分类口径（AUTHN/LIFECYCLE/SENSITIVE/SCHEMA）基础上多 AUTHZ 越权类） */
export const SCAN_CATEGORY_META: Record<string, { color: string; label: string }> = {
  AUTHN: { color: 'red', label: '认证' },
  AUTHZ: { color: 'volcano', label: '越权' },
  LIFECYCLE: { color: 'orange', label: '生命周期' },
  SENSITIVE: { color: 'magenta', label: '敏感数据' },
  SCHEMA: { color: 'geekblue', label: 'Schema' },
}

/** 任务是否终态（非终态列表触发轮询刷新） */
export function isTerminalJobStatus(status: ApiScanJobStatus): boolean {
  return status === 'STOPPED' || status === 'COMPLETED' || status === 'FAILED'
}

/** 逗号分隔探针集 → 数组（空串归一为空数组） */
export function splitProbeSets(s: string): string[] {
  return s
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean)
}

/**
 * 授权生效状态（镜像 server Authorization.InactiveReason 派生逻辑，仅用于展示）：
 * 未撤销、未过期、处于时间窗内 = 有效。
 */
export function authorizationState(
  a: ApiScanAuthorization,
  now: Date = new Date(),
): { color: string; label: string; active: boolean } {
  if (a.revoked_at && new Date(a.revoked_at).getTime() <= now.getTime()) {
    return { color: 'default', label: '已撤销', active: false }
  }
  if (new Date(a.expires_at).getTime() <= now.getTime()) {
    return { color: 'red', label: '已过期', active: false }
  }
  if (a.time_window?.start && now.getTime() < new Date(a.time_window.start).getTime()) {
    return { color: 'gold', label: '未到时间窗', active: false }
  }
  if (a.time_window?.end && now.getTime() > new Date(a.time_window.end).getTime()) {
    return { color: 'gold', label: '已超时间窗', active: false }
  }
  return { color: 'green', label: '有效', active: true }
}
