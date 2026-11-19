import dayjs from 'dayjs'
import type { BusinessSnapshot } from '../types'

/** 部署模式展示元数据：REVERSE_PROXY 默认色 / ROUTED 紫 / MIRROR 青 / TRANSPARENT 橙（四者可区分） */
export const DEPLOYMENT_MODE_META: Record<string, { color: string; label: string }> = {
  REVERSE_PROXY: { color: 'default', label: '反向代理' },
  ROUTED: { color: 'purple', label: '路由牵引' },
  MIRROR: { color: 'cyan', label: '镜像' },
  TRANSPARENT: { color: 'orange', label: '透明串接' },
}

/** 防护模式展示元数据：OFF 灰 / OBSERVE 蓝 / PROTECT 绿 / BYPASS 火山橙（醒目警示） */
export const PROTECTION_MODE_META: Record<string, { color: string; label: string }> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察' },
  PROTECT: { color: 'green', label: '防护' },
  BYPASS: { color: 'volcano', label: '透传' },
}

export const APP_STATUS_META: Record<string, { color: string; label: string }> = {
  DRAFT: { color: 'default', label: '草稿' },
  ACTIVE: { color: 'green', label: '已启用' },
  DISABLED: { color: 'orange', label: '已停用' },
  ERROR: { color: 'red', label: '异常' },
  DELETED: { color: 'default', label: '已删除' },
}

export const DEPLOYMENT_STATUS_META: Record<string, { color: string; label: string }> = {
  NOT_PUBLISHED: { color: 'default', label: '未发布' },
  PUBLISHING: { color: 'processing', label: '发布中' },
  PUBLISHED: { color: 'green', label: '已发布' },
  PUBLISH_FAILED: { color: 'red', label: '发布失败' },
  ROLLING_BACK: { color: 'processing', label: '回滚中' },
  ROLLBACK_FAILED: { color: 'red', label: '回滚失败' },
}

export const CERT_STATUS_META: Record<string, { color: string; label: string }> = {
  VALID: { color: 'green', label: '有效' },
  EXPIRING: { color: 'orange', label: '即将到期' },
  EXPIRED: { color: 'red', label: '已过期' },
  INVALID: { color: 'default', label: '无效' },
  KEY_MISMATCH: { color: 'red', label: '密钥不匹配' },
}

export const PUBLISH_RESULT_META: Record<string, { color: string; label: string }> = {
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
  VERIFY_FAILED: { color: 'red', label: '验证失败' },
}

/** 发布后流量验证（冒烟）结果展示（阶段5 §十七） */
export const SMOKE_RESULT_META: Record<string, { color: string; label: string }> = {
  SMOKE_PASS: { color: 'green', label: '通过' },
  SMOKE_FAIL: { color: 'red', label: '未通过' },
  SMOKE_SKIPPED: { color: 'gold', label: '已降级' },
}

export const TASK_STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '等待中' },
  VALIDATING: { color: 'processing', label: '校验中' },
  GENERATING: { color: 'processing', label: '生成配置' },
  PUBLISHING: { color: 'processing', label: '发布中' },
  VERIFYING: { color: 'processing', label: '验证中' },
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
  ROLLING_BACK: { color: 'processing', label: '回滚中' },
  ROLLED_BACK: { color: 'orange', label: '已回滚' },
}

/** 证书剩余有效天数；无效/空值返回 null（负数表示已过期天数） */
export function certRemainingDays(notAfter?: string | null): number | null {
  if (!notAfter) return null
  const d = dayjs(notAfter)
  if (!d.isValid()) return null
  return d.startOf('day').diff(dayjs().startOf('day'), 'day')
}

/** 剩余天数颜色：<7 红 / <15 橙 / <30 黄 / 其余绿；已过期红 */
export function certRemainingColor(days: number): string {
  if (days < 0) return 'red'
  if (days < 7) return 'red'
  if (days < 15) return 'orange'
  if (days < 30) return 'gold'
  return 'green'
}

/** 发布/回滚任务是否已到终态 */
export function isTerminalTaskStatus(status: string): boolean {
  return status === 'SUCCESS' || status === 'FAILED' || status === 'ROLLED_BACK'
}

/** 解析业务摘要 JSON 字符串（version/diff 响应字段），失败返回 null */
export function parseBusinessSnapshot(json: string): BusinessSnapshot | null {
  if (!json) return null
  try {
    const obj = JSON.parse(json) as BusinessSnapshot
    if (!obj || !Array.isArray(obj.apps)) return null
    return obj
  } catch {
    return null
  }
}

/** 截断配置哈希用于表格展示 */
export function truncateHash(hash: string, head = 12): string {
  if (!hash) return '-'
  return hash.length > head ? `${hash.slice(0, head)}…` : hash
}
