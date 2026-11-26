import { ApiError } from '../../api/client'
import type { UpgradeClusterMode } from '../../types'

const ACTIVE_UPGRADE_STORAGE_KEY = 'jiuzhang_wdsp_active_upgrade'

export interface ActiveUpgradeContext {
  jobId: string
  initialStatus?: string
  versionFrom?: string
  versionTo?: string
  components?: string[]
  hasLayerDelta?: boolean
  clusterMode?: UpgradeClusterMode
  startedAtMs: number
}

export function saveActiveUpgrade(ctx: ActiveUpgradeContext): void {
  try {
    window.sessionStorage.setItem(ACTIVE_UPGRADE_STORAGE_KEY, JSON.stringify(ctx))
  } catch {
    // 隐私模式或禁用 storage 时忽略，内存态仍正常工作
  }
}

export function loadActiveUpgrade(): ActiveUpgradeContext | null {
  try {
    const raw = window.sessionStorage.getItem(ACTIVE_UPGRADE_STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<ActiveUpgradeContext>
    if (!parsed || typeof parsed.jobId !== 'string' || !parsed.jobId) return null
    // 超过 2 小时的陈旧记录不自动接管，交由正常列表拉取判定
    const startedAtMs = typeof parsed.startedAtMs === 'number' ? parsed.startedAtMs : Date.now()
    if (Date.now() - startedAtMs > 2 * 60 * 60 * 1000) {
      clearActiveUpgrade()
      return null
    }
    return {
      jobId: parsed.jobId,
      initialStatus: typeof parsed.initialStatus === 'string' ? parsed.initialStatus : undefined,
      versionFrom: typeof parsed.versionFrom === 'string' ? parsed.versionFrom : undefined,
      versionTo: typeof parsed.versionTo === 'string' ? parsed.versionTo : undefined,
      components: Array.isArray(parsed.components) ? parsed.components : undefined,
      hasLayerDelta: Boolean(parsed.hasLayerDelta),
      clusterMode: parsed.clusterMode === 'HA_ROLLING' ? 'HA_ROLLING' : 'LOCAL',
      startedAtMs,
    }
  } catch {
    return null
  }
}

export function clearActiveUpgrade(): void {
  try {
    window.sessionStorage.removeItem(ACTIVE_UPGRADE_STORAGE_KEY)
  } catch {
    // ignore
  }
}

/**
 * 判断升级状态轮询遇到的异常是否属于「服务重启切换期间的可恢复瞬时断连」。
 * 仅对网络断连、超时、502/503/504 及代理 5xx 静默重试；401/403/404 等确定性错误不吞掉。
 */
export function isTransientUpgradePollError(err: unknown): boolean {
  if (err instanceof ApiError) {
    if (err.code === 'NETWORK_ERROR' || err.code === 'TIMEOUT') return true
    if (err.status === 0 || err.status === 502 || err.status === 503 || err.status === 504) {
      return true
    }
    if (err.code === 'HTTP_ERROR' && err.status >= 500) return true
    return false
  }
  return true
}
