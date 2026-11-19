import type { QueryClient } from '@tanstack/react-query'
import { queryClient as defaultQueryClient } from '../api/queryClient'
import { useAuthStore } from '../stores/auth'
import { useLicenseStore } from '../stores/license'
import { useProductStore } from '../stores/product'

/**
 * 清理本地会话状态与 TanStack Query 缓存，防止共享浏览器跨账号数据残留。
 * 若在活跃页面中退出（如 AdminLayout），可传入 onBeforeClearCache（例如 flushSync 跳转登录页）
 * 先卸载活跃查询观察器再 clear()，避免轮询查询在 clear 后立即重取回灌。
 */
export function clearClientSession(
  qc: QueryClient = defaultQueryClient,
  onBeforeClearCache?: () => void,
): void {
  useAuthStore.getState().reset()
  useProductStore.getState().reset()
  useLicenseStore.getState().reset()
  onBeforeClearCache?.()
  qc.clear()
}
