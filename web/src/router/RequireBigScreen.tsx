import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { filterBigScreens } from '../pages/big-screen/screens'
import { useAuthStore } from '../stores/auth'
import { useProductStore } from '../stores/product'
import { FullScreenLoading } from './RequireLicense'

/**
 * 大屏大厅路由守卫：
 * - 产品能力未初始化时显示 Loading，避免误判 API 大屏权限；
 * - 纯审计管理员与无任何大屏权限的账号（含系统管理员）一律重定向到 /403。
 */
export function RequireBigScreen({ children }: { children: ReactNode }) {
  const user = useAuthStore((s) => s.user)
  const { initialized, apiDynamicProtection } = useProductStore()
  if (!initialized) return <FullScreenLoading />
  const roleCodes = user?.roles.map((role) => role.code) ?? []
  const auditOnly =
    roleCodes.includes('AUDIT_ADMIN') &&
    !roleCodes.some(
      (code) => code === 'SYSTEM_ADMIN' || code === 'SECURITY_ADMIN',
    )
  if (auditOnly) {
    return <Navigate to="/403" replace />
  }
  const screens = filterBigScreens(user?.permissions, { apiDynamicProtection })
  if (screens.length === 0) {
    return <Navigate to="/403" replace />
  }
  return <>{children}</>
}
