import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useProductStore } from '../stores/product'
import { FullScreenLoading } from './RequireLicense'

/** APM 业务性能能力守卫：apm_enabled 关闭或探测失败时按不存在处理（跳 404），仿 RequireAPIDynamicProtection */
export function RequireApm({ children }: { children: ReactNode }) {
  const { initialized, apmEnabled } = useProductStore()
  if (!initialized) return <FullScreenLoading />
  if (!apmEnabled) return <Navigate to="/404" replace />
  return <>{children}</>
}
