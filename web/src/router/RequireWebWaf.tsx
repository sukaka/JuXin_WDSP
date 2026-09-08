import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useProductStore } from '../stores/product'
import { FullScreenLoading } from './RequireLicense'

/** Web 防护产品形态守卫：纯 API 形态（edition=api，webWafEnabled=false）无 WAF 域功能，按无权限跳 403 */
export function RequireWebWaf({ children }: { children: ReactNode }) {
  const { initialized, webWafEnabled } = useProductStore()
  if (!initialized) return <FullScreenLoading />
  if (!webWafEnabled) return <Navigate to="/403" replace />
  return <>{children}</>
}
