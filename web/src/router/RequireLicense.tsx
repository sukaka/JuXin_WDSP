import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { Spin } from 'antd'
import { useLicenseStore } from '../stores/license'

/** 全屏加载（会话/授权等启动探测未完成时的占位，避免页面闪烁） */
export function FullScreenLoading() {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Spin size="large" tip="加载中..." />
    </div>
  )
}

/**
 * 授权守卫：登录后由 license store 承载 /license/status 状态——
 * 未加载完成先全屏 Loading（不闪烁）；授权无效（含状态加载失败）时
 * 除 /license 外一律重定向授权管理页（无授权 = 全系统锁定，后端 423 为强制点）。
 */
export function RequireLicense({ children }: { children: ReactNode }) {
  const { status, initialized } = useLicenseStore()
  const location = useLocation()
  if (!initialized) return <FullScreenLoading />
  if (!status?.valid && location.pathname !== '/license') {
    return <Navigate to="/license" replace />
  }
  return <>{children}</>
}
