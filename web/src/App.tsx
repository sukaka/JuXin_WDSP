import { useEffect } from 'react'
import { BrowserRouter } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import AppRoutes from './router'
import { authApi } from './api/auth'
import { setLicenseInvalidHandler, setSessionExpiredHandler } from './api/client'
import { queryClient } from './api/queryClient'
import { useAuthStore } from './stores/auth'
import { useLicenseStore } from './stores/license'
import { useProductStore } from './stores/product'
import { clearClientSession } from './utils/session'

export default function App() {
  // 会话失效（401）：清理登录状态并跳登录页
  useEffect(() => {
    setSessionExpiredHandler(() => {
      clearClientSession(queryClient)
      if (!window.location.pathname.startsWith('/login')) {
        window.location.assign('/login')
      }
    })
    // 授权失效（423）：重新拉取授权状态，无效时由 RequireLicense 锁定到授权管理页
    setLicenseInvalidHandler(() => {
      void useLicenseStore.getState().load()
    })
    return () => {
      setSessionExpiredHandler(null)
      setLicenseInvalidHandler(null)
    }
  }, [])

  // 应用启动时探测当前会话
  useEffect(() => {
    if (useAuthStore.getState().initialized) return
    let cancelled = false
    authApi
      .me()
      .then(async (data) => {
        if (cancelled) return
        useAuthStore.getState().setSession(data.user, data.csrf_token)
        await useProductStore.getState().load()
        await useLicenseStore.getState().load()
      })
      .catch(() => {
        if (!cancelled) {
          useAuthStore.getState().reset()
          useProductStore.getState().reset()
          useLicenseStore.getState().reset()
        }
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <ConfigProvider locale={zhCN} theme={{ token: { colorPrimary: '#2f54eb' } }}>
      <AntdApp>
        <QueryClientProvider client={queryClient}>
          <BrowserRouter>
            <AppRoutes />
          </BrowserRouter>
        </QueryClientProvider>
      </AntdApp>
    </ConfigProvider>
  )
}
