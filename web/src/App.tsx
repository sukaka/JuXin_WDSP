import { useEffect } from 'react'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import AppRoutes from './router'
import { authApi } from './api/auth'
import { setSessionExpiredHandler } from './api/client'
import { useAuthStore } from './stores/auth'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 10_000 },
  },
})

export default function App() {
  // 会话失效（401）：清理登录状态并跳登录页
  useEffect(() => {
    setSessionExpiredHandler(() => {
      useAuthStore.getState().reset()
      if (!window.location.pathname.startsWith('/login')) {
        window.location.assign('/login')
      }
    })
    return () => setSessionExpiredHandler(null)
  }, [])

  // 应用启动时探测当前会话
  useEffect(() => {
    if (useAuthStore.getState().initialized) return
    let cancelled = false
    authApi
      .me()
      .then((data) => {
        if (!cancelled) useAuthStore.getState().setSession(data.user, data.csrf_token)
      })
      .catch(() => {
        if (!cancelled) useAuthStore.getState().reset()
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
