import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import AppRoutes from '../index'
import { RequireBigScreen } from '../RequireBigScreen'
import { useAuthStore } from '../../stores/auth'
import { useLicenseStore } from '../../stores/license'
import { useProductStore } from '../../stores/product'
import type { CurrentUser } from '../../types'

function renderAt(path = '/big-screen') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route
          path="/big-screen"
          element={
            <RequireBigScreen>
              <div>大屏展示大厅</div>
            </RequireBigScreen>
          }
        />
        <Route path="/403" element={<div>403 无权限</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

function makeUser(roleCode: string, roleName: string, permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: roleCode.toLowerCase(),
    display_name: roleName,
    status: 'ACTIVE',
    roles: [{ code: roleCode, name: roleName }],
    permissions,
    must_change_password: false,
  }
}

describe('RequireBigScreen 大屏大厅守卫', () => {
  afterEach(() => {
    useAuthStore.getState().reset()
    useProductStore.getState().reset()
  })

  it('产品能力未初始化时显示全屏 Loading，不渲染大厅也不跳转 403', () => {
    useAuthStore.setState({
      user: makeUser('SECURITY_ADMIN', '运维管理员', ['big_screen.runtime.read']),
      csrfToken: null,
      initialized: true,
    })
    useProductStore.setState({ initialized: false })

    const { container } = renderAt()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
    expect(screen.queryByText('大屏展示大厅')).not.toBeInTheDocument()
    expect(screen.queryByText('403 无权限')).not.toBeInTheDocument()
  })

  it('系统管理员（即使持有 system_health.read 与 dashboard.runtime.read）直达 /big-screen 重定向 403', async () => {
    useAuthStore.setState({
      user: makeUser('SYSTEM_ADMIN', '系统管理员', ['system_health.read', 'dashboard.runtime.read']),
      csrfToken: null,
      initialized: true,
    })
    useProductStore.setState({ initialized: true, apiDynamicProtection: true })

    renderAt()
    expect(await screen.findByText('403 无权限')).toBeInTheDocument()
    expect(screen.queryByText('大屏展示大厅')).not.toBeInTheDocument()
  })

  it('纯审计管理员即使历史残留大屏权限点仍重定向 403', async () => {
    useAuthStore.setState({
      user: makeUser('AUDIT_ADMIN', '审计管理员', ['dashboard.security.read', 'big_screen.runtime.read']),
      csrfToken: null,
      initialized: true,
    })
    useProductStore.setState({ initialized: true, apiDynamicProtection: true })

    renderAt()
    expect(await screen.findByText('403 无权限')).toBeInTheDocument()
    expect(screen.queryByText('大屏展示大厅')).not.toBeInTheDocument()
  })

  it('运维管理员持有 big_screen.runtime.read 时正常放行大屏大厅', () => {
    useAuthStore.setState({
      user: makeUser('SECURITY_ADMIN', '运维管理员', ['big_screen.runtime.read']),
      csrfToken: null,
      initialized: true,
    })
    useProductStore.setState({ initialized: true, apiDynamicProtection: true })

    renderAt()
    expect(screen.getByText('大屏展示大厅')).toBeInTheDocument()
    expect(screen.queryByText('403 无权限')).not.toBeInTheDocument()
  })

  it('仅持有 api_runtime.read 时受 apiDynamicProtection 能力开关门控', async () => {
    useAuthStore.setState({
      user: makeUser('SECURITY_ADMIN', '运维管理员', ['api_runtime.read']),
      csrfToken: null,
      initialized: true,
    })
    useProductStore.setState({ initialized: true, apiDynamicProtection: false })

    renderAt()
    expect(await screen.findByText('403 无权限')).toBeInTheDocument()
  })
})

describe('AppRoutes 大屏路由三权隔离回归', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
    useProductStore.getState().reset()
    useLicenseStore.getState().reset()
  })

  it('系统管理员直达 /big-screen、/big-screen/runtime-ops、/big-screen/gateway-connections 均跳转 403', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data: null }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
      ),
    )
    useAuthStore.setState({
      user: makeUser('SYSTEM_ADMIN', '系统管理员', ['system_health.read', 'dashboard.runtime.read']),
      csrfToken: null,
      initialized: true,
    })
    useProductStore.setState({ initialized: true, apiDynamicProtection: true, webWafEnabled: true })
    useLicenseStore.setState({ initialized: true, status: { valid: true } as never })

    for (const path of ['/big-screen', '/big-screen/runtime-ops', '/big-screen/gateway-connections']) {
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
      const { unmount } = render(
        <QueryClientProvider client={qc}>
          <AntdApp>
            <MemoryRouter initialEntries={[path]}>
              <AppRoutes />
            </MemoryRouter>
          </AntdApp>
        </QueryClientProvider>,
      )
      expect(await screen.findByText('无访问权限'), `路径 ${path} 应被拒绝`).toBeInTheDocument()
      unmount()
    }
  })

  it('纯审计管理员即使携带安全大屏权限直达 /big-screen/security-posture 仍跳转 403', async () => {
    useAuthStore.setState({
      user: makeUser('AUDIT_ADMIN', '审计管理员', ['dashboard.security.read', 'big_screen.runtime.read']),
      csrfToken: null,
      initialized: true,
    })
    useProductStore.setState({ initialized: true, apiDynamicProtection: true, webWafEnabled: true })
    useLicenseStore.setState({ initialized: true, status: { valid: true } as never })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <MemoryRouter initialEntries={['/big-screen/security-posture']}>
            <AppRoutes />
          </MemoryRouter>
        </AntdApp>
      </QueryClientProvider>,
    )
    expect(await screen.findByText('无访问权限')).toBeInTheDocument()
  })
})
