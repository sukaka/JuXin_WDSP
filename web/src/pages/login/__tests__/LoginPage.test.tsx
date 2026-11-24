import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import LoginPage from '../LoginPage'
import { queryClient } from '../../../api/queryClient'
import { useAuthStore } from '../../../stores/auth'
import { useProductStore } from '../../../stores/product'
import type { CurrentUser } from '../../../types'

const fakeUser: CurrentUser = {
  id: 'u1',
  username: 'admin',
  display_name: '系统管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  permissions: [],
  must_change_password: false,
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderLogin(initialEntry: string | { pathname: string; state?: unknown } = '/login') {
  return render(
    <MemoryRouter initialEntries={[initialEntry as never]}>
      <AntdApp>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/dashboard" element={<div>dashboard-page</div>} />
          <Route path="/users" element={<div>users-page</div>} />
          <Route path="/ha-groups" element={<div>ha-groups-page</div>} />
          <Route path="/apm-overview" element={<div>apm-overview-page</div>} />
        </Routes>
      </AntdApp>
    </MemoryRouter>,
  )
}

describe('LoginPage', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
    useProductStore.setState({
      edition: 'waf',
      apiDynamicProtection: false,
      initialized: false,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染登录表单（验证码关闭时）', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { enabled: false } }),
        ),
      ),
    )
    renderLogin()
    expect(await screen.findByPlaceholderText('用户名')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('密码')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /登 录/ })).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('图形验证码')).not.toBeInTheDocument()
  })

  it('提交登录：请求体正确并写入会话', async () => {
    const fetchMock = vi.fn<typeof fetch>((input) => {
      const url = String(input)
      if (url.includes('/auth/captcha')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { enabled: false } }),
        )
      }
      if (url.includes('/auth/login')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { user: fakeUser, csrf_token: 'csrf-login' },
          }),
        )
      }
      if (url.includes('/product/edition')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { edition: 'wdsp', api_dynamic_protection: true },
          }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderLogin()
    fireEvent.change(await screen.findByPlaceholderText('用户名'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('密码'), { target: { value: 'Secret@123456' } })
    fireEvent.click(screen.getByRole('button', { name: /登 录/ }))

    await waitFor(() => {
      const loginCall = fetchMock.mock.calls.find(([input]) => String(input).includes('/auth/login'))
      expect(loginCall).toBeDefined()
      const init = loginCall?.[1] as RequestInit
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      expect(body.username).toBe('admin')
      expect(body.password).toBe('Secret@123456')
    })

    await waitFor(() => {
      expect(useAuthStore.getState().user?.username).toBe('admin')
      expect(useAuthStore.getState().csrfToken).toBe('csrf-login')
      expect(useProductStore.getState().apiDynamicProtection).toBe(true)
    })
  })

  it('登录失败：清空密码并刷新验证码，不写会话', async () => {
    let captchaCalls = 0
    const fetchMock = vi.fn<typeof fetch>((input) => {
      const url = String(input)
      if (url.includes('/auth/captcha')) {
        captchaCalls += 1
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { enabled: false } }),
        )
      }
      if (url.includes('/auth/login')) {
        return Promise.resolve(
          jsonResponse(401, { code: 'UNAUTHENTICATED', message: '用户名或密码错误' }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderLogin()
    fireEvent.change(await screen.findByPlaceholderText('用户名'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('密码'), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByRole('button', { name: /登 录/ }))

    await waitFor(() => {
      expect(captchaCalls).toBeGreaterThanOrEqual(2)
    })
    expect((screen.getByPlaceholderText('密码') as HTMLInputElement).value).toBe('')
    expect((screen.getByPlaceholderText('用户名') as HTMLInputElement).value).toBe('admin')
    expect(useAuthStore.getState().user).toBeNull()
  })

  /** 登录请求 mock：验证码关闭 + 登录成功 + 产品能力探测 */
  function stubLoginSuccess(user: CurrentUser) {
    const fetchMock = vi.fn<typeof fetch>((input) => {
      const url = String(input)
      if (url.includes('/auth/captcha')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { enabled: false } }),
        )
      }
      if (url.includes('/auth/login')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { user, csrf_token: 'csrf-login' },
          }),
        )
      }
      if (url.includes('/product/edition') || url.includes('/license')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { edition: 'waf' } }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)
  }

  async function submitLogin() {
    fireEvent.change(await screen.findByPlaceholderText('用户名'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('密码'), { target: { value: 'Secret@123456' } })
    fireEvent.click(screen.getByRole('button', { name: /登 录/ }))
  }

  it('登录后回跳：from 是当前账号可见的菜单页时按 from 跳转', async () => {
    stubLoginSuccess(fakeUser) // SYSTEM_ADMIN
    renderLogin({ pathname: '/login', state: { from: '/users' } })
    await submitLogin()
    expect(await screen.findByText('users-page')).toBeInTheDocument()
  })

  it('登录后回跳：from 属于其他角色页面时回退工作台（账号切换 403 回归）', async () => {
    stubLoginSuccess(fakeUser) // SYSTEM_ADMIN 不可见 /applications（SECURITY_ADMIN）
    renderLogin({ pathname: '/login', state: { from: '/applications' } })
    await submitLogin()
    expect(await screen.findByText('dashboard-page')).toBeInTheDocument()
  })

  it('登录后回跳：角色码不匹配但持有权限点时按 from 跳转（与路由守卫口径一致）', async () => {
    // AUDIT_ADMIN 不在 /ha-groups 菜单角色列表，但持有 ha.read（路由守卫按权限点放行）
    const auditUser: CurrentUser = {
      ...fakeUser,
      roles: [{ code: 'AUDIT_ADMIN', name: '审计管理员' }],
      permissions: ['ha.read'],
    }
    stubLoginSuccess(auditUser)
    renderLogin({ pathname: '/login', state: { from: '/ha-groups' } })
    await submitLogin()
    expect(await screen.findByText('ha-groups-page')).toBeInTheDocument()
  })

  it('登录后回跳：from 为根路径时静默进入工作台', async () => {
    stubLoginSuccess(fakeUser)
    renderLogin({ pathname: '/login', state: { from: '/' } })
    await submitLogin()
    expect(await screen.findByText('dashboard-page')).toBeInTheDocument()
  })

  it('新账号登录前清空上一账号残留的 QueryClient 缓存', async () => {
    queryClient.setQueryData(['security-events', 'stale'], { items: [{ id: 'prev-user-evt' }] })
    expect(queryClient.getQueryCache().getAll().length).toBeGreaterThan(0)
    stubLoginSuccess(fakeUser)
    renderLogin()
    await submitLogin()
    expect(await screen.findByText('dashboard-page')).toBeInTheDocument()
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0)
  })

  it('登录后回跳：from 属于系统管理员不可见的大屏或受限菜单时回退工作台（防 403）', async () => {
    for (const forbiddenPath of ['/big-screen/runtime-ops', '/traffic-agents', '/system-alerts']) {
      useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
      stubLoginSuccess({
        ...fakeUser,
        permissions: ['system_health.read', 'dashboard.runtime.read', 'users.read'],
      })
      const { unmount } = renderLogin({ pathname: '/login', state: { from: forbiddenPath } })
      await submitLogin()
      expect(await screen.findByText('dashboard-page')).toBeInTheDocument()
      unmount()
    }
  })

  it('登录后回跳：apm_enabled=true 且有权限时允许直接回跳 APM 页面', async () => {
    const secUser: CurrentUser = {
      ...fakeUser,
      roles: [{ code: 'SECURITY_ADMIN', name: '运维管理员' }],
      permissions: ['apm.overview.read'],
    }
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>((input) => {
        const url = String(input)
        if (url.includes('/auth/captcha')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { enabled: false } }),
          )
        }
        if (url.includes('/auth/login')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { user: secUser, csrf_token: 'csrf-apm' },
            }),
          )
        }
        if (url.includes('/product/edition')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { edition: 'wdsp', api_dynamic_protection: true, apm_enabled: true },
            }),
          )
        }
        if (url.includes('/license')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { valid: true } }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    renderLogin({ pathname: '/login', state: { from: '/apm-overview' } })
    await submitLogin()
    expect(await screen.findByText('apm-overview-page')).toBeInTheDocument()
  })
})
