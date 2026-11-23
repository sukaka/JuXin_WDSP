import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ProfilePage from '../ProfilePage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, ProfileData, UserItem } from '../../../types'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const CURRENT_USER: CurrentUser = {
  id: 'u1',
  username: 'admin',
  display_name: '初始显示名',
  status: 'ACTIVE',
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  permissions: ['system_settings.read'],
  must_change_password: false,
}

const PROFILE: ProfileData = {
  id: 'u1',
  username: 'admin',
  display_name: '初始显示名',
  status: 'ACTIVE',
  must_change_password: false,
  totp_enabled: false,
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  permissions: ['system_settings.read'],
  permission_details: [{ code: 'system_settings.read', name: '查看系统设置', module: 'system_settings' }],
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-01T00:00:00Z',
  version: 3,
}

const UPDATED_USER: UserItem = {
  id: 'u1',
  username: 'admin',
  display_name: '新显示名',
  status: 'ACTIVE',
  must_change_password: false,
  totp_enabled: false,
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-02T00:00:00Z',
  version: 4,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <ProfilePage />
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('ProfilePage 个人中心', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: CURRENT_USER, csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('PUT /profile 返回不含 permissions 的 UserItem 时正常更新 display_name 与 auth store', async () => {
    let currentDisplayName = PROFILE.display_name
    let currentVersion = PROFILE.version
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (url.endsWith('/api/v1/profile') && method === 'PUT') {
          const body = JSON.parse(String(init?.body)) as { display_name: string; version: number }
          currentDisplayName = body.display_name
          currentVersion = body.version + 1
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { ...UPDATED_USER, display_name: currentDisplayName, version: currentVersion },
            }),
          )
        }
        if (url.endsWith('/api/v1/profile')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { ...PROFILE, display_name: currentDisplayName, version: currentVersion },
            }),
          )
        }
        if (url.includes('/profile/login-logs')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: null, page: 1, page_size: 20, total: 0 },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderPage()
    expect(await screen.findByText('初始显示名')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /修改显示名/ }))
    const dialog = await screen.findByRole('dialog')
    const input = within(dialog).getByLabelText('显示名')
    fireEvent.change(input, { target: { value: '新显示名' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).endsWith('/api/v1/profile') && c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      expect(JSON.parse(String(putCall![1]?.body))).toEqual({
        display_name: '新显示名',
        version: 3,
      })
    })

    await waitFor(() => {
      expect(useAuthStore.getState().user?.display_name).toBe('新显示名')
    })
    expect(await screen.findByText('新显示名')).toBeInTheDocument()

    // 切到「我的登录记录」验证 items: null 也能安全渲染空态
    fireEvent.click(screen.getByRole('tab', { name: '我的登录记录' }))
    await waitFor(() => expect(document.querySelector('.ant-empty')).toBeTruthy())
  })
})
