import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AccessControlVersionsPage from '../AccessControlVersionsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

const VERSIONS = {
  items: [
    {
      id: 'v1',
      version_no: 3,
      config_hash: 'abcd1234ef567890',
      change_summary: '新增黑名单规则',
      publish_result: 'SUCCESS',
      created_at: '2026-09-01T02:00:00Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 1,
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockFetch() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (method === 'POST' && url.includes('/rollback')) {
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { message: '回滚已提交' } }),
      )
    }
    if (url.includes('/diff')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { version_id: 'v1', version_no: 3, compare_with: 'v0', compare_with_no: 2, differences: [] },
        }),
      )
    }
    if (url.includes('/access-control/versions')) {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: VERSIONS }))
    }
    return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <AccessControlVersionsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('AccessControlVersionsPage 访问控制版本', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('仅 read 权限（路由 any-of 准入）：可查看差异，不显示回滚按钮', async () => {
    vi.stubGlobal('fetch', mockFetch())
    useAuthStore.setState({
      user: makeUser(['access_control_versions.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(await screen.findByText('v3')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /差\s*异/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /回\s*滚/ })).not.toBeInTheDocument()
  })

  it('有 rollback 权限：显示回滚按钮，二次确认后发起回滚', async () => {
    vi.stubGlobal('fetch', mockFetch())
    useAuthStore.setState({
      user: makeUser(['access_control_versions.read', 'access_control_versions.rollback']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /回\s*滚/ }))
    // antd confirm 弹窗标题在 Modal 与 Confirm 两处渲染，用 findAllByText 断言
    expect((await screen.findAllByText(/回滚到访问控制版本 v3？/)).length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: /确\s*认\s*回\s*滚/ }))

    await waitFor(() => {
      const calls = (fetch as ReturnType<typeof vi.fn>).mock.calls
      expect(
        calls.some(
          (c) =>
            String(c[0]).includes('/access-control/versions/v1/rollback') &&
            (c[1] as RequestInit | undefined)?.method === 'POST',
        ),
      ).toBe(true)
    })
    expect(await screen.findByText('回滚已提交，将触发配置重新发布')).toBeInTheDocument()
  })
})
