import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiEndpointsPage from '../ApiEndpointsPage'
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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const listData = {
  items: [
    {
      id: 'e1',
      method: 'GET',
      path_template: '/v1/users/{id}',
      endpoint_key: 'GET /v1/users/{id}',
      confidence: 0.6,
      status: 'DISCOVERED',
      is_api: true,
      hit_count: 3,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T08:30:00Z',
    },
    {
      id: 'e2',
      method: 'POST',
      path_template: '/v1/orders',
      endpoint_key: 'POST /v1/orders',
      confidence: 0.9,
      status: 'CONFIRMED',
      is_api: true,
      hit_count: 12,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T09:00:00Z',
      confirmed_at: '2026-07-02T01:00:00Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 2,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiEndpointsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiEndpointsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-endpoints')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染列表：路径模板、中文状态 Tag 与分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_endpoints.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('/v1/users/{id}')).toBeInTheDocument()
    expect(screen.getByText('/v1/orders')).toBeInTheDocument()
    expect(screen.getByText('已发现')).toBeInTheDocument()
    expect(screen.getAllByText('已确认').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })

  it('无 manage 权限：不显示「登记发现」与行内「确认」', async () => {
    useAuthStore.setState({ user: makeUser(['api_endpoints.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    expect(screen.queryByRole('button', { name: /登\s*记\s*发\s*现/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^确\s*认$/ })).not.toBeInTheDocument()
  })

  it('有 manage 权限：显示「登记发现」，未确认行显示「确认」操作', async () => {
    useAuthStore.setState({
      user: makeUser(['api_endpoints.read', 'api_endpoints.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    expect(screen.getByRole('button', { name: /登\s*记\s*发\s*现/ })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /^确\s*认$/ })).toHaveLength(1)
  })
})
