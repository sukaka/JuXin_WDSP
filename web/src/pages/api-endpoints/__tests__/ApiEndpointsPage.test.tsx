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
      http_method: 'GET',
      normalized_path: '/v1/users/{id}',
      endpoint_key: 'GET /v1/users/{id}',
      api_confidence: 0.6,
      asset_status: 'DISCOVERED',
      learning_status: 'LEARNING',
      is_api: true,
      hit_count: 3,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T08:30:00Z',
    },
    {
      id: 'e2',
      http_method: 'POST',
      normalized_path: '/v1/orders',
      endpoint_key: 'POST /v1/orders',
      api_confidence: 0.9,
      asset_status: 'CONFIRMED',
      learning_status: 'LEARNED',
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
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染列表：路径模板、中文状态与学习状态 Tag、分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('/v1/users/{id}')).toBeInTheDocument()
    expect(screen.getByText('/v1/orders')).toBeInTheDocument()
    expect(screen.getByText('已发现')).toBeInTheDocument()
    expect(screen.getByText('已确认')).toBeInTheDocument()
    expect(screen.getByText('学习中')).toBeInTheDocument()
    expect(screen.getByText('已完成')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })

  it('无 confirm/ignore 权限：不显示行内「确认」与「忽略」', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    expect(screen.queryByRole('button', { name: /^确\s*认$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^忽\s*略$/ })).not.toBeInTheDocument()
  })

  it('有 confirm/ignore 权限：未确认行显示「确认」，未忽略行显示「忽略」；「登记发现」已移除', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.read', 'api_asset.confirm', 'api_asset.ignore']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('/v1/users/{id}')
    expect(screen.getAllByRole('button', { name: /^确\s*认$/ })).toHaveLength(1)
    expect(screen.getAllByRole('button', { name: /^忽\s*略$/ })).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /登\s*记\s*发\s*现/ })).not.toBeInTheDocument()
  })
})
