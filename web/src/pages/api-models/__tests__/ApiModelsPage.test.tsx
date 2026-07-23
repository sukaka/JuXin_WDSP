import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiModelsPage from '../ApiModelsPage'
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

const endpointsData = {
  items: [
    {
      id: 'e1',
      http_method: 'POST',
      normalized_path: '/v1/orders/{id}',
      endpoint_key: 'POST /v1/orders/{id}',
      api_confidence: 0.9,
      asset_status: 'CONFIRMED',
      learning_status: 'LEARNING',
      is_api: true,
      hit_count: 12,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T09:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const listData = {
  items: [
    {
      id: 'm1',
      api_endpoint_id: 'e1',
      endpoint_key: 'POST /v1/orders/{id}',
      status: 'CANDIDATE',
      schema: { id: 'number' },
      content_hash: 'abcdef1234567890',
      version_number: 3,
      change_summary: '',
      created_reason: 'MANUAL',
      created_at: '2026-07-20T02:00:00Z',
    },
    {
      id: 'm2',
      api_endpoint_id: 'e1',
      endpoint_key: 'POST /v1/orders/{id}',
      status: 'FORMAL',
      schema: { id: 'number', name: 'string' },
      content_hash: '0011223344556677',
      version_number: 2,
      change_summary: '',
      created_reason: 'MANUAL',
      created_at: '2026-07-19T02:00:00Z',
      confirmed_at: '2026-07-19T03:00:00Z',
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
          <ApiModelsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiModelsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/endpoints/e1/models')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
        }
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染列表：中文状态 Tag、哈希截断与分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('候选')).toBeInTheDocument()
    expect(screen.getByText('正式')).toBeInTheDocument()
    expect(screen.getByText('abcdef1234…')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })

  it('无 edit 权限：不显示「创建候选」与行内「确认冻结」', async () => {
    useAuthStore.setState({ user: makeUser(['api_model.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('候选')
    expect(screen.queryByRole('button', { name: /创\s*建\s*候\s*选/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /确\s*认\s*冻\s*结/ })).not.toBeInTheDocument()
  })

  it('有 edit 权限：显示「创建候选」，候选行显示「确认冻结」', async () => {
    useAuthStore.setState({
      user: makeUser(['api_model.read', 'api_model.edit']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('候选')
    expect(screen.getByRole('button', { name: /创\s*建\s*候\s*选/ })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /确\s*认\s*冻\s*结/ })).toHaveLength(1)
  })
})
