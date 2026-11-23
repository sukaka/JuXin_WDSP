import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import WhitelistsPage from '../WhitelistsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secops',
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

function renderPage(initialEntry = '/whitelists') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={[initialEntry]}>
          <WhitelistsPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('WhitelistsPage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['access_rules.read', 'access_rules.manage', 'access_rules.publish']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api/v1/access-rules')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [
                  {
                    id: 'ip-1',
                    name: '办公出口白名单',
                    rule_type: 'ALLOW',
                    scope_type: 'GLOBAL',
                    address: '203.0.113.10',
                    ip_version: 'IPV4',
                    priority: 100,
                    status: 'ACTIVE',
                    validity_type: 'PERMANENT',
                    reason: '办公网',
                    source_type: 'MANUAL',
                    hit_count: 5,
                    created_at: '2026-11-19T00:00:00Z',
                    updated_at: '2026-11-19T00:00:00Z',
                    version: 1,
                  },
                ],
                total: 1,
                page: 1,
                page_size: 20,
              },
            }),
          )
        }
        if (url.includes('/api/v1/url-whitelists')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [
                  {
                    id: 'url-1',
                    name: '健康检查放行',
                    scope_type: 'GLOBAL',
                    match_type: 'EXACT',
                    uri_pattern: '/healthz',
                    methods: ['GET'],
                    priority: 10,
                    status: 'ACTIVE',
                    validity_type: 'PERMANENT',
                    reason: '探针',
                    source_type: 'MANUAL',
                    hit_count: 12,
                    created_at: '2026-11-19T00:00:00Z',
                    updated_at: '2026-11-19T00:00:00Z',
                    version: 1,
                  },
                ],
                total: 1,
                page: 1,
                page_size: 20,
              },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
  })

  it('默认渲染 IP 白名单并可切换到 URL 白名单 Tab', async () => {
    renderPage()

    expect(await screen.findByText('办公出口白名单')).toBeInTheDocument()
    expect(screen.getByText('白名单放行范围说明')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新建 IP 白名单/ })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('tab', { name: 'URL 白名单' }))
    expect(await screen.findByText('健康检查放行')).toBeInTheDocument()
    expect(screen.getByText('/healthz')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新建 URL 白名单/ })).toBeInTheDocument()
  })
})
