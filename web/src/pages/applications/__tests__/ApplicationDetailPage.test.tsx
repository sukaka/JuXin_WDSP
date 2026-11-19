import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import ApplicationDetailPage from '../ApplicationDetailPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function response(data: unknown): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

describe('ApplicationDetailPage 资产价值', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('详情页接入真实应用评分查询', async () => {
    const user: CurrentUser = {
      id: 'u1',
      username: 'asset-reader',
      display_name: '资产读取员',
      status: 'ACTIVE',
      roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
      permissions: ['applications.read', 'api_asset.read'],
      must_change_password: false,
    }
    useAuthStore.setState({ user, csrfToken: null, initialized: true })
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/applications/app-1/asset-value')) {
        return Promise.resolve(
          response({
            application_id: 'app-1',
            level: 'HIGH',
            average_score: 14.5,
            max_score: 20,
            max_total: 26,
            endpoint_count: 3,
            scored_count: 2,
            unscored_count: 1,
            level_distribution: { HIGH: 2 },
            dimensions: [],
            generated_at: '2026-11-15T04:00:00Z',
          }),
        )
      }
      if (url.endsWith('/api/v1/applications/app-1')) {
        return Promise.resolve(
          response({
            id: 'app-1',
            code: 'shop',
            name: '商城应用',
            description: '',
            status: 'DRAFT',
            protection_mode: 'OBSERVE',
            deployment_mode: 'REVERSE_PROXY',
            deployment_status: 'NOT_PUBLISHED',
            health_status: 'UNKNOWN',
            domains: [],
            upstreams: [],
            created_at: '2026-11-01T00:00:00Z',
            updated_at: '2026-11-01T00:00:00Z',
            version: 1,
          }),
        )
      }
      if (url.includes('/applications/app-1/domains')) {
        return Promise.resolve(response({ items: [] }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <QueryClientProvider client={queryClient}>
        <AntdApp>
          <MemoryRouter initialEntries={['/applications/app-1']}>
            <Routes>
              <Route
                path="/applications/:id"
                element={<ApplicationDetailPage />}
              />
            </Routes>
          </MemoryRouter>
        </AntdApp>
      </QueryClientProvider>,
    )
    expect(await screen.findByText('商城应用')).toBeInTheDocument()
    expect(
      await screen.findByText('API 资产价值（按接口评分聚合）'),
    ).toBeInTheDocument()
    const average = await screen.findByText('平均得分')
    expect(average.closest('.ant-statistic')).toHaveTextContent('14.50')
    expect(
      fetchMock.mock.calls.some((call) =>
        String(call[0]).includes(
          '/api-security/applications/app-1/asset-value',
        ),
      ),
    ).toBe(true)
    // 无 certificates.read 权限时不露出「证书绑定」页签
    expect(screen.queryByRole('tab', { name: '证书绑定' })).not.toBeInTheDocument()
  })
})
