import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
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

  it('有 api_asset.read 权限时以独立页签按需加载资产价值且不嵌套 Card', async () => {
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
            dimensions: [
              { name: 'data_sensitivity', average_score: 2.5, max: 4 },
            ],
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

    // 首屏默认在「域名管理」页签，露出「API 资产价值」页签但不渲染独立卡片也不提前请求
    const assetValueTab = screen.getByRole('tab', { name: 'API 资产价值' })
    expect(assetValueTab).toBeInTheDocument()
    expect(
      screen.queryByText('API 资产价值（按接口评分聚合）'),
    ).not.toBeInTheDocument()
    expect(screen.queryByText('平均得分')).not.toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some((call) =>
        String(call[0]).includes(
          '/api-security/applications/app-1/asset-value',
        ),
      ),
    ).toBe(false)
    // 无 certificates.read 权限时不露出「证书绑定」页签
    expect(screen.queryByRole('tab', { name: '证书绑定' })).not.toBeInTheDocument()

    // 点击「API 资产价值」页签后才触发查询并渲染嵌入式聚合指标与中文维度
    fireEvent.click(assetValueTab)
    const average = await screen.findByText('平均得分')
    expect(average.closest('.ant-statistic')).toHaveTextContent('14.50')
    expect(screen.getByText('数据敏感度')).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some((call) =>
        String(call[0]).includes(
          '/api-security/applications/app-1/asset-value',
        ),
      ),
    ).toBe(true)
    const tabPanel = average.closest('[role="tabpanel"]')
    expect(tabPanel).not.toBeNull()
    expect(tabPanel?.querySelector('.ant-card')).toBeNull()
    expect(
      screen.queryByText('API 资产价值（按接口评分聚合）'),
    ).not.toBeInTheDocument()
  })

  it('无 api_asset.read 权限时不露出「API 资产价值」页签且不触发资产价值查询', async () => {
    const user: CurrentUser = {
      id: 'u2',
      username: 'app-reader',
      display_name: '应用只读员',
      status: 'ACTIVE',
      roles: [{ code: 'AUDITOR', name: '审计员' }],
      permissions: ['applications.read', 'domains.read'],
      must_change_password: false,
    }
    useAuthStore.setState({ user, csrfToken: null, initialized: true })
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/api/v1/applications/app-2')) {
        return Promise.resolve(
          response({
            id: 'app-2',
            code: 'portal',
            name: '门户应用',
            description: '',
            status: 'ACTIVE',
            protection_mode: 'PROTECT',
            deployment_mode: 'REVERSE_PROXY',
            deployment_status: 'PUBLISHED',
            health_status: 'HEALTHY',
            domains: [],
            upstreams: [],
            created_at: '2026-11-01T00:00:00Z',
            updated_at: '2026-11-01T00:00:00Z',
            version: 1,
          }),
        )
      }
      if (url.includes('/applications/app-2/domains')) {
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
          <MemoryRouter initialEntries={['/applications/app-2']}>
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
    expect(await screen.findByText('门户应用')).toBeInTheDocument()
    expect(
      screen.queryByRole('tab', { name: 'API 资产价值' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText('API 资产价值（按接口评分聚合）'),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByText('缺少「API 资产查看」权限，无法查看应用资产价值'),
    ).not.toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some((call) => String(call[0]).includes('/asset-value')),
    ).toBe(false)
  })

  it('TRANSPARENT 透明串接应用展示部署引导横幅并向域名/源站页签透传部署模式', async () => {
    const user: CurrentUser = {
      id: 'u1',
      username: 'ops',
      display_name: '运维管理员',
      status: 'ACTIVE',
      roles: [{ code: 'OPS_ADMIN', name: '运维管理员' }],
      permissions: ['applications.read', 'domains.read', 'upstreams.read'],
      must_change_password: false,
    }
    useAuthStore.setState({ user, csrfToken: null, initialized: true })
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/api/v1/applications/app-tp')) {
        return Promise.resolve(
          response({
            id: 'app-tp',
            code: 'tproxy-app',
            name: '透明业务应用',
            description: '',
            status: 'ACTIVE',
            protection_mode: 'PROTECT',
            deployment_mode: 'TRANSPARENT',
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
      if (url.includes('/applications/app-tp/domains')) {
        return Promise.resolve(response({ items: [] }))
      }
      if (url.includes('/applications/app-tp/upstreams')) {
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
          <MemoryRouter initialEntries={['/applications/app-tp']}>
            <Routes>
              <Route path="/applications/:id" element={<ApplicationDetailPage />} />
            </Routes>
          </MemoryRouter>
        </AntdApp>
      </QueryClientProvider>,
    )
    expect(await screen.findByText('透明业务应用')).toBeInTheDocument()
    expect(
      screen.getByText('当前应用为透明串接模式（二层桥接在线检测与阻断）'),
    ).toBeInTheDocument()
    expect(screen.getByText(/已在「网络配置」完成网桥配置/)).toBeInTheDocument()
    expect(screen.getByText(/至少 1 个已启用的源站服务器/)).toBeInTheDocument()
    // 域名页签收到 deploymentMode='TRANSPARENT' 并展示域名与端口说明
    expect(await screen.findByText('透明串接域名与目标端口说明')).toBeInTheDocument()
    // 无 ai_crawl.read 权限时不露出「AI 爬虫治理」页签
    expect(screen.queryByRole('tab', { name: 'AI 爬虫治理' })).not.toBeInTheDocument()
    // 无 client_side.read 权限时不露出「客户端供应链安全」页签
    expect(screen.queryByRole('tab', { name: '客户端供应链安全' })).not.toBeInTheDocument()
  })

  it('有 ai_crawl.read 与 client_side.read 权限时露出对应页签', async () => {
    const user: CurrentUser = {
      id: 'u3',
      username: 'crawl-reader',
      display_name: '爬虫治理员',
      status: 'ACTIVE',
      roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
      permissions: ['applications.read', 'ai_crawl.read', 'client_side.read'],
      must_change_password: false,
    }
    useAuthStore.setState({ user, csrfToken: null, initialized: true })
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.endsWith('/api/v1/applications/app-1')) {
        return Promise.resolve(
          response({
            id: 'app-1',
            code: 'shop',
            name: '商城应用',
            description: '',
            status: 'ACTIVE',
            protection_mode: 'PROTECT',
            deployment_mode: 'REVERSE_PROXY',
            deployment_status: 'PUBLISHED',
            health_status: 'HEALTHY',
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
    expect(screen.getByRole('tab', { name: 'AI 爬虫治理' })).toBeInTheDocument()
    expect(
      screen.getByRole('tab', { name: '客户端供应链安全' }),
    ).toBeInTheDocument()
  })
})
