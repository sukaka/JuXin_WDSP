import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApmEndpointsPage from '../ApmEndpointsPage'
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

const SERVICES = {
  items: [
    {
      application_id: 'svc-1',
      app: 'shop',
      name: '商城站点',
      observation_mode: 'agentless',
      requests: 5000,
      error_rate: 0.01,
      blocked: 3,
      p50: 10,
      p95: 120,
      p99: 300,
      last_seen_at: '2026-08-30T01:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const ENDPOINTS = {
  list: [
    {
      app: 'shop',
      application_id: 'svc-1',
      endpoint: 'GET /api/orders',
      method: 'GET',
      path_template: '/api/orders',
      requests: 800,
      error_rate: 0.02,
      blocked: 1,
      p50: 20,
      p95: 450,
      p99: 900,
      last_seen_at: '2026-08-30T01:00:00Z',
    },
    {
      app: 'shop',
      application_id: 'svc-1',
      endpoint: '__UNCLASSIFIED__',
      method: '',
      path_template: '',
      requests: 7,
      error_rate: 0,
      blocked: 0,
      p50: 5,
      p95: 30,
      p99: 60,
      last_seen_at: '2026-08-30T01:00:00Z',
    },
    {
      app: 'shop',
      application_id: 'svc-1',
      endpoint: '__OTHER__',
      method: '',
      path_template: '',
      requests: 300,
      error_rate: 0.01,
      blocked: 0,
      p50: 8,
      p95: 40,
      p99: 80,
      last_seen_at: '2026-08-30T01:00:00Z',
    },
  ],
  total: 3,
  page: 1,
  page_size: 20,
  access_log_enabled: true,
}

interface MockOptions {
  listStatus?: number
  endpoints?: unknown
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/services')) return ok(SERVICES)
    if (url.includes('/apm/endpoints')) {
      const status = opts.listStatus ?? 200
      if (status !== 200) {
        return Promise.resolve(
          jsonResponse(status, {
            code: status === 403 ? 'FORBIDDEN' : 'INTERNAL',
            message: status === 403 ? '无权限' : '服务器错误',
            data: null,
          }),
        )
      }
      return ok(opts.endpoints ?? ENDPOINTS)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <ApmEndpointsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApmEndpointsPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
    useAuthStore.setState({
      user: makeUser(['apm.services.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载态表格显示 Spin', () => {
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('正常渲染端点行：特殊桶标注「未归类端点」与「其它（超出 Top-N）」', async () => {
    renderPage()
    expect(await screen.findByText('GET /api/orders')).toBeInTheDocument()
    expect(screen.getByText('未归类端点')).toBeInTheDocument()
    expect(screen.getByText('其它（超出 Top-N）')).toBeInTheDocument()
    expect(screen.getAllByText('shop').length).toBeGreaterThanOrEqual(1)
    // 页头数据来源标识
    expect(screen.getByText('数据来源：无 Agent')).toBeInTheDocument()
  })

  it('应用下拉数据源为 /apm/services?page_size=100', async () => {
    renderPage()
    await screen.findByText('GET /api/orders')
    const serviceCalls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/services'))
    expect(serviceCalls).toHaveLength(1)
    expect(String(serviceCalls[0][0])).toContain('page_size=100')
  })

  it('access_log_enabled=false 时整页展示开启指引，不渲染表格', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ endpoints: { list: [], total: 0, page: 1, page_size: 20, access_log_enabled: false } }),
    )
    renderPage()
    expect(await screen.findByText('端点级数据需开启全量访问日志')).toBeInTheDocument()
    expect(screen.queryByText('GET /api/orders')).not.toBeInTheDocument()
  })

  it('查询失败（500）展示 QueryErrorAlert', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 500 }))
    renderPage()
    expect(await screen.findByText('加载端点性能列表失败')).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })
})
