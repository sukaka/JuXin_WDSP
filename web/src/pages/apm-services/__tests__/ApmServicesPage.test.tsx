import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApmServicesPage from '../ApmServicesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为桩组件 */
vi.mock('../../../components/EChart', () => ({
  default: () => <div data-testid="echart-stub" />,
}))

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
      error_rate: 0.125,
      blocked: 3,
      p50: 10,
      p95: 120,
      p99: 300,
      last_seen_at: '2026-08-30T01:00:00Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 1,
}

const SERVICE_DETAIL = {
  application_id: 'svc-1',
  app: 'shop',
  name: '商城站点',
  observation_mode: 'agentless',
  requests_total: 5000,
  error_rate: 0.125,
  latency: { p50: 10, p95: 120, p99: 300 },
  trend: [{ bucket_start: '2026-08-30T00:00:00Z', requests: 100, errors: 1, blocked: 0, p95: 110 }],
  status_classes: [
    { status_class: '2xx', count: 4900 },
    { status_class: '5xx', count: 100 },
  ],
  actions: [
    { action: 'ALLOW', count: 4997 },
    { action: 'BLOCK', count: 3 },
  ],
  top_endpoints: [{ endpoint: 'GET /api/orders', requests: 800, error_rate: 0.02, p95: 450 }],
}

interface MockOptions {
  listStatus?: number
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/services/')) return ok(SERVICE_DETAIL)
    if (url.includes('/apm/services')) {
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
      return ok(SERVICES)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <ApmServicesPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApmServicesPage', () => {
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

  it('正常渲染服务行：名称/编码、观测模式、RED 与分位数', async () => {
    renderPage()
    const row = (await screen.findByText('商城站点')).closest('tr')!
    expect(row.textContent).toContain('shop')
    expect(row.textContent).toContain('无 Agent')
    expect(row.textContent).toContain('5000')
    expect(row.textContent).toContain('12.50%')
    expect(row.textContent).toContain('10 ms')
    expect(row.textContent).toContain('120 ms')
    expect(row.textContent).toContain('300 ms')
    // 页头数据来源标识
    expect(screen.getByText('数据来源：无 Agent')).toBeInTheDocument()
  })

  it('行点击打开详情抽屉：趋势、状态码分布、WAF 动作分布与 Top 端点', async () => {
    renderPage()
    const row = (await screen.findByText('商城站点')).closest('tr')!
    fireEvent.click(row)

    expect(await screen.findByText('服务性能详情')).toBeInTheDocument()
    expect(await screen.findByText('状态码分布')).toBeInTheDocument()
    expect(screen.getByText('WAF 动作分布')).toBeInTheDocument()
    expect(screen.getByText('Top 端点')).toBeInTheDocument()
    expect(screen.getByText('GET /api/orders')).toBeInTheDocument()
  })

  it('查询失败（500）展示 QueryErrorAlert', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 500 }))
    renderPage()
    expect(await screen.findByText('加载服务性能列表失败')).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })
})
