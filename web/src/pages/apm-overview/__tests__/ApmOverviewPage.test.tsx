import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApmOverviewPage from '../ApmOverviewPage'
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

const OVERVIEW = {
  data_source: 'agentless',
  access_log_enabled: true,
  start_time: '2026-08-30T00:00:00Z',
  end_time: '2026-08-30T01:00:00Z',
  requests_total: 12345,
  error_5xx_total: 12,
  error_4xx_total: 340,
  blocked_total: 56,
  error_rate: 0.0285,
  latency: { p50: 12, p95: 120, p99: 380 },
  trend: [{ bucket_start: '2026-08-30T00:00:00Z', requests: 100, errors: 2, blocked: 1, p95: 110 }],
  top_slow_applications: [
    { application_id: 'svc-1', app: 'shop', name: '商城站点', requests: 5000, error_rate: 0.01, p95: 230 },
  ],
  top_error_applications: [
    { application_id: 'svc-2', app: 'pay', name: '支付网关', requests: 3000, error_rate: 0.08, p95: 150 },
  ],
  top_slow_endpoints: [
    { app: 'shop', endpoint: 'GET /api/orders', requests: 800, error_rate: 0.02, p95: 450 },
    { app: 'shop', endpoint: '__UNCLASSIFIED__', requests: 12, error_rate: 0, p95: 320 },
  ],
  unclassified_requests: 7,
}

const TRACE_ID = 'a'.repeat(32)

const TRACE_HIT = {
  trace_id: TRACE_ID,
  access_logs: [
    {
      id: 'log-1',
      occurred_at: '2026-08-30T00:30:00Z',
      request_id: 'req-1',
      application_id: 'svc-1',
      domain: 'shop.example.com',
      client_ip: '1.2.3.4',
      request_method: 'GET',
      request_path: '/api/orders/detail',
      response_status: 200,
      duration_ms: 230,
      ttfb_ms: 210,
      waf_action: 'ALLOW',
      endpoint_key: 'GET /api/orders/detail',
    },
  ],
  security_events: [
    {
      id: 'evt-1',
      occurred_at: '2026-08-30T00:30:01Z',
      request_id: 'req-1',
      application_id: 'svc-1',
      attack_type: 'SQL_INJECTION',
      severity: 'HIGH',
      action: 'BLOCK',
      response_status: 403,
      request_method: 'GET',
      request_uri: '/api/orders/detail',
      rule_match_count: 3,
      disposition_status: 'UNPROCESSED',
    },
  ],
  partial: false,
  note: '',
}

const TRACE_EMPTY = { trace_id: TRACE_ID, access_logs: [], security_events: [], partial: false, note: '' }

interface MockOptions {
  overviewStatus?: number
  overview?: unknown
  trace?: unknown
  /** true 时所有请求永不返回（加载态用例） */
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/traces/')) return ok(opts.trace ?? TRACE_HIT)
    if (url.includes('/apm/overview')) {
      const status = opts.overviewStatus ?? 200
      if (status !== 200) {
        return Promise.resolve(
          jsonResponse(status, { code: status === 403 ? 'FORBIDDEN' : 'INTERNAL', message: status === 403 ? '无权限' : '服务器错误', data: null }),
        )
      }
      return ok(opts.overview ?? OVERVIEW)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter>
          <ApmOverviewPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

function traceCalls() {
  return (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/traces/'))
}

describe('ApmOverviewPage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['apm.overview.read', 'apm.traces.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载态显示 Spin', () => {
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('正常渲染：数据来源标识、RED 指标卡与三个 Top 列表', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    // 先等待查询完成（页头 Tag 始终渲染，不能作为加载完成信号）
    await screen.findByText('商城站点')
    expect(screen.getByText('数据来源：无 Agent')).toBeInTheDocument()
    // RED 指标卡
    expect(screen.getByText('12,345')).toBeInTheDocument()
    expect(screen.getByText('2.85%')).toBeInTheDocument()
    expect(screen.getByText('120 ms')).toBeInTheDocument()
    expect(screen.getByText('56')).toBeInTheDocument()
    // 未归类请求提示
    expect(screen.getByText(/未归类请求 7 条/)).toBeInTheDocument()
    // Top 列表（__UNCLASSIFIED__ 映射为中文「未归类端点」）
    expect(screen.getByText('商城站点')).toBeInTheDocument()
    expect(screen.getByText('支付网关')).toBeInTheDocument()
    expect(screen.getByText('GET /api/orders')).toBeInTheDocument()
    expect(screen.getByText('未归类端点')).toBeInTheDocument()
    expect(screen.queryByText('__UNCLASSIFIED__')).not.toBeInTheDocument()
    // 图表角标（趋势 + 三个 Top 卡片）
    expect(screen.getAllByText('无 Agent').length).toBeGreaterThanOrEqual(4)
  })

  it('查询失败（500）展示 QueryErrorAlert', async () => {
    vi.stubGlobal('fetch', mockFetch({ overviewStatus: 500 }))
    renderPage()
    expect(await screen.findByText('加载业务性能总览失败')).toBeInTheDocument()
    expect(screen.getByText('服务器错误')).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ overviewStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('access_log_enabled=false 时慢端点区展示开启指引', async () => {
    vi.stubGlobal('fetch', mockFetch({ overview: { ...OVERVIEW, access_log_enabled: false } }))
    renderPage()
    expect(await screen.findByText('端点级数据需开启全量访问日志')).toBeInTheDocument()
    // 慢端点表被指引替换，但应用级 Top 不受影响
    expect(screen.queryByText('GET /api/orders')).not.toBeInTheDocument()
    expect(screen.getByText('商城站点')).toBeInTheDocument()
  })

  it('trace 检索命中：Drawer 展示访问记录与关联 WAF 事件', { timeout: 60000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('商城站点')

    fireEvent.change(screen.getByPlaceholderText('Trace ID（32 位十六进制）'), {
      target: { value: TRACE_ID },
    })
    fireEvent.click(screen.getByRole('button', { name: /检\s*索/ }))

    expect(await screen.findByText('/api/orders/detail')).toBeInTheDocument()
    expect(screen.getByText(/关联 WAF 事件/)).toBeInTheDocument()
    expect(screen.getByText('阻断')).toBeInTheDocument()
    expect(screen.getByText('SQL注入')).toBeInTheDocument()
    expect(screen.getByText('高')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('未处置')).toBeInTheDocument()
    expect(screen.getByText('req-1')).toBeInTheDocument()
    expect(traceCalls()).toHaveLength(1)
    // P1-01 A3：详情查询携带页面当前时间窗上下文（start_time/end_time）
    const traceUrl = String(traceCalls()[0][0])
    expect(traceUrl.startsWith(`/api/v1/apm/traces/${TRACE_ID}?`)).toBe(true)
    expect(traceUrl).toContain('start_time=')
    expect(traceUrl).toContain('end_time=')
  })

  it('trace 空结果显示未命中提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ trace: TRACE_EMPTY }))
    renderPage()
    await screen.findByText('商城站点')

    fireEvent.change(screen.getByPlaceholderText('Trace ID（32 位十六进制）'), {
      target: { value: TRACE_ID },
    })
    fireEvent.click(screen.getByRole('button', { name: /检\s*索/ }))

    expect(await screen.findByText('未命中，可能未采样或已超保留期')).toBeInTheDocument()
  })

  it('trace ID 格式非法时仅提示，不发起检索请求', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('商城站点')

    fireEvent.change(screen.getByPlaceholderText('Trace ID（32 位十六进制）'), {
      target: { value: 'not-a-trace-id' },
    })
    fireEvent.click(screen.getByRole('button', { name: /检\s*索/ }))

    expect(await screen.findByText('Trace ID 格式不正确（应为 32 位十六进制字符）')).toBeInTheDocument()
    expect(traceCalls()).toHaveLength(0)
  })

  it('无 apm.traces.read 权限时不渲染 trace 检索入口', async () => {
    vi.stubGlobal('fetch', mockFetch())
    useAuthStore.setState({
      user: makeUser(['apm.overview.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('商城站点')
    expect(screen.queryByPlaceholderText('Trace ID（32 位十六进制）')).not.toBeInTheDocument()
  })
})
