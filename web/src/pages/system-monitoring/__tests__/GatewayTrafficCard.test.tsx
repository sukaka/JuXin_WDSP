import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import GatewayTrafficCard from '../GatewayTrafficCard'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, GatewayTrendResponse, RuntimeComponent } from '../../../types'

vi.mock('../../../components/EChart', () => ({
  default: ({ ariaLabel }: { ariaLabel: string }) => (
    <div data-testid="echart-stub" aria-label={ariaLabel} />
  ),
}))

function gateway(metrics: Record<string, unknown>): RuntimeComponent {
  return { component: 'GATEWAY', status: 'UP', metrics }
}

function gatewayCard(metrics: Record<string, unknown>) {
  return <GatewayTrafficCard gateway={gateway(metrics)} />
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(
    JSON.stringify(status === 200 ? { code: 'SUCCESS', message: 'ok', data } : data),
    {
      status,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function sampleTrend(range: '10m' | '1h' | '6h' | '24h' = '10m'): GatewayTrendResponse {
  return {
    range,
    source: range === '10m' ? 'gateway_live' : 'database',
    interval_seconds: range === '10m' ? 2 : 30,
    generated_at: '2026-11-24T06:00:00Z',
    node: 'gw-node-1',
    current: {
      status: 'UP',
      latency_ms: 3,
      taken_at: '2026-11-24T06:00:00Z',
      cpu_percent: 42.3,
      memory_percent: 58.6,
      memory_used_bytes: 8 * 1024 ** 3,
      memory_total_bytes: 16 * 1024 ** 3,
      load1: 1.25,
      load5: 1.1,
      load15: 0.95,
      fd_open: 1024,
      fd_max: 65535,
      fd_usage_percent: 1.6,
      tcp_connections_active: 88,
      tcp_connections_accepted_total: 9800,
      tcp_connections_accepted_per_second: 19.5,
      bytes_in_total: 100 * 1024 ** 2,
      bytes_out_total: 500 * 1024 ** 2,
      bytes_in_per_second: 256 * 1024,
      bytes_out_per_second: 2.5 * 1024 ** 2,
      http_requests_in_flight: 14,
      http_requests_total: 120000,
      http_requests_per_second: 245.6,
      http_sessions_active: 312,
      http_sessions_new_total: 5600,
      http_sessions_new_per_second: 12.4,
      http_sessions_overflow_total: 0,
      http_sessions_capacity: 10000,
      status_2xx_total: 110000,
      status_3xx_total: 6000,
      status_4xx_total: 3500,
      status_5xx_total: 500,
      status_2xx_per_second: 220.1,
      status_3xx_per_second: 12.0,
      status_4xx_per_second: 11.5,
      status_5xx_per_second: 2.0,
      software_bypass: {
        enabled: true,
        active: false,
        cpu_threshold_percent: 85,
        memory_threshold_percent: 85,
      },
      tcp_states: {
        established: 70,
        time_wait: 12,
        close_wait: 1,
        syn_recv: 2,
        fin_wait: 3,
        listen: 4,
        other: 0,
      },
    },
    summary: {
      peak_tcp_connections_active: 120,
      avg_tcp_connections_active: 76.4,
      peak_tcp_connections_accepted_per_second: 32.1,
      peak_http_sessions_active: 410,
      peak_http_sessions_new_per_second: 18.2,
      peak_http_requests_per_second: 310.5,
      peak_bytes_in_per_second: 512 * 1024,
      peak_bytes_out_per_second: 4 * 1024 ** 2,
      peak_cpu_percent: 62.5,
      peak_memory_percent: 64.0,
      bypass_active_points: 0,
    },
    points: [
      {
        taken_at: '2026-11-24T05:59:56Z',
        cpu_percent: 40.1,
        memory_percent: 58.1,
        load1: 1.2,
        fd_usage_percent: 1.5,
        tcp_connections_active: 80,
        tcp_connections_accepted_per_second: 18.0,
        bytes_in_per_second: 200 * 1024,
        bytes_out_per_second: 2.1 * 1024 ** 2,
        http_requests_in_flight: 11,
        http_requests_per_second: 230.0,
        http_sessions_active: 300,
        http_sessions_new_per_second: 11.2,
        status_2xx_per_second: 208.0,
        status_3xx_per_second: 10.0,
        status_4xx_per_second: 10.0,
        status_5xx_per_second: 2.0,
        software_bypass_active: false,
      },
      {
        taken_at: '2026-11-24T05:59:58Z',
        cpu_percent: 42.3,
        memory_percent: 58.6,
        load1: 1.25,
        fd_usage_percent: 1.6,
        tcp_connections_active: 88,
        tcp_connections_accepted_per_second: 19.5,
        bytes_in_per_second: 256 * 1024,
        bytes_out_per_second: 2.5 * 1024 ** 2,
        http_requests_in_flight: 14,
        http_requests_per_second: 245.6,
        http_sessions_active: 312,
        http_sessions_new_per_second: 12.4,
        status_2xx_per_second: 220.1,
        status_3xx_per_second: 12.0,
        status_4xx_per_second: 11.5,
        status_5xx_per_second: 2.0,
        software_bypass_active: false,
      },
    ],
    applications: [
      {
        app_id: 'app-1',
        app_code: 'shop-api',
        app_name: '商城核心接口',
        requests_in_flight: 9,
        requests_total: 88000,
        requests_per_second: 162.4,
        bypassed_requests_total: 0,
        bytes_in_total: 60 * 1024 ** 2,
        bytes_out_total: 320 * 1024 ** 2,
        bytes_in_per_second: 180 * 1024,
        bytes_out_per_second: 1.8 * 1024 ** 2,
        status_4xx_total: 120,
        status_5xx_total: 8,
      },
    ],
  }
}

describe('GatewayTrafficCard', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('展示真实连接、会话、资源指标和旁路风险提示', () => {
    render(
      gatewayCard({
        cpu_usage_percent: 81.52,
        memory_usage_percent: 82.1,
        tcp_connections_active: 12,
        tcp_connections_accepted_total: 1200,
        tcp_connections_accepted_per_second: 34.5,
        http_sessions_active: 8,
        http_sessions_new_total: 100,
        http_requests_in_flight: 3,
        software_bypass_enabled: true,
        software_bypass_active: true,
        software_bypass_reason: 'CPU_THRESHOLD',
        software_bypass_cpu_threshold_percent: 80,
        software_bypass_memory_threshold_percent: 80,
      }),
    )
    expect(screen.getByText('旁路中（未检测）')).toBeInTheDocument()
    expect(screen.getByText(/CPU 超过阈值/)).toBeInTheDocument()
    const values = Array.from(document.querySelectorAll('.ant-statistic-content-value')).map(
      (node) => node.textContent,
    )
    expect(values).toEqual(expect.arrayContaining(['81.5', '12', '34.50', '1,200']))
    expect(
      screen.getByText(/访问控制、CC、Bot、API 动态防护与 WAF 均已跳过/),
    ).toBeInTheDocument()
    expect(screen.getByText(/常态统计，5\s*分钟空闲后不计为活跃/)).toBeInTheDocument()
  })

  it('未启用时保持正常状态，零值按零展示', () => {
    render(
      gatewayCard({
        tcp_connections_active: 0,
        tcp_connections_accepted_total: 0,
        http_sessions_active: 0,
        software_bypass_enabled: false,
        software_bypass_active: false,
      }),
    )
    expect(screen.getByText('自动旁路未启用')).toBeInTheDocument()
    expect(screen.queryByText(/当前为纯透传/)).not.toBeInTheDocument()
    expect(screen.getAllByText('0').length).toBeGreaterThanOrEqual(3)
  })

  it('旧版网关无运行指标时不渲染卡片', () => {
    const { container } = render(gatewayCard({ config_hash: 'abc' }))
    expect(container).toBeEmptyDOMElement()
  })

  it('拉取 gateway-trend 展示 4 张趋势图、状态分布、应用负载并支持切换时间窗与有权限时跳转大屏', async () => {
    useAuthStore.setState({
      user: {
        id: 'u-oper',
        username: 'operadmin',
        display_name: '运维管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SECURITY_ADMIN', name: '运维管理员' }],
        permissions: ['big_screen.runtime.read'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: null,
      initialized: true,
    })
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('range=1h')) {
        return Promise.resolve(jsonResponse(sampleTrend('1h')))
      }
      return Promise.resolve(jsonResponse(sampleTrend('10m')))
    })
    vi.stubGlobal('fetch', fetchMock)

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <MemoryRouter initialEntries={['/system-monitoring']}>
        <QueryClientProvider client={qc}>
          <Routes>
            <Route
              path="/system-monitoring"
              element={gatewayCard({ tcp_connections_active: 10, software_bypass_enabled: true })}
            />
            <Route
              path="/big-screen/gateway-connections"
              element={<div data-testid="gateway-big-screen-page">大屏已进入</div>}
            />
          </Routes>
        </QueryClientProvider>
      </MemoryRouter>,
    )

    expect(await screen.findByText('实时 2s 采样')).toBeInTheDocument()
    expect(screen.getAllByTestId('echart-stub')).toHaveLength(4)
    expect(screen.getByText('256 KB/s')).toBeInTheDocument()
    expect(screen.getByText('2.50 MB/s')).toBeInTheDocument()
    expect(screen.getByText('1.25 / 1.10 / 0.95')).toBeInTheDocument()
    expect(screen.getByText('ESTABLISHED（已建立）')).toBeInTheDocument()
    expect(screen.getByText('2xx 成功')).toBeInTheDocument()
    expect(screen.getByText('商城核心接口')).toBeInTheDocument()

    // 切换时间窗口到 近 1 小时
    fireEvent.click(screen.getByText('近 1 小时'))
    expect(await screen.findByText('历史 30s 采样')).toBeInTheDocument()
    await waitFor(() => {
      expect(fetchMock.mock.calls.some((args) => String(args[0]).includes('range=1h'))).toBe(true)
    })

    // 点击快捷按钮进入大屏
    fireEvent.click(screen.getByRole('button', { name: /进入大屏监控/ }))
    expect(await screen.findByTestId('gateway-big-screen-page')).toBeInTheDocument()
  })

  it('系统管理员（无 big_screen.runtime.read）在运行监控页不显示「进入大屏监控」按钮', () => {
    useAuthStore.setState({
      user: {
        id: 'u-sys',
        username: 'admin',
        display_name: '系统管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
        permissions: ['system_health.read', 'dashboard.runtime.read'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: null,
      initialized: true,
    })

    render(
      <MemoryRouter>
        {gatewayCard({ tcp_connections_active: 12, software_bypass_enabled: false })}
      </MemoryRouter>,
    )

    expect(screen.queryByRole('button', { name: /进入大屏监控/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /进入大屏监控/ })).not.toBeInTheDocument()
  })

  it('趋势接口失败时平滑降级到 gateway.metrics 并提示友好告警', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(jsonResponse({ code: 'INTERNAL_ERROR', message: 'boom' }, 500)),
      ),
    )

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          {gatewayCard({
            cpu_usage_percent: 33.4,
            tcp_connections_active: 42,
            http_sessions_active: 15,
            software_bypass_enabled: false,
            software_bypass_active: false,
          })}
        </QueryClientProvider>
      </MemoryRouter>,
    )

    expect(
      await screen.findByText('趋势数据暂不可用，已自动降级为当前快照指标展示'),
    ).toBeInTheDocument()
    const values = Array.from(document.querySelectorAll('.ant-statistic-content-value')).map(
      (node) => node.textContent,
    )
    expect(values).toEqual(expect.arrayContaining(['33.4', '42', '15']))
    expect(screen.queryAllByTestId('echart-stub')).toHaveLength(0)
  })
})
