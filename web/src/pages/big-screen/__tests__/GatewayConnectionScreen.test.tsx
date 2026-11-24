import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import GatewayConnectionScreen from '../GatewayConnectionScreen'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, GatewayTrendResponse } from '../../../types'

const capturedOptions: unknown[] = []

vi.mock('../components/ScreenChart', () => ({
  default: ({ option }: { option: unknown }) => {
    capturedOptions.push(option)
    return <div data-testid="screen-chart-stub" />
  },
}))

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderScreen() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <GatewayConnectionScreen />
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

function mockTrend(range: '10m' | '1h' | '6h' | '24h', overrides?: Partial<GatewayTrendResponse>): GatewayTrendResponse {
  return {
    range,
    source: range === '10m' ? 'gateway_live' : 'database',
    interval_seconds: range === '10m' ? 2 : 30,
    generated_at: '2026-11-24T06:00:00Z',
    node: 'gateway-prod-01',
    current: {
      status: 'UP',
      latency_ms: 2,
      taken_at: '2026-11-24T06:00:00Z',
      cpu_percent: 45.2,
      memory_percent: 61.8,
      load1: 1.45,
      load5: 1.32,
      load15: 1.2,
      fd_open: 2048,
      fd_max: 65535,
      fd_usage_percent: 3.1,
      tcp_connections_active: 256,
      tcp_connections_accepted_total: 18500,
      tcp_connections_accepted_per_second: 42.5,
      bytes_in_total: 512 * 1024 ** 2,
      bytes_out_total: 2 * 1024 ** 3,
      bytes_in_per_second: 1.5 * 1024 ** 2,
      bytes_out_per_second: 4.5 * 1024 ** 2,
      http_requests_in_flight: 18,
      http_requests_total: 98000,
      http_requests_per_second: 312.4,
      http_sessions_active: 640,
      http_sessions_new_total: 9200,
      http_sessions_new_per_second: 15.8,
      http_sessions_overflow_total: 0,
      http_sessions_capacity: 10000,
      status_2xx_total: 90000,
      status_3xx_total: 4000,
      status_4xx_total: 3200,
      status_5xx_total: 800,
      status_2xx_per_second: 290,
      status_3xx_per_second: 10,
      status_4xx_per_second: 10.4,
      status_5xx_per_second: 2,
      software_bypass: {
        enabled: true,
        active: false,
        cpu_threshold_percent: 85,
        memory_threshold_percent: 85,
      },
      tcp_states: {
        established: 200,
        time_wait: 40,
        close_wait: 2,
        syn_recv: 5,
        fin_wait: 6,
        listen: 3,
        other: 0,
      },
    },
    summary: {
      peak_tcp_connections_active: 310,
      avg_tcp_connections_active: 224.5,
      peak_tcp_connections_accepted_per_second: 58.2,
      peak_http_sessions_active: 720,
      peak_http_sessions_new_per_second: 22.4,
      peak_http_requests_per_second: 380.6,
      peak_bytes_in_per_second: 2 * 1024 ** 2,
      peak_bytes_out_per_second: 6 * 1024 ** 2,
      peak_cpu_percent: 58.0,
      peak_memory_percent: 64.5,
      bypass_active_points: 0,
    },
    points: [
      {
        taken_at: '2026-11-24T05:59:58Z',
        cpu_percent: 45.2,
        memory_percent: 61.8,
        load1: 1.45,
        fd_usage_percent: 3.1,
        tcp_connections_active: 256,
        tcp_connections_accepted_per_second: 42.5,
        bytes_in_per_second: 1.5 * 1024 ** 2,
        bytes_out_per_second: 4.5 * 1024 ** 2,
        http_requests_in_flight: 18,
        http_requests_per_second: 312.4,
        http_sessions_active: 640,
        http_sessions_new_per_second: 15.8,
        status_2xx_per_second: 290,
        status_3xx_per_second: 10,
        status_4xx_per_second: 10.4,
        status_5xx_per_second: 2,
        software_bypass_active: false,
      },
    ],
    applications: [
      {
        app_id: 'prod-1',
        app_code: 'pay-core',
        app_name: '支付核心网关',
        requests_in_flight: 12,
        requests_total: 64000,
        requests_per_second: 210.5,
        bypassed_requests_total: 0,
        bytes_in_total: 300 * 1024 ** 2,
        bytes_out_total: 1.2 * 1024 ** 3,
        bytes_in_per_second: 900 * 1024,
        bytes_out_per_second: 3.1 * 1024 ** 2,
        status_4xx_total: 50,
        status_5xx_total: 3,
      },
    ],
    ...overrides,
  }
}

describe('GatewayConnectionScreen 网关连接与会话大屏', () => {
  beforeEach(() => {
    capturedOptions.length = 0
    useAuthStore.setState({
      user: {
        id: 'u1',
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
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('正常加载真实数据时展示 KPI、实时采样标识与时间窗口切换', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('range=24h')) {
        return Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data: mockTrend('24h') }))
      }
      return Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data: mockTrend('10m') }))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderScreen()

    expect(await screen.findByText('节点：gateway-prod-01')).toBeInTheDocument()
    expect(screen.getByText('实时 2s 采样')).toBeInTheDocument()
    expect(screen.getByText('每 5s 自动刷新')).toBeInTheDocument()
    expect(screen.getByText('自动保护中')).toBeInTheDocument()
    expect(screen.getByText(/峰值 310/)).toBeInTheDocument()
    expect(screen.getByText(/入峰 2\.00 MB\/s · 出峰 6\.00 MB\/s/)).toBeInTheDocument()
    expect(screen.getByText(/入 1\.50 MB\/s · 出 4\.50 MB\/s/)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByText(/演示数据/)).not.toBeInTheDocument()

    // 切换到近 24h，刷新周期切换为 30s，数据源标签更新为历史 30s 采样
    fireEvent.click(screen.getByRole('button', { name: '近 24h' }))
    expect(await screen.findByText('历史 30s 采样')).toBeInTheDocument()
    expect(screen.getByText('每 30s 自动刷新')).toBeInTheDocument()
    await waitFor(() => {
      expect(fetchMock.mock.calls.some((args) => String(args[0]).includes('range=24h'))).toBe(true)
    })
  })

  it('查询成功且 points 为空时图表区使用演示数据兜底并展示演示角标，KPI 保持真实值', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse({
            code: 'SUCCESS',
            message: 'ok',
            data: mockTrend('10m', { current: null, summary: null, points: [], applications: [] }),
          }),
        ),
      ),
    )

    renderScreen()

    expect(await screen.findByText(/演示数据：当前无真实采样数据/)).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    // KPI 保持真实值 0（软件旁路状态为未启用），不被演示数据覆盖
    expect(screen.getByText('未启用')).toBeInTheDocument()
    const kpiValues = Array.from(document.querySelectorAll('.bs-kpi-value')).map((n) => n.textContent)
    expect(kpiValues[0]).toBe('0')
    expect(kpiValues[4]).toContain('0.0')
    // 图表区拿到演示数据（包含 demo- 应用排行）
    expect(JSON.stringify(capturedOptions)).toContain('demo-商城门户')
  })

  it('查询失败时展示降级提示条且绝不静默切换演示数据', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(jsonResponse({ code: 'INTERNAL_ERROR', message: 'gateway down' }, 500)),
      ),
    )

    renderScreen()

    expect(await screen.findByRole('alert')).toHaveTextContent('部分数据接口加载失败')
    expect(screen.queryByText(/演示数据/)).not.toBeInTheDocument()
    expect(JSON.stringify(capturedOptions)).not.toContain('demo-商城门户')
    expect(screen.getByText('当前节点未提供 TCP 状态细分')).toBeInTheDocument()
    expect(screen.getByText('暂无按站点实时负载数据')).toBeInTheDocument()
  })

  it('软件旁路激活时大屏清晰展示旁路透传中与触发原因', async () => {
    const base = mockTrend('10m')
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse({
            code: 'SUCCESS',
            message: 'ok',
            data: {
              ...base,
              current: {
                ...base.current!,
                software_bypass: {
                  enabled: true,
                  active: true,
                  reason: 'CPU_THRESHOLD',
                  cpu_threshold_percent: 80,
                  memory_threshold_percent: 80,
                },
              },
            },
          }),
        ),
      ),
    )

    renderScreen()

    expect(await screen.findByText('旁路透传中')).toBeInTheDocument()
    expect(screen.getByText('CPU 超过阈值')).toBeInTheDocument()
  })
})
