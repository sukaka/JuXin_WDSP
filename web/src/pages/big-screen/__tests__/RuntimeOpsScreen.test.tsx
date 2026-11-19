import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import RuntimeOpsScreen from '../RuntimeOpsScreen'
import ScreenLobbyPage from '../ScreenLobbyPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../components/ScreenChart', () => ({
  default: () => <div data-testid="screen-chart-stub" />,
}))

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('RuntimeOpsScreen & ScreenLobbyPage 中文化展示', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        id: 'u1',
        username: 'ops',
        display_name: '系统管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
        permissions: ['system_health.read'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
        if (url.includes('/system-health/storage')) {
          return ok({
            disk_total_bytes: 100 * 1024 ** 3,
            disk_free_bytes: 60 * 1024 ** 3,
            postgres_size_bytes: 1024 ** 3,
            valkey_used_memory_bytes: 128 * 1024 ** 2,
            valkey_max_memory_bytes: 1024 ** 3,
            reports_size_bytes: 0,
            reports_file_count: 0,
            backups_size_bytes: 0,
            backups_file_count: 0,
            db_connections: 5,
          })
        }
        if (url.includes('/system-health')) {
          return ok({
            components: [
              { component: 'GATEWAY', status: 'UP', latency_ms: 2, taken_at: '2026-09-10T01:00:00Z' },
              { component: 'POSTGRES', status: 'DEGRADED', message: '慢查询偏高', taken_at: '2026-09-10T01:00:00Z' },
              { component: 'VALKEY', status: 'DOWN', taken_at: '2026-09-10T01:00:00Z' },
            ],
            missing_components: ['EVENT_COLLECTOR'],
          })
        }
        if (url.includes('/dashboard/runtime-overview')) {
          return ok({
            generated_at: '2026-09-10T01:00:00Z',
            gateway: { status: 'UP', uptime_seconds: 7200, snapshot_at: '2026-09-10T01:00:00Z' },
            publish: { window_days: 7, total: 10, success: 10, failed: 0, success_rate: 1, avg_duration_seconds: 2 },
            reports: { window_days: 7, total: 5, success: 5, failed: 0, success_rate: 1 },
          })
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('RuntimeOpsScreen：组件名、组件状态、缺失组件与网关状态均展示为中文', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <MemoryRouter>
        <QueryClientProvider client={qc}>
          <RuntimeOpsScreen />
        </QueryClientProvider>
      </MemoryRouter>,
    )

    expect(await screen.findByText('防护网关')).toBeInTheDocument()
    expect(screen.getByText('数据库')).toBeInTheDocument()
    expect(screen.getByText('缓存服务')).toBeInTheDocument()
    expect(screen.getByText('降级')).toBeInTheDocument()
    expect(screen.getByText('故障')).toBeInTheDocument()
    expect(screen.getAllByText('数据库 状态异常：降级（慢查询偏高）').length).toBeGreaterThan(0)
    expect(screen.getAllByText('事件采集器 缺少健康快照').length).toBeGreaterThan(0)
    // 网关状态为中文「正常」而非裸 UP
    expect(await screen.findByText('正常')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByText('GATEWAY')).not.toBeInTheDocument()
    expect(screen.queryByText('DEGRADED')).not.toBeInTheDocument()
    expect(screen.queryByText('UP')).not.toBeInTheDocument()
  })

  it('ScreenLobbyPage：展示中文副标题「九章动态安全防护」', () => {
    render(
      <MemoryRouter>
        <ScreenLobbyPage />
      </MemoryRouter>,
    )
    expect(screen.getByText(/九章动态安全防护/)).toBeInTheDocument()
    expect(screen.queryByText(/JiuZhang Dynamic Security/)).not.toBeInTheDocument()
  })
})
