import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SystemMonitoringPage from '../SystemMonitoringPage'

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <SystemMonitoringPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('SystemMonitoringPage 运行监控中文化展示', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/dashboard/runtime-overview')) {
          return Promise.resolve(
            jsonResponse({
              gateway: { status: 'UP', uptime_seconds: 7200 },
              publish: { window_days: 30, success_rate: 1 },
              reports: { window_days: 30, success: 3, failed: 0 },
            }),
          )
        }
        if (url.includes('/system-health/components')) {
          return Promise.resolve(
            jsonResponse({
              checked_at: '2026-10-20T08:00:00Z',
              components: [
                {
                  component: 'POSTGRES',
                  status: 'UP',
                  latency_ms: 4,
                  metrics: {
                    database_size_bytes: 2 * 1024 * 1024,
                    db_connections: 12,
                    software_bypass_enabled: false,
                    checkpoints: { access: 100 },
                  },
                },
                {
                  component: 'VALKEY',
                  status: 'DEGRADED',
                  latency_ms: 8,
                  metrics: {
                    used_memory_bytes: 1024,
                    software_bypass_active: true,
                  },
                },
              ],
            }),
          )
        }
        if (url.includes('/system-health')) {
          return Promise.resolve(
            jsonResponse({
              status: 'DEGRADED',
              checked_at: '2026-10-20T08:00:00Z',
              components: [],
              missing_components: [],
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('网关状态使用中文标签，组件指标键映射中文、字节/布尔/结构化对象均格式化展示', async () => {
    renderPage()

    // 网关状态 Statistic 展示中文「正常」而非英文 UP
    const gatewayStat = (await screen.findByText('网关状态')).closest('.ant-statistic')!
    expect(gatewayStat.textContent).toContain('正常')
    expect(gatewayStat.textContent).not.toContain('UP')

    // 指标键中文映射 + *_bytes 格式化 + boolean 映射 是/否 + 对象 JSON 序列化
    expect(await screen.findByText('数据库大小：2.00 MB')).toBeInTheDocument()
    expect(screen.getByText('数据库连接数：12')).toBeInTheDocument()
    expect(screen.getByText('自动软件旁路开关：否')).toBeInTheDocument()
    expect(screen.getByText('采集检查点：{"access":100}')).toBeInTheDocument()
    expect(screen.getByText('已用内存：1.00 KB')).toBeInTheDocument()
    expect(screen.getByText('软件旁路状态：是')).toBeInTheDocument()
    expect(screen.queryByText(/\[object Object\]/)).not.toBeInTheDocument()
    expect(screen.queryByText(/database_size_bytes/)).not.toBeInTheDocument()
  })
})
