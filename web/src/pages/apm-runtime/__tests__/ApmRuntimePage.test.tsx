import { afterEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApmRuntimePage from '../ApmRuntimePage'

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为桩组件 */
vi.mock('../../../components/EChart', () => ({
  default: () => <div data-testid="echart-stub" />,
}))

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
      observation_mode: 'agent',
      agents_online: 1,
      agents_total: 1,
      requests: 5000,
      error_rate: 0.01,
      blocked: 0,
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

const RUNTIME = {
  data_source: 'otel',
  note: '不同语言运行时指标集不同，按 Agent 实际上报如实展示',
  instances: [
    {
      instance_id: 'inst-001',
      service_name: 'shop',
      metrics: [
        {
          name: 'jvm.memory.heap.used',
          unit: 'By',
          description: 'JVM 堆已用内存',
          latest_value: 512,
          points: [
            { ts: '2026-08-30T00:59:00Z', value: 500 },
            { ts: '2026-08-30T01:00:00Z', value: 512 },
          ],
        },
        {
          name: 'jvm.threads.count',
          unit: '{thread}',
          description: 'JVM 线程数',
          latest_value: 42,
          points: [
            { ts: '2026-08-30T00:59:00Z', value: 40 },
            { ts: '2026-08-30T01:00:00Z', value: 42 },
          ],
        },
      ],
    },
  ],
}

interface MockOptions {
  runtimeStatus?: number
  runtime?: unknown
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/services')) return ok(SERVICES)
    if (url.includes('/apm/runtime')) {
      const status = opts.runtimeStatus ?? 200
      if (status !== 200) {
        return Promise.resolve(
          jsonResponse(status, {
            code: status === 403 ? 'FORBIDDEN' : 'INTERNAL',
            message: status === 403 ? '无权限' : '服务器错误',
            data: null,
          }),
        )
      }
      return ok(opts.runtime ?? RUNTIME)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/apm-runtime']}>
          <ApmRuntimePage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApmRuntimePage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载态显示 Spin', () => {
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('正常渲染实例指标卡片：name/unit/latest_value 如实展示，每指标一张图', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    expect(await screen.findByText('jvm.memory.heap.used')).toBeInTheDocument()
    expect(screen.getByText('jvm.threads.count')).toBeInTheDocument()
    // 实例标识与数据来源/轮询标识
    expect(screen.getByText('inst-001')).toBeInTheDocument()
    expect(screen.getByText('数据来源：Agent')).toBeInTheDocument()
    expect(screen.getByText('30 秒自动刷新')).toBeInTheDocument()
    // note 如实展示
    expect(screen.getByText('不同语言运行时指标集不同，按 Agent 实际上报如实展示')).toBeInTheDocument()
    // 单位 suffix 与最新值
    expect(screen.getByText('512')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('By')).toBeInTheDocument()
    // 每个指标一张折线图（桩）
    expect(screen.getAllByTestId('echart-stub')).toHaveLength(2)
  })

  it('data_source=agentless 时展示接入 Agent 降级提示', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ runtime: { data_source: 'agentless', instances: [], note: '' } }),
    )
    renderPage()
    expect(await screen.findByText('运行时指标需接入 Agent')).toBeInTheDocument()
    expect(screen.queryByTestId('echart-stub')).not.toBeInTheDocument()
  })

  it('instances 为空时展示暂无数据提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ runtime: { data_source: 'otel', instances: [], note: '' } }))
    renderPage()
    expect(await screen.findByText('暂无运行时指标数据')).toBeInTheDocument()
  })

  it('查询失败（500）展示 QueryErrorAlert', async () => {
    vi.stubGlobal('fetch', mockFetch({ runtimeStatus: 500 }))
    renderPage()
    expect(await screen.findByText('加载运行时指标失败')).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ runtimeStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('选择实例后查询透传 instance_id 参数', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('jvm.memory.heap.used')

    // 实例下拉：按占位文本消歧（antd 6 占位符 class 为 .ant-select-placeholder）
    const ph = screen.getByText('全部实例')
    fireEvent.mouseDown(ph.closest('.ant-select-placeholder') ?? ph)
    const options = await screen.findAllByText('inst-001（shop）')
    const option = options.find((el) => el.closest('.ant-select-item-option-content')) ?? options[0]
    fireEvent.click(option)

    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/runtime'))
      expect(calls.some((c) => String(c[0]).includes('instance_id=inst-001'))).toBe(true)
    })
  })
})
