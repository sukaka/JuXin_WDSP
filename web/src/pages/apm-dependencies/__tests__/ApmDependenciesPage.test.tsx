import { afterEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApmDependenciesPage from '../ApmDependenciesPage'

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

const DEPENDENCIES = {
  edges: [
    { source: 'shop-web', target: 'shop-order', target_type: 'service', calls: 3000, error_rate: 0.01, avg_ms: 45 },
    { source: 'shop-order', target: 'shop_db', target_type: 'db', calls: 6200, error_rate: 0.02, avg_ms: 12 },
    { source: 'shop-order', target: 'kafka://orders', target_type: 'messaging', calls: 900, error_rate: 0, avg_ms: 8 },
    { source: 'shop-web', target: 'pay.example.com', target_type: 'external', calls: 300, error_rate: 0.07, avg_ms: 210 },
  ],
  data_source: 'otel',
  note: '依赖关系基于客户端 span 单视角派生，未插桩服务间的调用不可见',
}

interface MockOptions {
  status?: number
  dependencies?: unknown
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/services')) return ok(SERVICES)
    if (url.includes('/apm/dependencies')) {
      const status = opts.status ?? 200
      if (status !== 200) {
        return Promise.resolve(
          jsonResponse(status, {
            code: status === 403 ? 'FORBIDDEN' : 'INTERNAL',
            message: status === 403 ? '无权限' : '服务器错误',
            data: null,
          }),
        )
      }
      return ok(opts.dependencies ?? DEPENDENCIES)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/apm-dependencies']}>
          <ApmDependenciesPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApmDependenciesPage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载态表格显示 Spin', () => {
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('默认表格视图渲染依赖边：source/target/目标类型 Tag/调用数/错误率/平均耗时与 note 如实展示', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    // shop-web 是两条边的调用方、shop-order 同时作为调用方与被调方出现多次
    expect((await screen.findAllByText('shop-web')).length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('shop-order').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('shop_db')).toBeInTheDocument()
    expect(screen.getByText('kafka://orders')).toBeInTheDocument()
    // 目标类型 Tag
    expect(screen.getByText('服务')).toBeInTheDocument()
    expect(screen.getByText('数据库')).toBeInTheDocument()
    expect(screen.getByText('消息队列')).toBeInTheDocument()
    expect(screen.getByText('外部服务')).toBeInTheDocument()
    expect(screen.getByText('12 ms')).toBeInTheDocument()
    // note 口径说明如实展示
    expect(screen.getByText('依赖关系基于客户端 span 单视角派生，未插桩服务间的调用不可见')).toBeInTheDocument()
    // 页头数据来源标识
    expect(screen.getByText('数据来源：Agent')).toBeInTheDocument()
    // 默认不渲染关系图
    expect(screen.queryByTestId('echart-stub')).not.toBeInTheDocument()
  })

  it('切换关系图视图渲染依赖关系图', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findAllByText('shop-web')

    fireEvent.click(screen.getByText('关系图'))
    expect(await screen.findByTestId('echart-stub')).toBeInTheDocument()
    // 切回表格
    fireEvent.click(screen.getByText('表格视图'))
    await waitFor(() => expect(screen.queryByTestId('echart-stub')).not.toBeInTheDocument())
    expect(screen.getAllByText('shop-order').length).toBeGreaterThanOrEqual(1)
  })

  it('关系图视图下无边数据时展示空态', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ dependencies: { edges: [], data_source: 'otel', note: '' } }),
    )
    renderPage()
    await screen.findByText('暂无数据')
    fireEvent.click(screen.getByText('关系图'))
    expect(await screen.findByText('暂无依赖数据')).toBeInTheDocument()
  })

  it('查询失败（500）展示 QueryErrorAlert', async () => {
    vi.stubGlobal('fetch', mockFetch({ status: 500 }))
    renderPage()
    expect(await screen.findByText('加载依赖关系失败')).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ status: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('服务下拉选择透传 service 参数', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findAllByText('shop-web')

    // 服务下拉：按占位文本消歧（antd 6 占位符 class 为 .ant-select-placeholder）
    const ph = screen.getByText('全部服务')
    fireEvent.mouseDown(ph.closest('.ant-select-placeholder') ?? ph)
    const options = await screen.findAllByText('商城站点（shop）')
    const option = options.find((el) => el.closest('.ant-select-item-option-content')) ?? options[0]
    fireEvent.click(option)

    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/dependencies'))
      expect(calls.some((c) => String(c[0]).includes('service=shop'))).toBe(true)
    })
  })
})
