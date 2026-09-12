import { afterEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApmExceptionsPage from '../ApmExceptionsPage'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const TRACE_ID = 'c'.repeat(32)

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

const EXCEPTIONS = {
  list: [
    {
      exception_type: 'java.lang.NullPointerException',
      fingerprint: 'ff00ff00ff00ff00ff00ff00ff00ff00',
      count: 87,
      first_seen_at: '2026-08-29T12:00:00Z',
      last_seen_at: '2026-08-30T00:55:00Z',
      affected_services: ['shop-web', 'shop-order'],
      sample_trace_ids: [TRACE_ID],
    },
  ],
  total: 1,
  page: 1,
  page_size: 20,
  data_source: 'otel',
}

interface MockOptions {
  listStatus?: number
  exceptions?: unknown
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/services')) return ok(SERVICES)
    if (url.includes('/apm/exceptions')) {
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
      return ok(opts.exceptions ?? EXCEPTIONS)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage(initialPath = '/apm-exceptions') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={[initialPath]}>
          <ApmExceptionsPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApmExceptionsPage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载态表格显示 Spin', () => {
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('正常渲染异常指纹行：类型、缩略指纹、次数、影响服务数、首末出现与示例 Trace 链接', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    expect(await screen.findByText('java.lang.NullPointerException')).toBeInTheDocument()
    expect(screen.getByText('ff00ff00ff00ff00…')).toBeInTheDocument()
    expect(screen.getByText('87')).toBeInTheDocument()
    expect(screen.getByText('2 个服务')).toBeInTheDocument()
    expect(screen.getByText('数据来源：Agent')).toBeInTheDocument()
    // 示例 trace 按钮跳 /apm-traces?trace_id=（列头同文案，取包裹在 <a> 内的单元格按钮）
    const link = screen
      .getAllByText('示例 Trace')
      .map((el) => el.closest('a'))
      .find(Boolean)!
    expect(link.getAttribute('href')).toBe(`/apm-traces?trace_id=${TRACE_ID}`)
  })

  it('data_source=agentless 时展示无 Agent 降级提示与空态', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        exceptions: { list: [], total: 0, page: 1, page_size: 20, data_source: 'agentless' },
      }),
    )
    renderPage()
    expect(await screen.findByText('当前为无 Agent 数据来源')).toBeInTheDocument()
    expect(screen.getByText('暂无数据')).toBeInTheDocument()
  })

  it('查询失败（500）展示 QueryErrorAlert', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 500 }))
    renderPage()
    expect(await screen.findByText('加载异常指纹列表失败')).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('服务下拉选择透传 service 参数', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('java.lang.NullPointerException')

    // 服务下拉：按占位文本消歧（antd 6 占位符 class 为 .ant-select-placeholder）
    const ph = screen.getByText('全部服务')
    fireEvent.mouseDown(ph.closest('.ant-select-placeholder') ?? ph)
    const options = await screen.findAllByText('商城站点（shop）')
    const option = options.find((el) => el.closest('.ant-select-item-option-content')) ?? options[0]
    fireEvent.click(option)

    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/exceptions'))
      expect(calls.some((c) => String(c[0]).includes('service=shop'))).toBe(true)
    })
  })
})


/* ==================== P1-01 A3：Trace 级定位深链与异常明细 ==================== */

const AVAILABILITY_READY = {
  query_state: 'READY',
  reason_codes: [],
  observed_sources: ['OTEL'],
  last_collected_at: null,
  last_ingested_at: null,
  estimated_lag_ms: null,
  partial: false,
}

const TRACE_EXACT_PAGE = {
  list: [],
  total: 0,
  page: 1,
  page_size: 20,
  data_source: 'otel',
  message: '',
  trace_id: TRACE_ID,
  match_mode: 'trace_exact',
  match_note: '',
  trace_exceptions: [
    {
      trace_id: TRACE_ID,
      span_id: 's1',
      service_name: 'shop-order',
      occurred_at: '2026-08-30T00:30:00Z',
      exception_type: 'java.lang.NullPointerException',
      // 含 HTML 片段：必须按纯文本渲染，不得解析执行
      exception_message: 'order id missing <b>bold</b>',
      stacktrace:
        'java.lang.NullPointerException: order id missing\n\tat com.example.OrderService.get(OrderService.java:42)\n<script>alert(1)</script>',
      fingerprint: 'ff00ff00ff00ff00ff00ff00ff00ff00',
      message_truncated: true,
      stacktrace_truncated: true,
    },
  ],
  availability: AVAILABILITY_READY,
}

describe('ApmExceptionsPage · A3 Trace 级定位', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('URL 深链 ?trace_id= 透传检索，trace_exact 渲染 trace_exceptions 明细（脱敏文本+截断标记）', async () => {
    vi.stubGlobal('fetch', mockFetch({ exceptions: TRACE_EXACT_PAGE }))
    renderPage(`/apm-exceptions?trace_id=${TRACE_ID}`)

    expect(await screen.findByText(/已按 Trace 精确定位/)).toBeInTheDocument()
    // trace 级明细列
    expect(screen.getByText('shop-order')).toBeInTheDocument()
    expect(screen.getByText('java.lang.NullPointerException')).toBeInTheDocument()
    // 截断标记如实展示
    expect(screen.getByText('已截断')).toBeInTheDocument()
    // 检索请求携带 trace_id
    const calls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/exceptions'))
    expect(calls.some((c) => String(c[0]).includes(`trace_id=${TRACE_ID}`))).toBe(true)
  })

  it('异常消息/堆栈中的 HTML 与脚本一律按纯文本渲染，不执行', async () => {
    vi.stubGlobal('fetch', mockFetch({ exceptions: TRACE_EXACT_PAGE }))
    const { container } = renderPage(`/apm-exceptions?trace_id=${TRACE_ID}`)

    // 消息中的 <b> 标签显示为字面文本而非加粗元素
    expect(await screen.findByText(/order id missing <b>bold<\/b>/)).toBeInTheDocument()

    // 展开堆栈（纯文本 <pre>），其中的 <script> 字面展示且不产生 script 元素
    const expandIcon = container.querySelector('.ant-table-row-expand-icon')
    expect(expandIcon).toBeTruthy()
    fireEvent.click(expandIcon as Element)
    expect(await screen.findByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument()
    expect(screen.getByText('堆栈已在采集侧截断')).toBeInTheDocument()
    expect(container.querySelector('script')).toBeNull()
    expect(container.querySelector('b')).toBeNull()
  })

  it('trace_exact 但该 Trace 无异常：明确展示，不把 WAF 403 当应用异常', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ exceptions: { ...TRACE_EXACT_PAGE, trace_exceptions: [] } }),
    )
    renderPage(`/apm-exceptions?trace_id=${TRACE_ID}`)

    expect(await screen.findByText('该 Trace 未记录应用异常')).toBeInTheDocument()
    expect(screen.getByText(/WAF 阻断（403）不属于应用异常/)).toBeInTheDocument()
  })

  it('match_mode=window_aggregate：明确标注「同时间窗候选，未精确定位」，保留聚合列表', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        exceptions: {
          ...EXCEPTIONS,
          trace_id: TRACE_ID,
          match_mode: 'window_aggregate',
          match_note: '窗口聚合结果，非特定请求定位',
          availability: AVAILABILITY_READY,
        },
      }),
    )
    renderPage(`/apm-exceptions?trace_id=${TRACE_ID}`)

    expect(await screen.findByText(/同时间窗候选，未精确定位/)).toBeInTheDocument()
    expect(screen.getByText('窗口聚合结果，非特定请求定位')).toBeInTheDocument()
    // 聚合列表仍渲染
    expect(screen.getByText('java.lang.NullPointerException')).toBeInTheDocument()
  })

  it('非法 trace_id 忽略并提示，检索不携带 trace_id', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage('/apm-exceptions?trace_id=bad-id')

    expect(await screen.findByText(/URL 参数 trace_id 格式非法/)).toBeInTheDocument()
    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.filter((c) =>
        String(c[0]).includes('/apm/exceptions'),
      )
      expect(calls.length).toBeGreaterThan(0)
    })
    const calls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/exceptions'))
    expect(calls.some((c) => String(c[0]).includes('trace_id='))).toBe(false)
  })
})
