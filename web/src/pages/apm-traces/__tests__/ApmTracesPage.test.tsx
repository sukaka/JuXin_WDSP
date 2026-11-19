import { afterEach, describe, expect, it, vi, type Mock } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApmTracesPage from '../ApmTracesPage'
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

const TRACE_ID = 'a'.repeat(32)

const SEARCH_HIT = {
  list: [
    {
      trace_id: TRACE_ID,
      root_service: 'shop-web',
      root_operation: 'GET /api/orders',
      start_time: '2026-08-30T00:30:00Z',
      duration_ms: 230,
      span_count: 2,
      error_count: 1,
      services: ['shop-web', 'shop-order'],
    },
  ],
  total: 1,
  page: 1,
  page_size: 20,
  data_source: 'otel',
}

const TRACE_WITH_SPANS = {
  trace_id: TRACE_ID,
  access_logs: [],
  security_events: [],
  partial: false,
  note: '',
  otel_spans: [
    {
      span_id: 's1',
      parent_span_id: '',
      service_name: 'shop-web',
      operation_name: 'GET /api/orders',
      span_kind: 'SERVER',
      start_time: '2026-08-30T00:30:00.000Z',
      duration_ms: 230,
      status_code: 'OK',
      attributes: { 'http.method': 'GET' },
    },
    {
      span_id: 's2',
      parent_span_id: 's1',
      service_name: 'shop-order',
      operation_name: 'SELECT orders',
      span_kind: 'CLIENT',
      start_time: '2026-08-30T00:30:00.050Z',
      duration_ms: 120,
      status_code: 'ERROR',
      attributes: { 'db.system': 'mysql' },
    },
  ],
  span_count: 2,
  truncated: false,
  data_source: 'otel',
}

const TRACE_FALLBACK = {
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
    { id: 'evt-1', occurred_at: '2026-08-30T00:30:01Z', action: 'BLOCK', rule_id: 'CRS-942100', request_id: 'req-1' },
  ],
  partial: false,
  note: '',
}

interface MockOptions {
  searchStatus?: number
  search?: unknown
  trace?: unknown
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/traces/')) return ok(opts.trace ?? TRACE_WITH_SPANS)
    if (url.includes('/apm/trace-search')) {
      const status = opts.searchStatus ?? 200
      if (status !== 200) {
        return Promise.resolve(
          jsonResponse(status, {
            code: status === 403 ? 'FORBIDDEN' : 'INTERNAL',
            message: status === 403 ? '无权限' : '服务器错误',
            data: null,
          }),
        )
      }
      return ok(opts.search ?? SEARCH_HIT)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage(initialPath = '/apm-traces') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={[initialPath]}>
          <ApmTracesPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

function searchCalls() {
  return (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/trace-search'))
}

describe('ApmTracesPage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('加载态表格显示 Spin', () => {
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('正常渲染检索结果行与数据来源标识', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    const row = (await screen.findByText('shop-web')).closest('tr')!
    expect(row.textContent).toContain('GET /api/orders')
    expect(row.textContent).toContain('230 ms')
    expect(row.textContent).toContain('2')
    expect(row.textContent).toContain('1')
    // trace_id 缩略展示（前 8 位 + 省略号）
    expect(row.textContent).toContain('aaaaaaaa…')
    expect(screen.getByText('数据来源：Agent')).toBeInTheDocument()
    // 首次查询携带时间窗参数
    const url = String(searchCalls()[0][0])
    expect(url).toContain('start_time=')
    expect(url).toContain('end_time=')
    expect(url).toContain('page=1')
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ searchStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('DSN 未配置（data_source=agentless 且空结果）展示无 Agent 提示与空态', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        search: { list: [], total: 0, page: 1, page_size: 20, data_source: 'agentless' },
      }),
    )
    renderPage()
    expect(await screen.findByText('当前为无 Agent 数据来源')).toBeInTheDocument()
    expect(screen.getByText('暂无数据')).toBeInTheDocument()
  })

  it('Trace ID 精确检索：参数透传至 trace-search', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('shop-web')

    const input = screen.getByPlaceholderText('Trace ID（32 位十六进制）')
    fireEvent.change(input, { target: { value: TRACE_ID.toUpperCase() } })
    fireEvent.keyDown(input, { key: 'Enter', keyCode: 13 })

    await waitFor(() => {
      const hit = searchCalls().some((c) => String(c[0]).includes(`trace_id=${TRACE_ID}`))
      expect(hit).toBe(true)
    })
  })

  it('Trace ID 格式非法时仅提示，不携带 trace_id 发起检索', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('shop-web')

    const input = screen.getByPlaceholderText('Trace ID（32 位十六进制）')
    fireEvent.change(input, { target: { value: 'not-a-trace-id' } })
    fireEvent.keyDown(input, { key: 'Enter', keyCode: 13 })

    expect(
      await screen.findByText('Trace ID 格式不正确（应为 32 位十六进制字符）'),
    ).toBeInTheDocument()
    expect(searchCalls().some((c) => String(c[0]).includes('trace_id='))).toBe(false)
  })

  it('行点击打开瀑布 Drawer：otel_spans 渲染瀑布，点击 span 展开属性表', { timeout: 20000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    const row = (await screen.findByText('shop-web')).closest('tr')!
    fireEvent.click(row)

    // 瀑布视图：span 行 + 层级缩进 + 错误标识
    expect(await screen.findByText('调用链瀑布')).toBeInTheDocument()
    expect(screen.getByText('SELECT orders')).toBeInTheDocument()
    expect(screen.getByText('错误')).toBeInTheDocument()
    expect(screen.getByText('共 2 个 span')).toBeInTheDocument()
    // 子 span 有缩进
    const childLabel = screen.getByText('SELECT orders').closest('div')!
    expect(childLabel.style.paddingLeft).toBe('16px')

    // 点击 span 行展开 attributes 表
    fireEvent.click(screen.getByRole('button', { name: 'span GET /api/orders' }))
    expect(await screen.findByText('http.method')).toBeInTheDocument()
  })

  it('无 otel_spans 时降级为访问记录 + 关联 WAF 事件视图', async () => {
    vi.stubGlobal('fetch', mockFetch({ trace: TRACE_FALLBACK }))
    renderPage()

    const row = (await screen.findByText('shop-web')).closest('tr')!
    fireEvent.click(row)

    expect(await screen.findByText('访问记录（1）')).toBeInTheDocument()
    expect(screen.getByText('关联 WAF 事件（1）')).toBeInTheDocument()
    expect(screen.getByText('/api/orders/detail')).toBeInTheDocument()
    expect(screen.getByText('CRS-942100')).toBeInTheDocument()
    expect(screen.queryByText('调用链瀑布')).not.toBeInTheDocument()
  })

  it('truncated=true 时提示已截断', async () => {
    vi.stubGlobal('fetch', mockFetch({ trace: { ...TRACE_WITH_SPANS, truncated: true } }))
    renderPage()

    const row = (await screen.findByText('shop-web')).closest('tr')!
    fireEvent.click(row)

    expect(await screen.findByText(/结果已截断/)).toBeInTheDocument()
    // 瀑布仍正常渲染
    expect(screen.getByText('调用链瀑布')).toBeInTheDocument()
  })

  it('URL ?request_id= 预填检索框并自动发起检索', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage(`/apm-traces?request_id=req-777`)

    await waitFor(() => {
      expect(searchCalls().some((c) => String(c[0]).includes('request_id=req-777'))).toBe(true)
    })
    expect(screen.getByPlaceholderText('请求 ID')).toHaveValue('req-777')
  })

  it('URL ?trace_id= 合法时预填并检索；非法时忽略', async () => {
    vi.stubGlobal('fetch', mockFetch())
    const { unmount } = renderPage(`/apm-traces?trace_id=${TRACE_ID}`)
    await waitFor(() => {
      expect(searchCalls().some((c) => String(c[0]).includes(`trace_id=${TRACE_ID}`))).toBe(true)
    })
    expect(screen.getByPlaceholderText('Trace ID（32 位十六进制）')).toHaveValue(TRACE_ID)
    unmount()

    vi.stubGlobal('fetch', mockFetch())
    renderPage(`/apm-traces?trace_id=bad-id`)
    await waitFor(() => expect(searchCalls().length).toBeGreaterThan(0))
    expect(searchCalls().some((c) => String(c[0]).includes('trace_id='))).toBe(false)
    expect(screen.getByPlaceholderText('Trace ID（32 位十六进制）')).toHaveValue('')
  })
})


/* ==================== P1-01 A3：五态缺数据 UX 与跳转上下文 ==================== */

const APP_ID = '6f4b3a2e-1111-4222-8333-abcdefabcdef'

function availabilityFixture(partial: Record<string, unknown>) {
  return {
    query_state: 'READY',
    reason_codes: [],
    observed_sources: ['GATEWAY', 'OTEL'],
    last_collected_at: null,
    last_ingested_at: null,
    estimated_lag_ms: null,
    partial: false,
    ...partial,
  }
}

const SEARCH_UNAVAILABLE = {
  list: [],
  total: 0,
  page: 1,
  page_size: 20,
  data_source: 'agentless',
  message: '',
  availability: availabilityFixture({
    query_state: 'UNAVAILABLE',
    reason_codes: ['STORAGE_UNAVAILABLE'],
    observed_sources: [],
  }),
}

const SEARCH_NO_MATCH = {
  list: [],
  total: 0,
  page: 1,
  page_size: 20,
  data_source: 'otel',
  availability: availabilityFixture({ query_state: 'EMPTY', reason_codes: ['NO_MATCH'] }),
  correlation: {
    state: 'NOT_FOUND',
    match_basis: 'request_id_to_trace_id',
    candidate_count: 0,
    reason: '证据范围内不存在该请求 ID 对应的调用链',
    candidates: [],
  },
}

const SEARCH_PENDING = {
  list: [],
  total: 0,
  page: 1,
  page_size: 20,
  data_source: 'otel',
  availability: availabilityFixture({
    query_state: 'EMPTY',
    reason_codes: ['INGESTION_DELAY_CONFIRMED'],
    observed_sources: ['OTEL'],
    last_collected_at: '2026-08-30T00:30:00Z',
    last_ingested_at: '2026-08-30T00:29:58Z',
    estimated_lag_ms: 12_000,
  }),
  correlation: {
    state: 'PENDING',
    match_basis: 'request_id_to_trace_id',
    candidate_count: 0,
    reason: '该请求可能尚在采集/入库途中',
    candidates: [],
  },
}

const CANDIDATE_1 = 'a'.repeat(32)
const CANDIDATE_2 = 'b'.repeat(32)

const SEARCH_AMBIGUOUS = {
  list: [],
  total: 0,
  page: 1,
  page_size: 20,
  data_source: 'otel',
  availability: availabilityFixture({}),
  correlation: {
    state: 'AMBIGUOUS',
    match_basis: 'request_id_to_trace_id',
    candidate_count: 2,
    reason: '该请求 ID 命中两条候选调用链',
    candidates: [
      {
        trace_id: CANDIDATE_1,
        occurred_at: '2026-08-30T00:30:00Z',
        services: ['shop-web'],
        match_basis: 'otel_traces.trace_id',
      },
      {
        trace_id: CANDIDATE_2,
        occurred_at: '2026-08-30T00:30:01Z',
        services: ['shop-order'],
        match_basis: 'access_logs.trace_id',
      },
    ],
  },
}

const SEARCH_GATEWAY_ONLY = {
  list: [],
  total: 0,
  page: 1,
  page_size: 20,
  data_source: 'agentless',
  availability: availabilityFixture({ query_state: 'EMPTY', observed_sources: ['GATEWAY'] }),
}

describe('ApmTracesPage · A3 五态与跳转上下文', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
    useAuthStore.getState().reset()
  })

  it('URL 深链：service/application_id/start_time/end_time 透传检索，白名单 from 显示返回按钮', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage(
      `/apm-traces?request_id=req-9&application_id=${APP_ID}&service=shop-web` +
        `&start_time=2026-08-30T00%3A25%3A00Z&end_time=2026-08-30T00%3A35%3A00Z&from=/security-events`,
    )

    await waitFor(() => {
      const hit = searchCalls().some((c) => {
        const u = String(c[0])
        return (
          u.includes('request_id=req-9') &&
          u.includes(`application_id=${APP_ID}`) &&
          u.includes('service=shop-web') &&
          u.includes('start_time=2026-08-30T00%3A25%3A00.000Z') &&
          u.includes('end_time=2026-08-30T00%3A35%3A00.000Z')
        )
      })
      expect(hit).toBe(true)
    })
    // 服务名预填、应用 Tag 展示、返回按钮指向站内白名单路由
    expect(screen.getByPlaceholderText('服务名')).toHaveValue('shop-web')
    expect(screen.getByText(`应用：${APP_ID}`)).toBeInTheDocument()
    const back = screen.getByRole('button', { name: /返回安全事件/ })
    expect(back.closest('a')?.getAttribute('href')).toBe('/security-events')
  })

  it('URL 非法参数忽略并提示；外部 from 一律拒绝（防开放重定向）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage(
      '/apm-traces?trace_id=bad-id&application_id=not-uuid&start_time=2026-08-30T00%3A25%3A00Z&from=https://evil.example.com',
    )

    expect(await screen.findByText(/URL 参数 Trace ID 格式非法/)).toBeInTheDocument()
    expect(screen.getByText(/URL 参数应用 ID 格式非法/)).toBeInTheDocument()
    expect(screen.getByText(/起止时间需同时提供/)).toBeInTheDocument()
    expect(screen.getByText(/返回地址不是允许的站内地址/)).toBeInTheDocument()
    // 非法值均未进入检索请求；无返回按钮
    await waitFor(() => expect(searchCalls().length).toBeGreaterThan(0))
    for (const c of searchCalls()) {
      const u = String(c[0])
      expect(u.includes('trace_id=')).toBe(false)
      expect(u.includes('application_id=')).toBe(false)
      // URL 上的非法时间窗未生效（检索仍用页面默认时间窗，不含 URL 指定的日期）
      expect(u.includes('2026-08-30')).toBe(false)
    }
    expect(screen.queryByRole('button', { name: /返回/ })).not.toBeInTheDocument()
  })

  it('存储不可用（UNAVAILABLE）：显示「调用链存储暂不可用」+ 重试，不展示零值空表', async () => {
    vi.stubGlobal('fetch', mockFetch({ search: SEARCH_UNAVAILABLE }))
    renderPage()

    expect(await screen.findByText('调用链存储暂不可用')).toBeInTheDocument()
    expect(screen.getByText(/调用链存储当前不可用/)).toBeInTheDocument()
    // 不显示「暂无数据」零值结论（表格不渲染）
    expect(screen.queryByText('暂无数据')).not.toBeInTheDocument()

    const callsBefore = searchCalls().length
    fireEvent.click(screen.getByRole('button', { name: /重\s*试/ }))
    await waitFor(() => expect(searchCalls().length).toBe(callsBefore + 1))
  })

  it('无匹配（EMPTY+NO_MATCH）：显示「未找到匹配的调用链」与关联判定原因', async () => {
    vi.stubGlobal('fetch', mockFetch({ search: SEARCH_NO_MATCH }))
    renderPage('/apm-traces?request_id=req-404')

    expect(await screen.findByText('未找到匹配的调用链')).toBeInTheDocument()
    expect(screen.getByText('证据范围内不存在该请求 ID 对应的调用链')).toBeInTheDocument()
  })

  it('旧后端缺 availability/correlation 字段：显示「状态信息不足」，不编造原因', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        search: { list: [], total: 0, page: 1, page_size: 20, data_source: 'otel' },
      }),
    )
    renderPage()
    expect(await screen.findByText('状态信息不足')).toBeInTheDocument()
  })

  it('仅网关观测数据（observed_sources 仅 GATEWAY）：解释并给接入指引', async () => {
    vi.stubGlobal('fetch', mockFetch({ search: SEARCH_GATEWAY_ONLY }))
    renderPage()
    expect(await screen.findByText('目前仅有网关观测数据')).toBeInTheDocument()
    expect(screen.getByText(/不会生成代码级 Trace/)).toBeInTheDocument()
  })

  it('等待入库（PENDING）：展示采集/入库水位，自动重试有界（最多 30 秒）后转手动刷新', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', mockFetch({ search: SEARCH_PENDING }))
    renderPage('/apm-traces?request_id=req-pending')

    await act(async () => {
      await vi.advanceTimersByTimeAsync(50)
    })
    expect(screen.getByText(/正在自动等待/)).toBeInTheDocument()
    expect(screen.getByText(/最近采集时间/)).toBeInTheDocument()
    expect(screen.getByText(/最近入库时间/)).toBeInTheDocument()
    expect(screen.getByText(/约 12 秒/)).toBeInTheDocument()
    expect(screen.getByText('该请求可能尚在采集/入库途中')).toBeInTheDocument()
    expect(searchCalls().length).toBe(1)

    // 30 秒预算内：每 5 秒一次自动重试（最多 6 次），之后停止
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    const atStop = searchCalls().length
    expect(atStop).toBeGreaterThan(1)
    expect(atStop).toBeLessThanOrEqual(7)
    expect(screen.getByText('数据尚未入库，自动等待已结束')).toBeInTheDocument()

    // 超过预算后不再自动重试（无无限轮询）
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000)
    })
    expect(searchCalls().length).toBe(atStop)

    // 手动刷新与排障入口可用（键盘可聚焦的原生按钮/链接）
    fireEvent.click(screen.getByRole('button', { name: '手动刷新' }))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(50)
    })
    expect(searchCalls().length).toBe(atStop + 1)
    const diag = screen.getByRole('button', { name: '前往「Agent 管理」排查数据面' })
    expect(diag.closest('a')?.getAttribute('href')).toBe('/apm-agents')
  })

  it('页面卸载后清理定时器，不再发起自动重试', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', mockFetch({ search: SEARCH_PENDING }))
    const { unmount } = renderPage('/apm-traces?request_id=req-pending')

    await act(async () => {
      await vi.advanceTimersByTimeAsync(50)
    })
    expect(searchCalls().length).toBe(1)
    unmount()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000)
    })
    expect(searchCalls().length).toBe(1)
  })

  it('AMBIGUOUS：列出全部候选（时间/服务/匹配依据），不自动任选，点击候选才打开对应 Trace', async () => {
    vi.stubGlobal('fetch', mockFetch({ search: SEARCH_AMBIGUOUS }))
    renderPage('/apm-traces?request_id=req-amb')

    expect(await screen.findByText('存在多个候选')).toBeInTheDocument()
    expect(screen.getByText('aaaaaaaa…')).toBeInTheDocument()
    expect(screen.getByText('bbbbbbbb…')).toBeInTheDocument()
    // 不自动打开任一候选
    expect(screen.queryByText('调用链瀑布')).not.toBeInTheDocument()

    fireEvent.click(screen.getAllByRole('button', { name: '查看该 Trace' })[1])
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some((c) =>
          String(c[0]).includes(`/apm/traces/${CANDIDATE_2}`),
        ),
      ).toBe(true)
    })
    expect(await screen.findByText('调用链瀑布')).toBeInTheDocument()
  })

  it('抽屉详情查询携带时间窗上下文；下钻 SQL/异常携带相同 trace_id 与时间窗', async () => {
    useAuthStore.setState({
      user: makeUser(['apm.traces.read', 'apm.sql.read']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal('fetch', mockFetch())
    renderPage('/apm-traces?start_time=2026-08-30T00%3A25%3A00Z&end_time=2026-08-30T00%3A35%3A00Z')

    const row = (await screen.findByText('shop-web')).closest('tr')!
    fireEvent.click(row)
    expect(await screen.findByText('调用链瀑布')).toBeInTheDocument()

    // 详情查询携带时间窗
    const traceCall = (fetch as Mock).mock.calls.find((c) =>
      String(c[0]).includes(`/apm/traces/${TRACE_ID}`),
    )
    expect(traceCall).toBeTruthy()
    expect(String(traceCall![0])).toContain('start_time=2026-08-30T00%3A25%3A00.000Z')
    expect(String(traceCall![0])).toContain('end_time=2026-08-30T00%3A35%3A00.000Z')

    // 下钻链接携带相同 trace_id 与时间窗
    const sqlHref = screen.getByRole('button', { name: '下钻 SQL 诊断' }).closest('a')!
      .getAttribute('href')!
    expect(sqlHref.startsWith('/apm-sql?')).toBe(true)
    expect(sqlHref).toContain(`trace_id=${TRACE_ID}`)
    expect(sqlHref).toContain('start_time=2026-08-30T00%3A25%3A00.000Z')
    const excHref = screen.getByRole('button', { name: '下钻异常分析' }).closest('a')!
      .getAttribute('href')!
    expect(excHref.startsWith('/apm-exceptions?')).toBe(true)
    expect(excHref).toContain(`trace_id=${TRACE_ID}`)
  })

  it('权限裁剪：无 apm.sql.read 时隐藏 SQL 下钻入口，异常下钻保留', async () => {
    useAuthStore.setState({
      user: makeUser(['apm.traces.read']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    const row = (await screen.findByText('shop-web')).closest('tr')!
    fireEvent.click(row)
    expect(await screen.findByText('调用链瀑布')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '下钻 SQL 诊断' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下钻异常分析' })).toBeInTheDocument()
  })

  it('抽屉展示关联强度与数据完整性；旧后端缺 correlation 时提示信息不足', async () => {
    useAuthStore.setState({
      user: makeUser(['apm.traces.read']),
      csrfToken: null,
      initialized: true,
    })
    const traceWithCorrelation = {
      ...TRACE_WITH_SPANS,
      correlation: {
        state: 'MATCHED',
        match_basis: 'trace_id_direct',
        candidate_count: 1,
        reason: '',
        candidates: [],
      },
      availability: availabilityFixture({ partial: true, query_state: 'PARTIAL' }),
    }
    vi.stubGlobal('fetch', mockFetch({ trace: traceWithCorrelation }))
    const { unmount } = renderPage()
    fireEvent.click((await screen.findByText('shop-web')).closest('tr')!)
    expect(await screen.findByText('已关联')).toBeInTheDocument()
    expect(screen.getByText(/按 Trace ID 精确匹配/)).toBeInTheDocument()
    expect(screen.getByText('结果可能不完整')).toBeInTheDocument()
    unmount()

    // 旧后端：无 correlation/availability 字段 → 状态信息不足（页面与抽屉各一处提示）
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    fireEvent.click((await screen.findByText('shop-web')).closest('tr')!)
    expect(await screen.findByText(/关联状态信息不足/)).toBeInTheDocument()
    expect(screen.getAllByText('状态信息不足').length).toBeGreaterThanOrEqual(1)
  })
})
