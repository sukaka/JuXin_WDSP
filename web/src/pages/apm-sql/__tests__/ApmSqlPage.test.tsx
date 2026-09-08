import { afterEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApmSqlPage from '../ApmSqlPage'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const TRACE_ID_1 = 'a'.repeat(32)
const TRACE_ID_2 = 'b'.repeat(32)

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

const SQL_PAGE = {
  list: [
    {
      sql_fingerprint: 'abc123def4567890fedcba0987654321',
      db_system: 'mysql',
      namespace: 'shop_db',
      operation: 'SELECT',
      calls: 1200,
      error_count: 3,
      avg_ms: 45.5,
      p95_ms: 230,
      sample_trace_ids: [TRACE_ID_1, TRACE_ID_2],
    },
  ],
  total: 1,
  page: 1,
  page_size: 20,
  data_source: 'otel',
  message: '',
}

interface MockOptions {
  listStatus?: number
  sql?: unknown
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/apm/services')) return ok(SERVICES)
    if (url.includes('/apm/sql')) {
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
      return ok(opts.sql ?? SQL_PAGE)
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage(initialPath = '/apm-sql') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={[initialPath]}>
          <ApmSqlPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

function sqlCalls() {
  return (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('/apm/sql'))
}

describe('ApmSqlPage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('加载态表格显示 Spin', () => {
    vi.stubGlobal('fetch', mockFetch({ pending: true }))
    const { container } = renderPage()
    expect(container.querySelector('.ant-spin')).toBeTruthy()
  })

  it('正常渲染指纹行：缩略等宽指纹、聚合指标、数据来源标识与示例 Trace 链接', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    // 指纹缩略展示（前 16 位 + 省略号）
    expect(await screen.findByText('abc123def4567890…')).toBeInTheDocument()
    expect(screen.getByText('mysql')).toBeInTheDocument()
    expect(screen.getByText('shop_db')).toBeInTheDocument()
    expect(screen.getByText('SELECT')).toBeInTheDocument()
    expect(screen.getByText('1200')).toBeInTheDocument()
    expect(screen.getByText('45.5 ms')).toBeInTheDocument()
    expect(screen.getByText('230 ms')).toBeInTheDocument()
    // 页头数据来源标识
    expect(screen.getByText('数据来源：Agent')).toBeInTheDocument()
    // 示例 trace 按钮跳 /apm-traces?trace_id=
    const link = screen.getByText('示例 Trace 1').closest('a')!
    expect(link.getAttribute('href')).toBe(`/apm-traces?trace_id=${TRACE_ID_1}`)
    // 首次查询默认 sort=calls 并携带时间窗
    const url = String(sqlCalls()[0][0])
    expect(url).toContain('sort=calls')
    expect(url).toContain('start_time=')
    expect(url).toContain('end_time=')
  })

  it('data_source=agentless 时展示接入 OTel 数据面指引，不渲染表格', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        sql: { list: [], total: 0, page: 1, page_size: 20, data_source: 'agentless', message: '' },
      }),
    )
    renderPage()
    expect(await screen.findByText('SQL 诊断需接入 OTel 数据面')).toBeInTheDocument()
    expect(screen.queryByText('abc123def4567890…')).not.toBeInTheDocument()
  })

  it('后端 message 有值时如实展示', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ sql: { ...SQL_PAGE, message: '部分服务未上报 db 属性，聚合可能不完整' } }),
    )
    renderPage()
    expect(await screen.findByText('部分服务未上报 db 属性，聚合可能不完整')).toBeInTheDocument()
    // 表格仍正常渲染
    expect(screen.getByText('abc123def4567890…')).toBeInTheDocument()
  })

  it('查询失败（500）展示 QueryErrorAlert', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 500 }))
    renderPage()
    expect(await screen.findByText('加载 SQL 指纹列表失败')).toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('数据库类型检索透传 db_system 参数', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('abc123def4567890…')

    const input = screen.getByPlaceholderText('数据库类型（如 mysql）')
    fireEvent.change(input, { target: { value: 'postgresql' } })
    fireEvent.keyDown(input, { key: 'Enter', keyCode: 13 })

    await waitFor(() => {
      expect(sqlCalls().some((c) => String(c[0]).includes('db_system=postgresql'))).toBe(true)
    })
  })

  it('切换排序透传 sort 参数', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('abc123def4567890…')

    fireEvent.click(screen.getByText('按 P95 耗时'))
    await waitFor(() => {
      expect(sqlCalls().some((c) => String(c[0]).includes('sort=p95_ms'))).toBe(true)
    })
  })

  it('服务下拉选择透传 service 参数', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('abc123def4567890…')

    // 服务下拉：按占位文本消歧（antd 6 占位符 class 为 .ant-select-placeholder）
    const ph = screen.getByText('全部服务')
    fireEvent.mouseDown(ph.closest('.ant-select-placeholder') ?? ph)
    const options = await screen.findAllByText('商城站点（shop）')
    const option = options.find((el) => el.closest('.ant-select-item-option-content')) ?? options[0]
    fireEvent.click(option)

    await waitFor(() => {
      expect(sqlCalls().some((c) => String(c[0]).includes('service=shop'))).toBe(true)
    })
  })
})


/* ==================== P1-01 A3：Trace 级定位深链与缺数据态 ==================== */

const AVAILABILITY_READY = {
  query_state: 'READY',
  reason_codes: [],
  observed_sources: ['OTEL'],
  last_collected_at: null,
  last_ingested_at: null,
  estimated_lag_ms: null,
  partial: false,
}

describe('ApmSqlPage · A3 Trace 级定位', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('URL 深链 ?trace_id= 透传检索，trace_exact 展示「已按 Trace 精确定位」与 match_note', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        sql: {
          ...SQL_PAGE,
          trace_id: TRACE_ID_1,
          match_mode: 'trace_exact',
          match_note: '以下结果仅来自该 Trace 的数据库调用 Span',
          availability: AVAILABILITY_READY,
        },
      }),
    )
    renderPage(
      `/apm-sql?trace_id=${TRACE_ID_1}&start_time=2026-08-30T00%3A25%3A00Z&end_time=2026-08-30T00%3A35%3A00Z`,
    )

    expect(await screen.findByText(/已按 Trace 精确定位/)).toBeInTheDocument()
    expect(screen.getByText('以下结果仅来自该 Trace 的数据库调用 Span')).toBeInTheDocument()
    // Trace 定位 Tag 展示
    expect(screen.getByText(`Trace：${TRACE_ID_1.slice(0, 8)}…`)).toBeInTheDocument()
    // 检索请求携带 trace_id 与 URL 时间窗
    const hit = sqlCalls().some((c) => {
      const u = String(c[0])
      return (
        u.includes(`trace_id=${TRACE_ID_1}`) &&
        u.includes('start_time=2026-08-30T00%3A25%3A00.000Z') &&
        u.includes('end_time=2026-08-30T00%3A35%3A00.000Z')
      )
    })
    expect(hit).toBe(true)
  })

  it('match_mode=window_aggregate 明确标注「同时间窗候选，未精确定位」，不写成已定位根因', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        sql: {
          ...SQL_PAGE,
          trace_id: TRACE_ID_1,
          match_mode: 'window_aggregate',
          match_note: '窗口聚合结果，非特定请求定位',
          availability: AVAILABILITY_READY,
        },
      }),
    )
    renderPage(`/apm-sql?trace_id=${TRACE_ID_1}`)

    expect(await screen.findByText(/同时间窗候选，未精确定位/)).toBeInTheDocument()
    expect(screen.getByText('窗口聚合结果，非特定请求定位')).toBeInTheDocument()
    expect(screen.queryByText(/已按 Trace 精确定位/)).not.toBeInTheDocument()
  })

  it('旧后端缺 match_mode：提示状态信息不足，按时间窗聚合理解', async () => {
    vi.stubGlobal('fetch', mockFetch({ sql: { ...SQL_PAGE, trace_id: TRACE_ID_1 } }))
    renderPage(`/apm-sql?trace_id=${TRACE_ID_1}`)

    expect(await screen.findByText(/状态信息不足：当前服务未返回定位语义/)).toBeInTheDocument()
    expect(screen.getByText(/不代表该请求的慢 SQL/)).toBeInTheDocument()
  })

  it('非法 trace_id 忽略并提示，检索不携带 trace_id', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage('/apm-sql?trace_id=bad-id')

    expect(await screen.findByText(/URL 参数 trace_id 格式非法/)).toBeInTheDocument()
    await waitFor(() => expect(sqlCalls().length).toBeGreaterThan(0))
    expect(sqlCalls().some((c) => String(c[0]).includes('trace_id='))).toBe(false)
  })

  it('清除 Trace 定位后按窗口聚合重新查询', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        sql: {
          ...SQL_PAGE,
          trace_id: TRACE_ID_1,
          match_mode: 'trace_exact',
          match_note: '',
          availability: AVAILABILITY_READY,
        },
      }),
    )
    renderPage(`/apm-sql?trace_id=${TRACE_ID_1}`)
    await screen.findByText(/已按 Trace 精确定位/)

    fireEvent.click(screen.getByRole('button', { name: '清除 Trace 定位' }))
    await waitFor(() => {
      const calls = sqlCalls()
      const last = String(calls[calls.length - 1][0])
      expect(last.includes('trace_id=')).toBe(false)
    })
  })

  it('存储不可用（UNAVAILABLE）：显示「调用链存储暂不可用」，不展示零值表格', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({
        sql: {
          ...SQL_PAGE,
          list: [],
          total: 0,
          availability: {
            ...AVAILABILITY_READY,
            query_state: 'UNAVAILABLE',
            reason_codes: ['STORAGE_UNAVAILABLE'],
            observed_sources: [],
          },
        },
      }),
    )
    renderPage()

    expect(await screen.findByText('调用链存储暂不可用')).toBeInTheDocument()
    expect(screen.queryByText('abc123def4567890…')).not.toBeInTheDocument()
    expect(screen.queryByText('暂无数据')).not.toBeInTheDocument()
  })
})
