import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiCrossBorderPage from '../ApiCrossBorderPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为捕获 option 的桩组件 */
const chartProps = vi.hoisted(() => [] as { option: unknown; height?: number }[])
vi.mock('../../../components/EChart', () => ({
  default: (props: { option: unknown; height?: number }) => {
    chartProps.push(props)
    return <div data-testid="echart-stub" />
  },
}))

function lastChartOption(): {
  xAxis: { data: string[] }
  series: { name: string; data: number[] }[]
} {
  const last = chartProps[chartProps.length - 1]
  expect(last).toBeTruthy()
  return JSON.parse(JSON.stringify(last.option))
}

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
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

/** GeoIP 可用时的完整看板 + 明细（聚合各维度取不同取值，便于分 Tab 断言） */
const crossBorderData = {
  geo_enabled: true,
  home_regions: ['CN', 'HK'],
  dashboard: {
    days: 7,
    summary: { total_events: 36, country_count: 2, endpoint_count: 3, high_risk_count: 4 },
    by_country: [{ country: 'US', event_count: 20, endpoint_count: 2, data_types: ['phone'] }],
    by_country_type: [{ country: 'JP', data_type: 'id_card', event_count: 7 }],
    by_endpoint: [{ endpoint_key: 'GET /v1/orders/{id}', event_count: 9, country_count: 1 }],
    trend: [
      { date: '2026-08-18', event_count: 10 },
      { date: '2026-08-19', event_count: 26 },
    ],
  },
  events: {
    items: [
      {
        id: 'cb-1',
        occurred_at: '2026-08-19T08:00:00Z',
        client_ip: '203.0.113.9',
        country: 'SG',
        asn: null,
        endpoint_key: 'POST /v1/pay',
        identity_fingerprint: '',
        data_types: ['bank_card'],
        direction: 'IN',
        risk_level: 'MEDIUM',
        source_event_id: 'sev-1',
        created_at: '2026-08-19T08:00:01Z',
      },
    ],
    page: 1,
    page_size: 20,
    total: 1,
  },
}

/** GeoIP 未加载时的降级响应（看板为空、事件为空） */
const geoDisabledData = {
  geo_enabled: false,
  home_regions: ['CN'],
  dashboard: {
    days: 7,
    summary: { total_events: 0, country_count: 0, endpoint_count: 0, high_risk_count: 0 },
    by_country: [],
    by_country_type: [],
    by_endpoint: [],
    trend: [],
  },
  events: { items: [], page: 1, page_size: 20, total: 0 },
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiCrossBorderPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 在指定 placeholder 的 Input.Search 上输入并触发搜索 */
function triggerSearch(placeholder: string, value: string) {
  const input = screen.getByPlaceholderText(placeholder)
  fireEvent.change(input, { target: { value } })
  const wrapper = input.closest('.ant-input-search')
  const btn = wrapper?.querySelector('.ant-input-search-btn')
  expect(btn).toBeTruthy()
  fireEvent.click(btn as HTMLElement)
}

/** 展开指定 placeholder 的 Select 并点击选项（与表头按 placeholder 类消歧） */
async function selectOption(placeholder: string, optionText: string) {
  const candidates = screen.getAllByText(placeholder)
  const ph = candidates.find((el) => el.closest('.ant-select-placeholder')) ?? candidates[0]
  fireEvent.mouseDown(ph)
  const options = await screen.findAllByText(optionText)
  const option = options.find((el) => el.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

describe('ApiCrossBorderPage', () => {
  beforeEach(() => {
    chartProps.length = 0
    useAuthStore.setState({ user: makeUser(['api_data.read']), csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('geo_enabled=false：降级提示卡 + 空看板，不误报识别能力', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: geoDisabledData })),
      ),
    )
    renderPage()
    expect(await screen.findByText('GeoIP 数据源未加载，跨境识别已降级')).toBeInTheDocument()
    expect(screen.getByText(/看板展示的是历史观察数据/)).toBeInTheDocument()
    // 本土地区基准仍如实展示中文
    expect(screen.getByText('本土地区判定基准：')).toBeInTheDocument()
    expect(screen.getByText('中国')).toBeInTheDocument()
    expect(screen.queryByText('CN')).not.toBeInTheDocument()
  })

  it('看板：汇总卡片/home_regions/趋势图/按国家聚合表', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: crossBorderData })),
      ),
    )
    renderPage()
    await screen.findByText('POST /v1/pay')
    // geo 可用时不出现降级提示
    expect(screen.queryByText('GeoIP 数据源未加载，跨境识别已降级')).not.toBeInTheDocument()

    const statOf = (title: string) => screen.getByText(title).closest('.ant-statistic') as HTMLElement
    expect(statOf('跨境事件').textContent).toContain('36')
    expect(statOf('涉及国家/地区').textContent).toContain('2')
    expect(statOf('涉及 API').textContent).toContain('3')
    expect(statOf('高风险事件').textContent).toContain('4')

    // 本土地区判定基准标签（中文化）
    expect(screen.getByText('中国')).toBeInTheDocument()
    expect(screen.getByText('中国香港')).toBeInTheDocument()
    expect(screen.queryByText('CN')).not.toBeInTheDocument()
    expect(screen.queryByText('HK')).not.toBeInTheDocument()

    // 趋势图
    await waitFor(() => expect(chartProps.length).toBeGreaterThan(0))
    const option = lastChartOption()
    expect(option.xAxis.data).toEqual(['2026-08-18', '2026-08-19'])
    expect(option.series[0].data).toEqual([10, 26])

    // 默认「按国家/地区」聚合页签
    expect(screen.getByText('美国')).toBeInTheDocument()
    expect(screen.getByText('手机号')).toBeInTheDocument()
  })

  it('聚合页签：国家×敏感类型 / 按端点 表格数据', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: crossBorderData })),
      ),
    )
    renderPage()
    await screen.findByText('POST /v1/pay')

    fireEvent.click(screen.getByRole('tab', { name: '国家×敏感类型' }))
    expect(await screen.findByText('日本')).toBeInTheDocument()
    expect(screen.getByText('身份证号')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('tab', { name: '按 API' }))
    expect(await screen.findByText('GET /v1/orders/{id}')).toBeInTheDocument()
  })

  it('明细分页：方向/风险/敏感类型/客户端 IP 渲染，过滤携带查询参数', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: crossBorderData })),
      ),
    )
    renderPage()
    const row = (await screen.findByText('POST /v1/pay')).closest('tr') as HTMLElement
    expect(within(row).getByText('新加坡')).toBeInTheDocument()
    expect(within(row).getByText('入境')).toBeInTheDocument()
    expect(within(row).getByText('中')).toBeInTheDocument()
    expect(within(row).getByText('银行卡号')).toBeInTheDocument()
    expect(within(row).getByText('203.0.113.9')).toBeInTheDocument()

    // 国家码过滤（小写输入归一为大写）
    triggerSearch('国家码（两位，如 US）', 'us')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('country=US'))).toBe(true)
    })

    await selectOption('方向', '出境')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('direction=OUT'))).toBe(true)
    })

    await selectOption('风险等级', '高')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('risk_level=HIGH'))).toBe(true)
    })

    triggerSearch('API 键（精确匹配）', 'POST /v1/pay')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('endpoint_key='))).toBe(true)
    })
  })
})
