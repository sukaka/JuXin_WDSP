import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from 'antd'
import dayjs from 'dayjs'
import SiteAccessTrendsPage from '../SiteAccessTrendsPage'
import type { SiteAccessTrendDomainsData, SiteTrafficData, SiteTrafficItem } from '../../../types'

vi.mock('../../../api/analytics', () => ({
  analyticsApi: {
    siteTraffic: vi.fn(),
    siteAccessTrendDomains: vi.fn(),
  },
}))

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为桩组件 */
vi.mock('../../../components/EChart', () => ({
  default: () => <div data-testid="echart-stub" />,
}))

import { analyticsApi } from '../../../api/analytics'

const mockedSiteTraffic = vi.mocked(analyticsApi.siteTraffic)
const mockedDomains = vi.mocked(analyticsApi.siteAccessTrendDomains)

/** 冻结时刻：2026-09-19T12:00:00Z */
const NOW = new Date('2026-09-19T12:00:00Z')

const baseSummary = {
  total_requests: 30000,
  total_bytes_in: 10 * 1024 * 1024,
  total_bytes_out: 24 * 1024 * 1024,
  unique_ips: 321,
  blocked_requests: 12,
  peak_bucket_requests: 888,
}

const appRow: SiteTrafficItem = {
  application_id: 'app-1',
  app_code: 'shop',
  app_name: '商城站点',
  total_requests: 12345,
  total_bytes_in: 5 * 1024 * 1024,
  total_bytes_out: 12 * 1024 * 1024,
  unique_ips: 123,
  blocked_requests: 3,
  series: [
    {
      t: '2026-09-19T10:00:00Z',
      requests: 100,
      bytes_in: 1024,
      bytes_out: 2048,
      unique_ips: 10,
      blocked_requests: 1,
    },
    {
      t: '2026-09-19T11:00:00Z',
      requests: 200,
      bytes_in: 2048,
      bytes_out: 4096,
      unique_ips: 20,
      blocked_requests: 2,
    },
  ],
}

function trafficData(overrides: Partial<SiteTrafficData> = {}): SiteTrafficData {
  return {
    start: '2026-09-19T00:00:00Z',
    end: '2026-09-19T12:00:00Z',
    granularity: 'hour',
    source: 'access_logs',
    summary: { ...baseSummary },
    items: [{ ...appRow }],
    ...overrides,
  }
}

const domainData: SiteAccessTrendDomainsData = {
  start: '2026-09-19T00:00:00Z',
  end: '2026-09-19T12:00:00Z',
  granularity: 'hour',
  items: [
    {
      domain: 'www.example.com',
      total_requests: 8000,
      series: [{ t: '2026-09-19T10:00:00Z', requests: 50 }],
    },
  ],
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <App>{ui}</App>
    </QueryClientProvider>,
  )
}

/** 伪定时器下刷新 microtask，让 react-query 完成首次取数 */
async function flush() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0)
  })
}

describe('SiteAccessTrendsPage', () => {
  beforeEach(() => {
    mockedSiteTraffic.mockReset()
    mockedDomains.mockReset()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('默认「今天」档渲染：应用行、概览统计卡片、数据来源口径说明', async () => {
    mockedSiteTraffic.mockResolvedValue(trafficData())
    wrap(<SiteAccessTrendsPage />)
    await waitFor(() => {
      expect(screen.getByText('商城站点')).toBeInTheDocument()
    })
    expect(screen.getByText('站点流量分析')).toBeInTheDocument()
    expect(screen.getByText('shop')).toBeInTheDocument()
    expect(screen.getByText('12,345')).toBeInTheDocument()
    expect(screen.getByText('12.0 MB')).toBeInTheDocument()
    // 概览统计卡片
    expect(screen.getByText('30,000')).toBeInTheDocument()
    expect(screen.getByText('10.0 MB')).toBeInTheDocument()
    expect(screen.getByText('24.0 MB')).toBeInTheDocument()
    expect(screen.getByText(/峰值桶请求数 888/)).toBeInTheDocument()
    // 数据来源口径副标题
    expect(screen.getByText(/近30天来自按日聚合表/)).toBeInTheDocument()
    // 非实时档不显示自动刷新提示
    expect(screen.queryByText('每30秒自动刷新')).toBeNull()
  })

  it('四档切换换算正确的 start_time/end_time（实时=最近1小时，今天=当日零点，近7天/近30天回溯）', async () => {
    vi.useFakeTimers({ now: NOW })
    mockedSiteTraffic.mockResolvedValue(trafficData())
    wrap(<SiteAccessTrendsPage />)
    await flush()

    // 默认「今天」：当日零点（本地时区）至今
    expect(mockedSiteTraffic).toHaveBeenLastCalledWith({
      start_time: dayjs().startOf('day').toISOString(),
      end_time: dayjs().toISOString(),
    })

    fireEvent.click(screen.getByText('实时'))
    await flush()
    expect(mockedSiteTraffic).toHaveBeenLastCalledWith({
      start_time: '2026-09-19T11:00:00.000Z',
      end_time: '2026-09-19T12:00:00.000Z',
    })

    fireEvent.click(screen.getByText('近7天'))
    await flush()
    expect(mockedSiteTraffic).toHaveBeenLastCalledWith({
      start_time: '2026-09-12T12:00:00.000Z',
      end_time: '2026-09-19T12:00:00.000Z',
    })

    fireEvent.click(screen.getByText('近30天'))
    await flush()
    expect(mockedSiteTraffic).toHaveBeenLastCalledWith({
      start_time: '2026-08-20T12:00:00.000Z',
      end_time: '2026-09-19T12:00:00.000Z',
    })
  })

  it('实时档显示「每30秒自动刷新」提示并每 30 秒自动重新取数，切走后停止', async () => {
    vi.useFakeTimers({ now: NOW })
    mockedSiteTraffic.mockResolvedValue(trafficData())
    wrap(<SiteAccessTrendsPage />)
    await flush()
    const atStart = mockedSiteTraffic.mock.calls.length

    fireEvent.click(screen.getByText('实时'))
    await flush()
    expect(screen.getByText('每30秒自动刷新')).toBeInTheDocument()
    expect(mockedSiteTraffic.mock.calls.length).toBe(atStart + 1)

    // 30 秒间隔触发一次自动刷新
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(mockedSiteTraffic.mock.calls.length).toBeGreaterThanOrEqual(atStart + 2)

    // 切回「今天」后不再自动刷新（实时档的轮询已停止）
    fireEvent.click(screen.getByText('今天'))
    await flush()
    const atSwitchBack = mockedSiteTraffic.mock.calls.length
    await act(async () => {
      await vi.advanceTimersByTimeAsync(90_000)
    })
    expect(mockedSiteTraffic.mock.calls.length).toBe(atSwitchBack)
  })

  it('近30天档 unique_ips/blocked_requests 为 null 时表格与统计卡片显示「-」', async () => {
    vi.useFakeTimers({ now: NOW })
    mockedSiteTraffic.mockResolvedValue(
      trafficData({
        summary: { ...baseSummary, unique_ips: null, blocked_requests: null },
        items: [{ ...appRow, unique_ips: null, blocked_requests: null }],
      }),
    )
    wrap(<SiteAccessTrendsPage />)
    await flush()
    fireEvent.click(screen.getByText('近30天'))
    await flush()
    expect(mockedSiteTraffic).toHaveBeenLastCalledWith({
      start_time: '2026-08-20T12:00:00.000Z',
      end_time: '2026-09-19T12:00:00.000Z',
    })

    // 表格行：独立IP、拦截数两列显示占位符
    const row = screen.getByText('商城站点').closest('tr') as HTMLElement
    expect(within(row).getAllByText('-').length).toBeGreaterThanOrEqual(2)
    // 概览统计卡片：独立访客IP、被拦截请求数显示占位符
    const ipCard = screen.getByText('独立访客IP').closest('.ant-card') as HTMLElement
    expect(ipCard).toHaveTextContent('-')
    const blockCard = screen.getByText('被拦截请求数').closest('.ant-card') as HTMLElement
    expect(blockCard).toHaveTextContent('-')
  })

  it('点击「详情」打开站点流量详情抽屉：大图趋势、站点统计与口径说明（带 application_id 查询）', async () => {
    mockedSiteTraffic.mockResolvedValue(trafficData())
    wrap(<SiteAccessTrendsPage />)
    await waitFor(() => {
      expect(screen.getByText('商城站点')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('详情'))
    await waitFor(() => {
      expect(screen.getByText('站点流量详情：商城站点')).toBeInTheDocument()
    })
    await waitFor(() => {
      expect(mockedSiteTraffic).toHaveBeenCalledWith(
        expect.objectContaining({ application_id: 'app-1' }),
      )
    })

    const drawer = document.querySelector('.ant-drawer-content-wrapper') as HTMLElement
    await waitFor(() => {
      expect(within(drawer).getByTestId('echart-stub')).toBeInTheDocument()
    })
    // 站点统计小卡片
    expect(within(drawer).getByText('总请求数')).toBeInTheDocument()
    expect(within(drawer).getByText('流出流量')).toBeInTheDocument()
    expect(within(drawer).getByText('独立访客IP')).toBeInTheDocument()
    expect(within(drawer).getByText('被拦截请求数')).toBeInTheDocument()
    expect(within(drawer).getByText('峰值桶请求数')).toBeInTheDocument()
    // 口径说明：时间范围 / 粒度（中文）/ 数据来源
    expect(within(drawer).getByText('时间范围')).toBeInTheDocument()
    expect(within(drawer).getByText('统计粒度')).toBeInTheDocument()
    expect(within(drawer).getByText('小时')).toBeInTheDocument()
    expect(within(drawer).getByText(/访问日志实时聚合（access_logs）/)).toBeInTheDocument()
  })

  it('7 天内档位展开行触发域名趋势查询（今天档映射 range=today）', async () => {
    mockedSiteTraffic.mockResolvedValue(trafficData())
    mockedDomains.mockResolvedValue(domainData)
    const { container } = wrap(<SiteAccessTrendsPage />)
    await waitFor(() => {
      expect(screen.getByText('商城站点')).toBeInTheDocument()
    })
    const expandIcon = container.querySelector('.ant-table-row-expand-icon')
    expect(expandIcon).toBeTruthy()
    fireEvent.click(expandIcon as Element)
    await waitFor(() => {
      expect(screen.getByText('www.example.com')).toBeInTheDocument()
    })
    expect(mockedDomains).toHaveBeenCalledWith({
      application_id: 'app-1',
      range: 'today',
    })
  })

  it('实时档展开行域名趋势映射 range=1h', async () => {
    mockedSiteTraffic.mockResolvedValue(trafficData())
    mockedDomains.mockResolvedValue(domainData)
    const { container } = wrap(<SiteAccessTrendsPage />)
    await waitFor(() => {
      expect(screen.getByText('商城站点')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('实时'))
    // 切档后新查询无缓存数据，表格行短暂消失；等行重新渲染后再找展开按钮
    await waitFor(() => {
      expect(screen.getByText('每30秒自动刷新')).toBeInTheDocument()
      expect(screen.getByText('商城站点')).toBeInTheDocument()
    })
    fireEvent.click(container.querySelector('.ant-table-row-expand-icon') as Element)
    await waitFor(() => {
      expect(screen.getByText('www.example.com')).toBeInTheDocument()
    })
    expect(mockedDomains).toHaveBeenCalledWith({
      application_id: 'app-1',
      range: '1h',
    })
  })

  it('近30天档展开行显示「域名明细仅支持 7 天内范围」提示，不请求域名接口、不报错', async () => {
    mockedSiteTraffic.mockResolvedValue(trafficData())
    const { container } = wrap(<SiteAccessTrendsPage />)
    await waitFor(() => {
      expect(screen.getByText('商城站点')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('近30天'))
    await waitFor(() => {
      expect(mockedSiteTraffic.mock.calls.length).toBe(2)
      expect(screen.getByText('商城站点')).toBeInTheDocument()
    })
    fireEvent.click(container.querySelector('.ant-table-row-expand-icon') as Element)
    await waitFor(() => {
      expect(screen.getByText('域名明细仅支持 7 天内范围')).toBeInTheDocument()
    })
    expect(mockedDomains).not.toHaveBeenCalled()
    expect(screen.queryByText('加载域名访问趋势失败')).toBeNull()
  })

  it('空数据时展示空状态', async () => {
    mockedSiteTraffic.mockResolvedValue(
      trafficData({
        summary: { ...baseSummary, total_requests: 0, peak_bucket_requests: 0 },
        items: [],
      }),
    )
    const { container } = wrap(<SiteAccessTrendsPage />)
    await waitFor(() => {
      expect(container.querySelector('.ant-empty')).toBeTruthy()
    })
    expect(mockedSiteTraffic).toHaveBeenCalled()
  })
})
