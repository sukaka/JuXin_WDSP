import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from 'antd'
import SiteAccessTrendsPage from '../SiteAccessTrendsPage'

vi.mock('../../../api/analytics', () => ({
  analyticsApi: {
    siteAccessTrends: vi.fn(),
    siteAccessTrendDomains: vi.fn(),
  },
}))

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为桩组件 */
vi.mock('../../../components/EChart', () => ({
  default: () => <div data-testid="echart-stub" />,
}))

import { analyticsApi } from '../../../api/analytics'

const appRow = {
  application_id: 'app-1',
  app_code: 'shop',
  app_name: '商城站点',
  total_requests: 12345,
  series: [
    { t: '2026-08-15T00:00:00Z', requests: 100 },
    { t: '2026-08-15T01:00:00Z', requests: 200 },
  ],
}

const domainRow = {
  domain: 'www.example.com',
  total_requests: 8000,
  series: [{ t: '2026-08-15T00:00:00Z', requests: 50 }],
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <App>{ui}</App>
    </QueryClientProvider>,
  )
}

describe('SiteAccessTrendsPage', () => {
  beforeEach(() => {
    vi.mocked(analyticsApi.siteAccessTrends).mockReset()
    vi.mocked(analyticsApi.siteAccessTrendDomains).mockReset()
  })

  it('默认按「今天」查询并渲染应用行（名称 + 编码 + 千分位访问量）', async () => {
    vi.mocked(analyticsApi.siteAccessTrends).mockResolvedValue({
      start: '2026-08-15T00:00:00Z',
      end: '2026-08-15T12:00:00Z',
      granularity: '1h',
      items: [appRow],
    })
    wrap(<SiteAccessTrendsPage />)
    await waitFor(() => {
      expect(screen.getByText('商城站点')).toBeInTheDocument()
    })
    expect(screen.getByText('shop')).toBeInTheDocument()
    expect(screen.getByText('12,345')).toBeInTheDocument()
    expect(analyticsApi.siteAccessTrends).toHaveBeenCalledWith({ range: 'today' })
    // 保留期提示
    expect(screen.getByText(/访问明细数据保留期约 7 天/)).toBeInTheDocument()
  })

  it('展开应用行触发域名趋势查询并渲染域名小表', async () => {
    vi.mocked(analyticsApi.siteAccessTrends).mockResolvedValue({
      start: '2026-08-15T00:00:00Z',
      end: '2026-08-15T12:00:00Z',
      granularity: '1h',
      items: [appRow],
    })
    vi.mocked(analyticsApi.siteAccessTrendDomains).mockResolvedValue({
      start: '2026-08-15T00:00:00Z',
      end: '2026-08-15T12:00:00Z',
      granularity: '1h',
      items: [domainRow],
    })
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
    expect(analyticsApi.siteAccessTrendDomains).toHaveBeenCalledWith({
      application_id: 'app-1',
      range: 'today',
    })
  })

  it('空数据时展示空状态', async () => {
    vi.mocked(analyticsApi.siteAccessTrends).mockResolvedValue({
      start: '2026-08-15T00:00:00Z',
      end: '2026-08-15T12:00:00Z',
      granularity: '1h',
      items: [],
    })
    const { container } = wrap(<SiteAccessTrendsPage />)
    await waitFor(() => {
      expect(container.querySelector('.ant-empty')).toBeTruthy()
    })
    expect(analyticsApi.siteAccessTrends).toHaveBeenCalled()
  })
})
