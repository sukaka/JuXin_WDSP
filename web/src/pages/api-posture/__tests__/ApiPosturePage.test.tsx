import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { App } from 'antd'
import ApiPosturePage from '../ApiPosturePage'
import { ApiError } from '../../../api/client'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

vi.mock('../../../api/apiPosture', () => ({
  apiPostureOverviewApi: {
    overview: vi.fn(),
    trends: vi.fn(),
    sources: vi.fn(),
    targets: vi.fn(),
  },
}))

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为桩组件并透出 option JSON 供中文标签断言 */
vi.mock('../../../components/EChart', () => ({
  default: ({ option, ariaLabel }: { option?: unknown; ariaLabel?: string }) => (
    <div data-testid="echart-stub" data-label={ariaLabel} data-option={JSON.stringify(option ?? {})} />
  ),
}))

import { apiPostureOverviewApi } from '../../../api/apiPosture'

const overviewData = {
  generated_at: '2026-08-19T04:00:00Z',
  traffic_24h: 1280,
  protected_24h: 37,
  assets_total: 96,
  assets_new_24h: 3,
  shadow_open: 2,
  zombie_total: 1,
  deprecated_total: 4,
  sensitive_endpoints: 12,
  high_risk_assets: 5,
  unauthenticated_endpoints: 8,
  models_pending: 6,
  schema_deviations_24h: 9,
}

const trendsData = {
  days: 7,
  points: [
    {
      date: '2026-08-13',
      traffic: 100,
      protected: 3,
      risk: 1,
      new_endpoints: 0,
      schema_deviations: 2,
      sensitive_hits: 1,
    },
    {
      date: '2026-08-14',
      traffic: 120,
      protected: 5,
      risk: 0,
      new_endpoints: 2,
      schema_deviations: 0,
      sensitive_hits: 0,
    },
  ],
}

/** W10-SEC 访问来源 mock（GeoIP 未启用降级形态） */
const sourcesData = {
  days: 7,
  geo_enabled: false,
  geo_truncated: false,
  top_client_ips: [
    { client_ip: '1.2.3.*', count: 12 },
    { client_ip: '2001:db8:85a3:*', count: 5 },
  ],
  geo_scopes: [],
  top_countries: [],
  top_identities: [{ fingerprint: 'abcdef123456…', count: 8 }],
  auth_types: [
    { auth_type: 'api_key', count: 9 },
    { auth_type: '', count: 3 },
  ],
}

/** W10-SEC 访问来源 mock（GeoIP 启用形态） */
const sourcesGeoData = {
  ...sourcesData,
  geo_enabled: true,
  geo_scopes: [
    { scope: 'HOME', count: 20 },
    { scope: 'FOREIGN', count: 6 },
    { scope: 'INTERNAL', count: 4 },
    { scope: 'UNKNOWN', count: 2 },
  ],
  top_countries: [
    { country: 'CN', count: 20 },
    { country: 'US', count: 6 },
  ],
}

/** W10-SEC 访问目标排名 mock */
const targetsData = {
  days: 7,
  top_by_traffic: [
    { endpoint_id: 'e1', endpoint_key: 'GET /pay/{id}', request_count: 100 },
  ],
  top_by_findings: [
    { endpoint_id: 'e1', endpoint_key: 'GET /pay/{id}', findings_count: 4 },
  ],
  top_applications: [
    { application_id: 'a1', application_name: '支付中心', request_count: 150 },
    { application_name: '', request_count: 9 },
  ],
  top_sensitive: [
    {
      endpoint_id: 'e1',
      endpoint_key: 'GET /pay/{id}',
      request_count: 100,
      sensitive_fields: 2,
    },
  ],
  top_high_risk: [
    {
      endpoint_id: 'e1',
      endpoint_key: 'GET /pay/{id}',
      asset_value: 'HIGH',
      request_count: 100,
    },
  ],
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <App>{ui}</App>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiPosturePage', () => {
  beforeEach(() => {
    vi.mocked(apiPostureOverviewApi.overview).mockReset()
    vi.mocked(apiPostureOverviewApi.trends).mockReset()
    vi.mocked(apiPostureOverviewApi.sources).mockReset()
    vi.mocked(apiPostureOverviewApi.targets).mockReset()
    vi.mocked(apiPostureOverviewApi.overview).mockResolvedValue(overviewData)
    vi.mocked(apiPostureOverviewApi.trends).mockResolvedValue(trendsData)
    vi.mocked(apiPostureOverviewApi.sources).mockResolvedValue(sourcesData)
    vi.mocked(apiPostureOverviewApi.targets).mockResolvedValue(targetsData)
    // 默认仅页面自身所需权限（api_runtime.read），不含钻取目标的 api_model.read
    useAuthStore.setState({
      user: makeUser(['api_runtime.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  it('渲染 12 项核心指标卡与两张趋势图，默认按 7 天查询', async () => {
    wrap(<ApiPosturePage />)
    // 等数据就绪（antd 6 Statistic 数字拆分在多个 span 中，按容器 textContent 断言）
    await waitFor(() => {
      expect(
        screen.getByText('API访问量（24h）').closest('.ant-statistic'),
      ).toHaveTextContent('1,280')
    })
    // 指标标题全项
    for (const title of [
      '防护量（24h）',
      '资产总数',
      '新增API（24h）',
      '影子 API',
      '僵尸 API',
      '已下线 API',
      '涉敏API',
      '高风险API',
      '无认证API',
      '待确认模型',
      'Schema偏离（24h）',
    ]) {
      expect(screen.getByText(title)).toBeInTheDocument()
    }
    expect(
      screen.getByText('资产总数').closest('.ant-statistic'),
    ).toHaveTextContent('96')
    // 生成时间 + 两张趋势图（访问与防护 / 风险与资产）
    expect(screen.getByText(/生成时间：/)).toBeInTheDocument()
    expect(screen.getByText('访问与防护趋势')).toBeInTheDocument()
    expect(screen.getByText('风险与资产趋势')).toBeInTheDocument()
    expect(apiPostureOverviewApi.trends).toHaveBeenCalledWith(7)
  })

  it('W10-SEC：渲染访问来源与访问目标排名区块（GeoIP 降级如实提示）', async () => {
    wrap(<ApiPosturePage />)
    await waitFor(() => {
      expect(screen.getByText('访问来源（安全事件口径）')).toBeInTheDocument()
    })
    // 访问来源四卡片（geo_enabled=false → 地域卡片为降级提示、无图表）
    expect(screen.getByText('客户端 IP Top10（已脱敏）')).toBeInTheDocument()
    expect(screen.getByText('身份指纹 Top10（截断展示）')).toBeInTheDocument()
    expect(screen.getByText('认证类型分布')).toBeInTheDocument()
    expect(screen.getByText('访问地域（GeoIP）')).toBeInTheDocument()
    expect(
      screen.getByText('GeoIP 数据源未启用，地域维度不可用'),
    ).toBeInTheDocument()
    // 访问目标排名五榜单
    expect(screen.getByText('访问目标排名')).toBeInTheDocument()
    for (const title of [
      'API 访问量 Top10',
      'API 风险发现 Top10',
      '应用访问量 Top10',
      '涉敏 API 访问量 Top10',
      '高风险 API 访问量 Top10',
    ]) {
      expect(screen.getByText(title)).toBeInTheDocument()
    }
    // 图表桩计数：趋势 2 + 来源 3（地域降级无图）+ 目标 5 = 10
    await waitFor(() => {
      expect(screen.getAllByTestId('echart-stub')).toHaveLength(10)
    })
    expect(apiPostureOverviewApi.sources).toHaveBeenCalledWith(7)
    expect(apiPostureOverviewApi.targets).toHaveBeenCalledWith(7)
  })

  it('W10-SEC：GeoIP 启用时渲染地域分桶与国家 Top 图表（国家码、资产等级与认证方式中文化）', async () => {
    vi.mocked(apiPostureOverviewApi.sources).mockResolvedValue({
      ...sourcesGeoData,
      geo_truncated: true,
      auth_types: [
        { auth_type: 'bearer_or_basic', count: 5 },
        { auth_type: 'api_key', count: 9 },
        { auth_type: '', count: 3 },
      ],
    })
    wrap(<ApiPosturePage />)
    await waitFor(() => {
      expect(screen.getByText('访问地域（GeoIP）')).toBeInTheDocument()
    })
    expect(
      screen.queryByText('GeoIP 数据源未启用，地域维度不可用'),
    ).not.toBeInTheDocument()
    expect(screen.getByText(/去重客户端 IP 超上限/)).toBeInTheDocument()
    // 趋势 2 + 来源 5（IP/身份/认证 + 地域分桶与国家 Top 两张）+ 目标 5 = 12
    await waitFor(() => {
      expect(screen.getAllByTestId('echart-stub')).toHaveLength(12)
    })
    const charts = screen.getAllByTestId('echart-stub')
    const allOptionsText = charts.map((c) => c.getAttribute('data-option') ?? '').join('\n')
    expect(allOptionsText).toContain('中国')
    expect(allOptionsText).toContain('美国')
    expect(allOptionsText).toContain('令牌/基本认证')
    expect(allOptionsText).toContain('GET /pay/{id} [高]')
  })

  it('切换天数后按新 days 重新查询趋势', async () => {
    wrap(<ApiPosturePage />)
    await waitFor(() => {
      expect(apiPostureOverviewApi.trends).toHaveBeenCalledWith(7)
    })
    fireEvent.mouseDown(screen.getByRole('combobox'))
    const option = await screen.findByText('最近30天')
    fireEvent.click(option)
    await waitFor(() => {
      expect(apiPostureOverviewApi.trends).toHaveBeenCalledWith(30)
    })
    // 访问来源/目标排名与趋势共用 days 窗口
    await waitFor(() => {
      expect(apiPostureOverviewApi.sources).toHaveBeenCalledWith(30)
      expect(apiPostureOverviewApi.targets).toHaveBeenCalledWith(30)
    })
  })

  it('403 无权限：显示降级提示而非指标卡', async () => {
    vi.mocked(apiPostureOverviewApi.overview).mockRejectedValue(
      new ApiError('无权限', 'FORBIDDEN', 403),
    )
    wrap(<ApiPosturePage />)
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
    expect(screen.queryByText('资产总数')).not.toBeInTheDocument()
  })

  it('点击刷新按钮重新拉取总览与趋势', async () => {
    wrap(<ApiPosturePage />)
    // 等首轮数据就绪（加载中按钮处于 loading 态会忽略点击）
    await waitFor(() => {
      expect(
        screen.getByText('API访问量（24h）').closest('.ant-statistic'),
      ).toHaveTextContent('1,280')
    })
    expect(apiPostureOverviewApi.overview).toHaveBeenCalledTimes(1)
    expect(apiPostureOverviewApi.trends).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: /刷\s*新/ }))
    await waitFor(() => {
      expect(apiPostureOverviewApi.overview).toHaveBeenCalledTimes(2)
      expect(apiPostureOverviewApi.trends).toHaveBeenCalledTimes(2)
    })
  })

  it('待确认模型钻取：无 api_model.read 权限时禁用点击并提示', async () => {
    wrap(<ApiPosturePage />)
    await waitFor(() => {
      expect(screen.getByText('待确认模型')).toBeInTheDocument()
    })
    const card = screen.getByText('待确认模型').closest('.ant-card') as HTMLElement
    // 无权限：不可点击（无 hoverable），hover 提示原因而非落入 403 页
    expect(card.className).not.toContain('ant-card-hoverable')
    fireEvent.mouseOver(card)
    expect(await screen.findByText('无权限查看钻取目标页面')).toBeInTheDocument()
    // 其他无权限要求的钻取卡（如资产总数 → /api-endpoints）不受影响
    const assetsCard = screen.getByText('资产总数').closest('.ant-card') as HTMLElement
    expect(assetsCard.className).toContain('ant-card-hoverable')
  })

  it('待确认模型钻取：有 api_model.read 权限时可点击', async () => {
    useAuthStore.setState({
      user: makeUser(['api_runtime.read', 'api_model.read']),
      csrfToken: null,
      initialized: true,
    })
    wrap(<ApiPosturePage />)
    await waitFor(() => {
      expect(screen.getByText('待确认模型')).toBeInTheDocument()
    })
    const card = screen.getByText('待确认模型').closest('.ant-card') as HTMLElement
    expect(card.className).toContain('ant-card-hoverable')
  })
})
