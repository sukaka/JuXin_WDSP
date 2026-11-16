import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApplicationAssetValueCard from '../ApplicationAssetValueCard'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function setPermissions(permissions: string[]) {
  const user: CurrentUser = {
    id: 'u1',
    username: 'asset-reader',
    display_name: '资产读取员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
  useAuthStore.setState({ user, csrfToken: null, initialized: true })
}

function response(status: number, data: unknown): Response {
  return new Response(
    JSON.stringify({
      code: status === 200 ? 'SUCCESS' : 'INTERNAL_ERROR',
      message: status === 200 ? 'ok' : 'score storage unavailable',
      data,
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderCard() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ApplicationAssetValueCard applicationId="app-1" />
    </QueryClientProvider>,
  )
}

describe('ApplicationAssetValueCard', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('展示真实聚合、评分覆盖率、等级分布与维度均值', async () => {
    setPermissions(['api_asset.read'])
    const fetchMock = vi.fn().mockResolvedValue(
      response(200, {
        application_id: 'app-1',
        level: 'HIGH',
        average_score: 14.5,
        max_score: 20,
        max_total: 26,
        endpoint_count: 3,
        scored_count: 2,
        unscored_count: 1,
        level_distribution: { HIGH: 1, MEDIUM: 1 },
        dimensions: [{ name: 'data_sensitivity', average_score: 2.5, max: 3 }],
        generated_at: '2026-11-15T04:00:00Z',
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    renderCard()
    const average = await screen.findByText('平均得分')
    expect(average.closest('.ant-statistic')).toHaveTextContent('14.50')
    expect(screen.getByText('20')).toBeInTheDocument()
    const coverage = screen.getByText('评分覆盖率')
    expect(coverage.closest('.ant-statistic')).toHaveTextContent('66.67')
    expect(screen.getByText('已评分 2，未评分 1')).toBeInTheDocument()
    expect(screen.getByText('高：1')).toBeInTheDocument()
    expect(screen.getByText('中：1')).toBeInTheDocument()
    expect(screen.getByText('data_sensitivity')).toBeInTheDocument()
    expect(screen.getByText('2.50')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/api-security/applications/app-1/asset-value',
      expect.objectContaining({ method: 'GET' }),
    )
  })

  it('无评分时明确披露，不将空数据冒充低分', async () => {
    setPermissions(['api_asset.read'])
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        response(200, {
          application_id: 'app-1',
          level: '',
          average_score: 0,
          max_score: 0,
          max_total: 26,
          endpoint_count: 2,
          scored_count: 0,
          unscored_count: 2,
          level_distribution: {},
          dimensions: [],
          generated_at: '2026-11-15T04:00:00Z',
        }),
      ),
    )
    renderCard()
    expect(
      await screen.findByText('该应用尚无可聚合的接口评分'),
    ).toBeInTheDocument()
    expect(screen.getByText('未评分')).toBeInTheDocument()
    expect(screen.queryByText('0.00')).not.toBeInTheDocument()
  })

  it('无权限时不查询', () => {
    setPermissions([])
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderCard()
    expect(
      screen.getByText('缺少 api_asset.read 权限，无法查看应用资产价值'),
    ).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('存储失败时展示真实错误', async () => {
    setPermissions(['api_asset.read'])
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(500, null)))
    renderCard()
    expect(
      await screen.findByText('score storage unavailable'),
    ).toBeInTheDocument()
  })
})
