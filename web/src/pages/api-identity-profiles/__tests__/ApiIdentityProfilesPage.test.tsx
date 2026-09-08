import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from 'antd'
import ApiIdentityProfilesPage from '../ApiIdentityProfilesPage'

vi.mock('../../../api/apiSecurity', () => ({
  apiIdentityProfilesApi: {
    list: vi.fn(),
    detail: vi.fn(),
  },
}))

import { apiIdentityProfilesApi } from '../../../api/apiSecurity'

const row = {
  identity_fingerprint: 'auth:deadbeef',
  endpoint_id: '11111111-1111-1111-1111-111111111111',
  endpoint_key: 'GET /api/v1/orders/{id}',
  auth_type: 'bearer_or_basic',
  request_count: 42,
  first_seen_at: '2026-08-01T00:00:00Z',
  last_seen_at: '2026-08-08T12:00:00Z',
  quality_score: 75,
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <App>{ui}</App>
    </QueryClientProvider>,
  )
}

describe('ApiIdentityProfilesPage', () => {
  beforeEach(() => {
    vi.mocked(apiIdentityProfilesApi.list).mockReset()
    vi.mocked(apiIdentityProfilesApi.detail).mockReset()
  })

  it('渲染身份模型列表与质量分', async () => {
    vi.mocked(apiIdentityProfilesApi.list).mockResolvedValue({
      items: [row],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiIdentityProfilesPage />)
    await waitFor(() => {
      expect(screen.getByText('auth:deadbeef')).toBeInTheDocument()
    })
    expect(screen.getByText('GET /api/v1/orders/{id}')).toBeInTheDocument()
    expect(screen.getByText('75')).toBeInTheDocument()
    expect(apiIdentityProfilesApi.list).toHaveBeenCalled()
  })

  it('点击行打开详情抽屉：画像 + 风险评估 + 近期事件', async () => {
    vi.mocked(apiIdentityProfilesApi.list).mockResolvedValue({
      items: [row],
      total: 1,
      page: 1,
      page_size: 20,
    })
    vi.mocked(apiIdentityProfilesApi.detail).mockResolvedValue({
      profile: row,
      risk: {
        level: 'MEDIUM',
        likelihood: 3,
        severity: 2,
        indicators: {
          events_total: 12,
          events_24h: 4,
          risky_events_total: 3,
          blocked_events_total: 1,
          distinct_endpoints: 2,
          active_days: 7,
          max_risk_score: 55,
        },
        summary: '可能性3级 × 严重程度2级 → 风险MEDIUM',
      },
      recent_events: [
        {
          id: 'ev-1',
          request_id: 'req-1',
          endpoint_key: 'GET /api/v1/orders/{id}',
          risk_score: 55,
          risk_level: 'MEDIUM',
          final_action: 'OBSERVE',
          occurred_at: '2026-08-08T11:00:00Z',
          auth_type: 'bearer_or_basic',
        },
      ],
    })
    wrap(<ApiIdentityProfilesPage />)
    await waitFor(() => {
      expect(screen.getByText('auth:deadbeef')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('auth:deadbeef'))
    await waitFor(() => {
      expect(screen.getByText('身份模型详情')).toBeInTheDocument()
    })
    expect(apiIdentityProfilesApi.detail).toHaveBeenCalledWith({
      identity_fingerprint: 'auth:deadbeef',
      endpoint_id: '11111111-1111-1111-1111-111111111111',
    })
    await waitFor(() => {
      expect(screen.getByText('风险级别')).toBeInTheDocument()
      expect(screen.getByText('中等')).toBeInTheDocument()
      expect(screen.getByText('3 / 5')).toBeInTheDocument()
      expect(screen.getByText('近期事件（最近 10 条）')).toBeInTheDocument()
    })
  })
})
