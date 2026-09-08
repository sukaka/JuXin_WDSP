import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from 'antd'
import ApiAccessProfilesPage from '../ApiAccessProfilesPage'

vi.mock('../../../api/apiSecurity', () => ({
  apiBehaviorProfilesApi: {
    list: vi.fn(),
  },
  apiObjectModelsApi: {
    list: vi.fn(),
  },
}))

import { apiBehaviorProfilesApi, apiObjectModelsApi } from '../../../api/apiSecurity'

const behaviorRow = {
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  endpoint_id: '11111111-1111-1111-1111-111111111111',
  endpoint_key: 'GET /api/v1/orders/{id}',
  identity_fingerprint: 'auth:deadbeef',
  window_seconds: 3600,
  request_count: 12,
  avg_rate: 0.0033,
  status_code_dist: { '2xx': 10, '5xx': 2 },
  hour_dist: { '8': 5, '9': 7 },
  updated_at: '2026-08-08T12:00:00Z',
}

const objectRow = {
  id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  endpoint_id: '11111111-1111-1111-1111-111111111111',
  endpoint_key: 'GET /api/v1/orders/{id}',
  object_segment: 'path:2',
  identifier_type: 'numeric',
  example_hash: 'cafebabe',
  sample_count: 10,
  first_seen: '2026-08-01T00:00:00Z',
  last_seen: '2026-08-08T12:00:00Z',
  updated_at: '2026-08-08T12:00:00Z',
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <App>{ui}</App>
    </QueryClientProvider>,
  )
}

describe('ApiAccessProfilesPage', () => {
  beforeEach(() => {
    vi.mocked(apiBehaviorProfilesApi.list).mockReset()
    vi.mocked(apiObjectModelsApi.list).mockReset()
    vi.mocked(apiBehaviorProfilesApi.list).mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 })
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 })
  })

  it('默认渲染环境维度 Tab：行为画像列表', async () => {
    vi.mocked(apiBehaviorProfilesApi.list).mockResolvedValue({
      items: [behaviorRow],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiAccessProfilesPage />)
    await waitFor(() => {
      expect(screen.getByText('auth:deadbeef')).toBeInTheDocument()
    })
    expect(screen.getByText('GET /api/v1/orders/{id}')).toBeInTheDocument()
    expect(screen.getByText('环境维度 · 行为画像')).toBeInTheDocument()
    expect(screen.getByText('对象维度 · 对象模型')).toBeInTheDocument()
    expect(apiBehaviorProfilesApi.list).toHaveBeenCalled()
  })

  it('行为画像点击行打开详情抽屉：状态码与时段分布', async () => {
    vi.mocked(apiBehaviorProfilesApi.list).mockResolvedValue({
      items: [behaviorRow],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiAccessProfilesPage />)
    await waitFor(() => {
      expect(screen.getByText('auth:deadbeef')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('auth:deadbeef'))
    await waitFor(() => {
      expect(screen.getByText('行为画像详情')).toBeInTheDocument()
    })
    expect(screen.getByText('状态码分布')).toBeInTheDocument()
    expect(screen.getByText('2xx：10')).toBeInTheDocument()
    expect(screen.getByText('调用时段分布（UTC，按 24h 回看重算）')).toBeInTheDocument()
  })

  it('切换到对象维度 Tab：对象模型列表与形态过滤', async () => {
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({
      items: [objectRow],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiAccessProfilesPage />)
    fireEvent.click(screen.getByText('对象维度 · 对象模型'))
    await waitFor(() => {
      expect(screen.getByText('path:2')).toBeInTheDocument()
    })
    expect(screen.getByText('数字')).toBeInTheDocument()
    expect(apiObjectModelsApi.list).toHaveBeenCalled()
  })

  it('对象模型点击行打开详情抽屉：示例哈希与脱敏说明', async () => {
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({
      items: [objectRow],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiAccessProfilesPage />)
    fireEvent.click(screen.getByText('对象维度 · 对象模型'))
    await waitFor(() => {
      expect(screen.getByText('path:2')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('path:2'))
    await waitFor(() => {
      expect(screen.getByText('对象模型详情')).toBeInTheDocument()
    })
    expect(screen.getByText('cafebabe')).toBeInTheDocument()
    expect(screen.getByText('脱敏说明')).toBeInTheDocument()
  })
})
