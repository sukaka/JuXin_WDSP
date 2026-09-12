import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import NoiseReductionPage from '../NoiseReductionPage'
import { useAuthStore } from '../../../../stores/auth'
import type { CurrentUser } from '../../../../types'

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

function envelope(data: unknown) {
  return { code: 'SUCCESS', message: 'ok', data }
}

const cluster = {
  id: 'c1',
  source: 'WAF',
  fingerprint_hash: 'fp-abc-123',
  application_id: null,
  host: 'example.com',
  normalized_uri: '/api/users/{id}',
  rule_id: 942100,
  detector_code: '',
  client_ip: '1.2.3.4',
  event_count: 42,
  first_seen: '2026-07-23T00:00:00Z',
  last_seen: '2026-07-23T01:00:00Z',
  status: 'ACTIVE',
  ai_verdict: 'LIKELY_FALSE_POSITIVE',
  ai_confidence: 0.87,
  ai_summary: '同一指纹高频重复，疑似扫描器误报',
  created_at: '2026-07-23T00:00:00Z',
  updated_at: '2026-07-23T01:00:00Z',
}

const stats = {
  active_clusters: 3,
  folded_events: 128,
  likely_false_positive_clusters: 2,
  suppressed_clusters: 1,
}

const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input)
  if (url.includes('/ai/noise/stats')) {
    return Promise.resolve(jsonResponse(200, envelope(stats)))
  }
  if (url.includes('/ai/noise/clusters/c1/suppress')) {
    return Promise.resolve(jsonResponse(200, envelope({ ...cluster, status: 'SUPPRESSED' })))
  }
  if (url.includes('/ai/noise/clusters/c1')) {
    return Promise.resolve(
      jsonResponse(
        200,
        envelope({
          cluster,
          events: [
            { event_id: 'e1', source: 'WAF', is_representative: true, created_at: '2026-07-23T00:30:00Z' },
          ],
        }),
      ),
    )
  }
  if (url.includes('/ai/noise/clusters')) {
    if (init?.method === 'POST') {
      return Promise.resolve(jsonResponse(200, envelope({})))
    }
    return Promise.resolve(
      jsonResponse(200, envelope({ items: [cluster], page: 1, page_size: 20, total: 1 })),
    )
  }
  return Promise.reject(new Error(`unexpected url: ${url}`))
})

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <NoiseReductionPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('NoiseReductionPage', () => {
  beforeEach(() => {
    fetchMock.mockClear()
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['ai.noise_reduction.use']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染统计卡片与簇列表', async () => {
    renderPage()
    expect(await screen.findByText('example.com')).toBeInTheDocument()
    expect(screen.getByText('活跃簇数')).toBeInTheDocument()
    expect(screen.getByText('已折叠事件总数')).toBeInTheDocument()
    expect(screen.getByText('疑似误报簇数')).toBeInTheDocument()
    expect(screen.getByText('128')).toBeInTheDocument()
    // 簇行关键字段：规则、折叠事件数、研判标签、置信度
    expect(screen.getByText('#942100')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('疑似误报')).toBeInTheDocument()
    expect(screen.getByText('87%')).toBeInTheDocument()
  })

  it('状态筛选：选择「已抑制」后带 status=SUPPRESSED 重新查询', async () => {
    renderPage()
    await screen.findByText('example.com')
    // 依次为 来源 / 状态 / AI 研判；antd v6 Select 根节点为 .ant-select
    const statusSelect = screen
      .getByText('状态', { selector: '.ant-select-placeholder' })
      .closest('.ant-select') as HTMLElement
    fireEvent.mouseDown(statusSelect)
    fireEvent.click(await screen.findByText('已抑制'))
    await waitFor(() => {
      const called = fetchMock.mock.calls.some(([input]) =>
        String(input).includes('status=SUPPRESSED'),
      )
      expect(called).toBe(true)
    })
  })

  it('抑制：Popconfirm 二次确认后 POST suppress', async () => {
    renderPage()
    await screen.findByText('example.com')
    fireEvent.click(screen.getByRole('button', { name: '抑制' }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定/ }))
    await waitFor(() => {
      const postCalls = fetchMock.mock.calls.filter(
        ([input, init]) =>
          String(input).includes('/ai/noise/clusters/c1/suppress') && init?.method === 'POST',
      )
      expect(postCalls).toHaveLength(1)
    })
  })

  it('权限门控：无 manage 权限不显示「立即扫描」与「设置」，有则显示', async () => {
    const { unmount } = renderPage()
    await screen.findByText('example.com')
    expect(screen.queryByRole('button', { name: '立即扫描' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^设\s*置$/ })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '扫描历史' })).toBeInTheDocument()
    unmount()

    useAuthStore.setState({
      user: makeUser(['ai.noise_reduction.use', 'ai.noise_reduction.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('example.com')
    expect(screen.getByRole('button', { name: '立即扫描' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^设\s*置$/ })).toBeInTheDocument()
  })
})
