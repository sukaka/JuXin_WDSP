import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiShadowZombiePage from '../ApiShadowZombiePage'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const finding = {
  id: 'f1',
  finding_type: 'SHADOW',
  severity: 'HIGH',
  status: 'OPEN',
  title: '未登记接口 POST /v1/internal/sync',
  endpoint_id: 'ep-1234567890abcdef',
  first_seen_at: '2026-08-01T02:00:00Z',
  last_seen_at: '2026-08-10T02:00:00Z',
}

const lifecycleEvents = [
  {
    id: 'le-1',
    endpoint_id: 'ep-1234567890abcdef',
    from_status: 'LEARNING',
    to_status: 'LEARNED',
    reason: '学习自动完成',
    actor: 'system',
    created_at: '2026-08-05T02:00:00Z',
  },
  {
    id: 'le-2',
    endpoint_id: 'ep-1234567890abcdef',
    from_status: 'LEARNED',
    to_status: 'ZOMBIE',
    reason: '连续 30 天无流量',
    actor: 'system',
    created_at: '2026-08-10T02:00:00Z',
  },
  {
    id: 'le-3',
    endpoint_id: 'ep-1234567890abcdef',
    from_status: 'ZOMBIE',
    to_status: 'MERGED',
    reason: '人工合并到主接口',
    actor: 'secops',
    created_at: '2026-08-11T02:00:00Z',
  },
]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiShadowZombiePage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiShadowZombiePage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/lifecycle-events')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: lifecycleEvents, page: 1, page_size: 50, total: lifecycleEvents.length },
            }),
          )
        }
        if (url.includes('/api-security/findings')) {
          const isCount = url.includes('page_size=1')
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: isCount ? [] : [finding],
                page: 1,
                page_size: isCount ? 1 : 20,
                total: 1,
              },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('卡片标题与生命周期时间线状态、系统执行人均展示中文标签', async () => {
    renderPage()

    expect(screen.getByText('影子与僵尸 API')).toBeInTheDocument()
    expect(screen.queryByText('Shadow 与 Zombie API')).not.toBeInTheDocument()

    const btn = await screen.findByRole('button', { name: '生命周期' })
    fireEvent.click(btn)

    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('学习中')).toBeInTheDocument()
    expect(within(drawer).getAllByText('已完成学习').length).toBeGreaterThanOrEqual(1)
    expect(within(drawer).getAllByText('僵尸接口').length).toBeGreaterThanOrEqual(1)
    expect(within(drawer).getByText('已合并')).toBeInTheDocument()
    expect(within(drawer).getAllByText(/系统 ·/).length).toBeGreaterThanOrEqual(1)
    expect(within(drawer).getByText(/secops ·/)).toBeInTheDocument()
    expect(within(drawer).queryByText('LEARNING')).not.toBeInTheDocument()
    expect(within(drawer).queryByText('ZOMBIE')).not.toBeInTheDocument()
    expect(within(drawer).queryByText('MERGED')).not.toBeInTheDocument()
    expect(within(drawer).queryByText(/^system ·/)).not.toBeInTheDocument()
  })
})
