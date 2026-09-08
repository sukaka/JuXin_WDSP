import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiSensitiveFieldsPage from '../ApiSensitiveFieldsPage'
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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const fieldNameHit = {
  id: '11111111-1111-4111-8111-111111111111',
  endpoint_id: '22222222-2222-4222-8222-222222222222',
  endpoint_key: 'POST /v1/orders',
  direction: 'REQUEST',
  structured_path: 'query.phone',
  data_type: 'phone',
  confidence: 0.8,
  detection_source: 'RUNTIME',
  occurrence_count: 3,
  first_seen: '2026-08-01T10:00:00Z',
  last_seen: '2026-08-20T09:00:00Z',
  source_detail: { location: 'query', rule_id: 'sensitive.in_query', event_id: 'ev-1', data_type: 'phone' },
  created_at: '2026-08-01T10:00:00Z',
  updated_at: '2026-08-20T09:00:00Z',
}

const fieldValueHit = {
  ...fieldNameHit,
  id: '33333333-3333-4333-8333-333333333333',
  structured_path: 'json.contact',
  confidence: 1.0,
  occurrence_count: 1,
  source_detail: { location: 'json', rule_id: 'sensitive.value', event_id: 'ev-2', data_type: 'phone' },
}

const listData = { items: [fieldNameHit, fieldValueHit], page: 1, page_size: 20, total: 2 }

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiSensitiveFieldsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiSensitiveFieldsPage', () => {
  let postBodies: unknown[]

  beforeEach(() => {
    postBodies = []
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        if (init?.method === 'POST') {
          postBodies.push(init.body ? JSON.parse(String(init.body)) : undefined)
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { deleted: 2 } }))
        }
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表展示接口键、置信度百分比与命中次数', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
    renderPage()
    expect((await screen.findAllByText('POST /v1/orders')).length).toBeGreaterThan(0)
    expect(screen.getByText('80%')).toBeInTheDocument()
    expect(screen.getByText('100%')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('点击详情打开抽屉并展示完整字段', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
    renderPage()
    const detailButtons = await screen.findAllByRole('button', { name: '详情' })
    fireEvent.click(detailButtons[0])
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('敏感字段详情')).toBeInTheDocument()
    expect(within(drawer).getByText('query.phone')).toBeInTheDocument()
    expect(within(drawer).getByText('sensitive.in_query')).toBeInTheDocument()
    expect(within(drawer).getByText('ev-1')).toBeInTheDocument()
    expect(within(drawer).getByText('累计命中')).toBeInTheDocument()
    expect(within(drawer).getByText('首次发现')).toBeInTheDocument()
  })

  it('无 api_data.manage 权限：不显示勾选列与批量删除按钮', async () => {
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findAllByText('POST /v1/orders')
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /批量删除/ })).not.toBeInTheDocument()
  })

  it('有 api_data.manage 权限：勾选后批量删除一次提交全部 ID', async () => {
    useAuthStore.setState({
      user: makeUser(['api_runtime.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findAllByText('POST /v1/orders')
    const checkboxes = screen.getAllByRole('checkbox')
    fireEvent.click(checkboxes[1])
    fireEvent.click(checkboxes[2])
    fireEvent.click(screen.getByRole('button', { name: /批量删除（2）/ }))
    const okBtn = await screen.findByRole('button', { name: /^删\s*除$/ })
    fireEvent.click(okBtn)
    await screen.findByText('已删除 2 条敏感字段')
    expect(postBodies).toEqual([
      { ids: [fieldNameHit.id, fieldValueHit.id] },
    ])
  })
})
