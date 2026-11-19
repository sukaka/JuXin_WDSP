import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AuditsPage from '../AuditsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const AUDIT_ITEM = {
  id: 'aud-1',
  occurred_at: '2026-09-10T08:00:00Z',
  username: 'secops',
  source_ip: '10.0.0.5',
  module: 'applications',
  action: 'create',
  object_type: 'application',
  object_id: 'app-1',
  object_name: '商城站点',
  result: 'SUCCESS',
  risk_level: 'MEDIUM',
  request_id: 'req-aud-1',
  before_summary: null,
  after_summary: { name: '商城站点' },
}

describe('AuditsPage 模块/操作/对象类型中文化展示', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        id: 'u1',
        username: 'auditor',
        display_name: '审计员',
        status: 'ACTIVE',
        roles: [{ code: 'AUDITOR', name: '审计员' }],
        permissions: ['audits.read'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
        if (url.endsWith('/audits/aud-1')) return ok(AUDIT_ITEM)
        if (url.includes('/audits')) {
          return ok({ items: [AUDIT_ITEM], total: 1, page: 1, page_size: 20 })
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('列表与详情抽屉均将 module/action/object_type 映射为中文', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <AuditsPage />
        </AntdApp>
      </QueryClientProvider>,
    )

    expect(await screen.findByText('应用管理')).toBeInTheDocument()
    expect(screen.getByText('创建')).toBeInTheDocument()
    expect(screen.queryByText('applications')).not.toBeInTheDocument()
    expect(screen.queryByText('create')).not.toBeInTheDocument()

    // 打开详情抽屉，核对模块/操作/对象类型中文化
    fireEvent.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByText('审计详情')).toBeInTheDocument()
    expect(await screen.findByText('应用')).toBeInTheDocument()
    expect(screen.getAllByText('应用管理').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('创建').length).toBeGreaterThanOrEqual(2)
    expect(screen.queryByText('application')).not.toBeInTheDocument()
  })
})
