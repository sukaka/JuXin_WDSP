import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ReportsPage from '../ReportsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[], id = 'u1'): CurrentUser {
  return {
    id,
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

const ownJob = {
  id: 'job-own',
  report_type: 'CUSTOM',
  time_range_start: '2026-08-01T00:00:00Z',
  time_range_end: '2026-08-07T00:00:00Z',
  status: 'SUCCESS',
  progress: 100,
  requested_by: 'u1',
  requested_at: '2026-08-07T10:00:00Z',
  file_format: 'html',
}

const otherJob = {
  ...ownJob,
  id: 'job-other',
  requested_by: 'u2',
}

const listData = { items: [ownJob, otherJob], page: 1, page_size: 20, total: 2 }

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ReportsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 等待列表两行渲染完成（CUSTOM 类型标签「自定义」出现两次） */
async function waitRowsRendered() {
  const tags = await screen.findAllByText('自定义')
  expect(tags.length).toBeGreaterThanOrEqual(2)
}

describe('ReportsPage 删除显隐（delete_own / delete_all）', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('仅 delete_own：只能删除本人报告（他人行无删除按钮），有批量删除入口', async () => {
    useAuthStore.setState({
      user: makeUser(['reports.read', 'reports.delete_own']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await waitRowsRendered()
    expect(screen.getAllByRole('button', { name: /^删\s*除$/ })).toHaveLength(1)
    expect(screen.getByRole('button', { name: /批量删除/ })).toBeInTheDocument()
    expect(screen.getAllByRole('checkbox').length).toBeGreaterThan(0)
  })

  it('仅 delete_own：他人报告勾选框禁用，本人报告可勾选', async () => {
    useAuthStore.setState({
      user: makeUser(['reports.read', 'reports.delete_own']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await waitRowsRendered()
    // 表头全选 + 两行数据勾选框
    const checkboxes = screen.getAllByRole('checkbox')
    expect(checkboxes).toHaveLength(3)
    // ownJob（requested_by=u1）可勾选，otherJob（requested_by=u2）禁用
    expect(checkboxes[1]).toBeEnabled()
    expect(checkboxes[2]).toBeDisabled()
  })

  it('delete_all：本人与他人报告均有删除按钮', async () => {
    useAuthStore.setState({
      user: makeUser(['reports.read', 'reports.delete_own', 'reports.delete_all']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await waitRowsRendered()
    expect(screen.getAllByRole('button', { name: /^删\s*除$/ })).toHaveLength(2)
  })

  it('无任何删除权限：无删除按钮、无勾选列与批量删除按钮', async () => {
    useAuthStore.setState({ user: makeUser(['reports.read']), csrfToken: null, initialized: true })
    renderPage()
    await waitRowsRendered()
    expect(screen.queryByRole('button', { name: /^删\s*除$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /批量删除/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })
})
