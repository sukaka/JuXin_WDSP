import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import AiTasksPage from '../AiTasksPage'
import { useAuthStore } from '../../../../stores/auth'
import type { CurrentUser } from '../../../../types'

const fakeUser: CurrentUser = {
  id: 'u1',
  username: 'secadmin',
  display_name: '安全管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
  permissions: ['ai.sessions.read_own'],
  must_change_password: false,
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const TASK = {
  id: 'task-1',
  session_id: 'sess-abc',
  session_title: '策略分析会话',
  task_type: 'POLICY_RECOMMENDATION',
  status: 'SUCCESS',
  risk_level: 'LOW',
  plan_summary: '分析现有例外策略',
  started_at: '2026-10-21T01:00:00Z',
  finished_at: '2026-10-21T01:00:02Z',
  failure_code: '',
  failure_message: '',
  created_at: '2026-10-21T01:00:00Z',
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/ai/tasks']}>
        <AntdApp>
          <AiTasksPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AiTasksPage 会话深链', () => {
  beforeEach(() => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-token')
    localStorage.clear()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
        if (url.includes('/ai/tasks/task-1')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { task: TASK } }),
          )
        }
        if (url.includes('/ai/tasks')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [TASK], page: 1, page_size: 20, total: 1 },
            }),
          )
        }
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
      }),
    )
  })

  afterEach(() => {
    useAuthStore.getState().reset()
    vi.unstubAllGlobals()
  })

  it('任务详情中的会话 ID 渲染为跳转安全助手的链接', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const dialog = await screen.findByRole('dialog')
    const link = await within(dialog).findByRole('link', { name: 'sess-abc' })
    expect(link).toHaveAttribute('href', '/ai/assistant?session_id=sess-abc')
  })
})
