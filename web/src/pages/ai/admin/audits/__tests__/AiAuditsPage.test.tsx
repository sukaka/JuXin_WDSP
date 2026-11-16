import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import AiAuditsPage from '../AiAuditsPage'
import { useAuthStore } from '../../../../../stores/auth'
import type { CurrentUser } from '../../../../../types'

const fakeUser: CurrentUser = {
  id: 'u1',
  username: 'admin',
  display_name: '系统管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  permissions: ['ai.audits.read'],
  must_change_password: false,
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const DRAFT_ID = '11111111-2222-3333-4444-555555555555'

const RECORD_WITH_DRAFT = {
  occurred_at: '2026-10-21T01:00:00Z',
  user_id: 'u1',
  username: 'secadmin',
  role_codes: '',
  session_id: null,
  task_id: null,
  action: 'draft_create',
  task_type: 'DRAFT_EXCEPTION',
  agent_code: 'waf_policy',
  tool_code: 'draft.exception.create',
  model_code: '',
  prompt_version: '',
  input_tokens: 10,
  output_tokens: 20,
  duration_ms: 30,
  estimated_cost: 0.001,
  request_summary: '生成例外草稿',
  result_summary: 'DRAFT',
  draft_reference: DRAFT_ID,
  confirm_result: '',
}

const RECORD_WITHOUT_DRAFT = {
  ...RECORD_WITH_DRAFT,
  occurred_at: '2026-10-21T02:00:00Z',
  username: 'admin',
  action: 'chat_message',
  draft_reference: '',
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/ai/admin/audits']}>
        <AntdApp>
          <AiAuditsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AiAuditsPage 草稿引用深链', () => {
  beforeEach(() => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-token')
    localStorage.clear()
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
        if (url.includes('/ai/audits')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [RECORD_WITH_DRAFT, RECORD_WITHOUT_DRAFT],
                page: 1,
                page_size: 20,
                total: 2,
              },
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

  it('草稿引用为可识别草稿 ID 时渲染为策略建议页链接', async () => {
    renderPage()
    const buttons = await screen.findAllByRole('button', { name: /详\s*情/ })
    fireEvent.click(buttons[0])
    const drawer = await screen.findByRole('dialog')
    const link = await within(drawer).findByRole('link', { name: DRAFT_ID })
    expect(link).toHaveAttribute('href', `/ai/policy-recommendation?draft_id=${DRAFT_ID}`)
  })

  it('草稿引用为空时显示占位符，不渲染链接', async () => {
    renderPage()
    const buttons = await screen.findAllByRole('button', { name: /详\s*情/ })
    fireEvent.click(buttons[1])
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('草稿引用')
    expect(within(drawer).queryByRole('link')).not.toBeInTheDocument()
  })
})
