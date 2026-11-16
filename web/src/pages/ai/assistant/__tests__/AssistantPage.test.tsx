import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import AssistantPage from '../AssistantPage'
import { useAuthStore } from '../../../../stores/auth'
import type { CurrentUser } from '../../../../types'

const fakeUser: CurrentUser = {
  id: 'u1',
  username: 'secadmin',
  display_name: '安全管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
  permissions: ['ai.chat.use'],
  must_change_password: false,
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const SESSION_A = {
  id: 'sess-1',
  title: '攻击复盘会话',
  status: 'ACTIVE',
  context_token_count: 12,
}

function stubFetch(sessions: unknown[], messagesBySession: Record<string, unknown[]>) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    if (url.includes('/messages')) {
      const m = url.match(/\/ai\/sessions\/([^/]+)\/messages/)
      const sid = m?.[1]
      const items = sid ? messagesBySession[sid] : undefined
      if (!items) {
        return Promise.resolve(
          jsonResponse(404, { code: 'NOT_FOUND', message: '会话不存在' }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items } }),
      )
    }
    if (url.includes('/ai/sessions')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: sessions, page: 1, page_size: 50, total: sessions.length },
        }),
      )
    }
    return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
  })
}

function renderPage(entry: string) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <AntdApp>
          <AssistantPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AssistantPage 深链 ?session_id=', () => {
  beforeEach(() => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-token')
  })

  afterEach(() => {
    useAuthStore.getState().reset()
    vi.unstubAllGlobals()
  })

  it('会话在列表中：自动定位并加载历史消息', async () => {
    vi.stubGlobal(
      'fetch',
      stubFetch([SESSION_A], {
        'sess-1': [
          { id: 'm1', role: 'user', content: '今天为什么攻击增多？', created_at: '2026-10-21T01:00:00Z' },
          { id: 'm2', role: 'assistant', content: '历史回答内容', created_at: '2026-10-21T01:00:05Z' },
        ],
      }),
    )
    renderPage('/ai/assistant?session_id=sess-1')
    // 右侧头部展示会话标题（列表项同名，用标题 strong 断言至少两处出现）
    await screen.findAllByText('攻击复盘会话')
    expect(await screen.findByText('历史回答内容')).toBeInTheDocument()
    expect(screen.queryByText(/未找到链接指定的会话/)).not.toBeInTheDocument()
  })

  it('会话不在列表中：显式报错且消息区提示加载失败，不静默', async () => {
    vi.stubGlobal('fetch', stubFetch([SESSION_A], {}))
    renderPage('/ai/assistant?session_id=sess-missing')
    expect(await screen.findByText(/未找到链接指定的会话/)).toBeInTheDocument()
    expect(await screen.findByText(/加载会话消息失败/)).toBeInTheDocument()
  })

  it('无深链参数：不报深链错误', async () => {
    vi.stubGlobal('fetch', stubFetch([SESSION_A], {}))
    renderPage('/ai/assistant')
    await screen.findByText('攻击复盘会话')
    expect(screen.queryByText(/未找到链接指定的会话/)).not.toBeInTheDocument()
  })
})
