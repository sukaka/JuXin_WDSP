import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SecurityEventsPage from '../SecurityEventsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secops',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <SecurityEventsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('SecurityEventsPage 导出提示', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['security_events.read', 'security_events.export']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/security-events')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('导出按钮悬停提示「导出筛选结果」生效的筛选维度', async () => {
    renderPage()
    const exportBtn = await screen.findByRole('button', { name: /导\s*出/ })
    fireEvent.mouseEnter(exportBtn)
    // 明示仅时间范围/域名/攻击类型/风险生效，其余筛选不参与导出
    expect(
      await screen.findByText(/仅携带时间范围、域名、攻击类型、风险四项筛选/),
    ).toBeInTheDocument()
    expect(screen.getByText(/客户端IP、请求路径、方法、动作、处置状态、请求 ID 不参与导出/)).toBeInTheDocument()
  })

  it('无 security_events.export 权限时不展示导出按钮', async () => {
    useAuthStore.setState({
      user: makeUser(['security_events.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(screen.queryByRole('button', { name: /导\s*出/ })).not.toBeInTheDocument()
  })
})
