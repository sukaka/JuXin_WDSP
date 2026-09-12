import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiClassificationsPage from '../ApiClassificationsPage'
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
      <MemoryRouter>
        <AntdApp>
          <ApiClassificationsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiClassificationsPage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['api_classification.manage']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/classifications')) {
          return Promise.resolve(jsonResponse({ builtin: [], custom: [] }))
        }
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 100, total: 0 }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('动态分类行提供带名称的原生删除按钮', async () => {
    renderPage()
    const addButton = await screen.findByRole('button', { name: /添加维度/ })
    fireEvent.click(addButton)

    const deleteButton = screen.getByRole('button', { name: '删除此分类维度' })
    expect(deleteButton).toHaveAttribute('type', 'button')

    fireEvent.click(deleteButton)
    expect(screen.queryByRole('button', { name: '删除此分类维度' })).not.toBeInTheDocument()
  })
})
