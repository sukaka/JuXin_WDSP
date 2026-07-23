import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiSpecsPage from '../ApiSpecsPage'
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

const listData = {
  items: [
    {
      id: 'spec1',
      format: 'openapi3',
      file_name: 'openapi-payment.json',
      content_hash: 'abcdef1234567890',
      endpoint_count: 12,
      imported_by: null,
      created_at: '2026-07-21T03:00:00Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 1,
}

const diffData = {
  items: [
    {
      id: 'd1',
      spec_id: 'spec1',
      diff_type: 'MISSING_IN_RUNTIME',
      endpoint_key: 'GET /v1/health',
      detail: { reason: 'not seen in runtime' },
      created_at: '2026-07-21T03:00:01Z',
    },
    {
      id: 'd2',
      spec_id: 'spec1',
      diff_type: 'CHANGED',
      endpoint_key: 'POST /v1/orders',
      detail: { field: 'id' },
      created_at: '2026-07-21T03:00:02Z',
    },
  ],
  page: 1,
  page_size: 20,
  total: 2,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiSpecsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiSpecsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/specs/spec1/diff')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: diffData }))
        }
        if (url.includes('/api-security/specs')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: listData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染规范列表：文件名、格式、哈希截断与分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_spec.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('openapi-payment.json')).toBeInTheDocument()
    expect(screen.getByText('openapi3')).toBeInTheDocument()
    expect(screen.getByText('abcdef1234…')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
  })

  it('无 import 权限：不显示「导入规范」', async () => {
    useAuthStore.setState({ user: makeUser(['api_spec.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('openapi-payment.json')
    expect(screen.queryByRole('button', { name: /导入规范/ })).not.toBeInTheDocument()
  })

  it('有 import 权限：显示「导入规范」，非法 JSON 给出提示且不发起导入', async () => {
    useAuthStore.setState({
      user: makeUser(['api_spec.read', 'api_spec.import']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    const importBtn = await screen.findByRole('button', { name: /导入规范/ })
    fireEvent.click(importBtn)
    const textarea = await screen.findByPlaceholderText('{"openapi":"3.0.0",...}')
    fireEvent.change(textarea, { target: { value: 'not-json' } })
    fireEvent.click(screen.getByRole('button', { name: '导 入' }))
    expect(await screen.findByText('规范内容须为合法 JSON')).toBeInTheDocument()
    // 仅列表与初始请求，未触发 /specs/import
    const calls = vi.mocked(fetch).mock.calls.map((c) => String(c[0]))
    expect(calls.some((u) => u.includes('/api-security/specs/import'))).toBe(false)
  })

  it('「查看差异」打开抽屉并渲染差异类型与端点键', async () => {
    useAuthStore.setState({ user: makeUser(['api_spec.read']), csrfToken: null, initialized: true })
    renderPage()
    const viewBtn = await screen.findByRole('button', { name: /查看差异/ })
    fireEvent.click(viewBtn)
    expect(await screen.findByText('运行时缺失')).toBeInTheDocument()
    expect(screen.getByText('定义变更')).toBeInTheDocument()
    expect(screen.getByText('GET /v1/health')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })
})
