import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiServiceAssetsPage from '../ApiServiceAssetsPage'
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

/** 有涉敏接口与未闭环风险的服务 */
const assetRisky = {
  server_ip: '10.0.0.8',
  port: 8080,
  application_count: 2,
  api_count: 15,
  traffic_7d: 120345,
  sensitive_api_count: 3,
  risk_count: 7,
}

/** 无涉敏/无风险的服务（不渲染标记） */
const assetClean = {
  server_ip: 'internal.example.com',
  port: 443,
  application_count: 1,
  api_count: 4,
  traffic_7d: 56,
  sensitive_api_count: 0,
  risk_count: 0,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiServiceAssetsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiServiceAssetsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/service-assets')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [assetRisky, assetClean], page: 1, page_size: 20, total: 2 },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    useAuthStore.setState({ user: makeUser(['api_asset.read']), csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表渲染：host:port 地址与各计数列', async () => {
    renderPage()
    expect(await screen.findByText('10.0.0.8:8080')).toBeInTheDocument()
    expect(screen.getByText('internal.example.com:443')).toBeInTheDocument()
    const row = screen.getByText('10.0.0.8:8080').closest('tr') as HTMLElement
    expect(within(row).getByText('2')).toBeInTheDocument()
    expect(within(row).getByText('15')).toBeInTheDocument()
    expect(within(row).getByText('120345')).toBeInTheDocument()
    // 初始请求携带分页参数
    const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
    expect(urls.some((u) => u.includes('page=1') && u.includes('page_size=20'))).toBe(true)
  })

  it('风险/涉敏标记：计数大于 0 的服务打标，为 0 不打标', async () => {
    renderPage()
    const riskyRow = (await screen.findByText('10.0.0.8:8080')).closest('tr') as HTMLElement
    expect(within(riskyRow).getByText('涉敏')).toBeInTheDocument()
    expect(within(riskyRow).getByText('风险')).toBeInTheDocument()

    const cleanRow = screen.getByText('internal.example.com:443').closest('tr') as HTMLElement
    expect(within(cleanRow).queryByText('涉敏')).not.toBeInTheDocument()
    expect(within(cleanRow).queryByText('风险')).not.toBeInTheDocument()
  })

  it('行展开：展示应用数/接口数等计数明细', async () => {
    const { container } = renderPage()
    await screen.findByText('10.0.0.8:8080')
    const expandIcon = container.querySelector('.ant-table-row-expand-icon')
    expect(expandIcon).toBeTruthy()
    fireEvent.click(expandIcon as Element)
    await waitFor(() => {
      expect(screen.getByText('承载应用数')).toBeInTheDocument()
    })
    expect(screen.getByText('归属接口数')).toBeInTheDocument()
    expect(screen.getByText('涉敏接口数')).toBeInTheDocument()
    expect(screen.getByText('未闭环风险数')).toBeInTheDocument()
  })
})
