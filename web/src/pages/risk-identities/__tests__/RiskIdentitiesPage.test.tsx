import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import RiskIdentitiesPage from '../RiskIdentitiesPage'
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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const IDENTITY_ROW = {
  id: 'idn-1',
  identity_key: 'ip:1.2.3.4',
  identity_type: 'BOT',
  risk_score: 86,
  risk_level: 'HIGH',
  status: 'ACTIVE',
  primary_ip: '1.2.3.4',
  ip_count: 3,
  account_id: 'acct-1001',
  request_count: 5321,
  first_seen_at: '2026-08-01T00:00:00Z',
  last_seen_at: '2026-08-31T12:00:00Z',
}

function mockFetchWith(body: unknown, status = 200) {
  const envelope =
    status === 200
      ? { code: 'SUCCESS', message: 'ok', data: body }
      : { code: 'INTERNAL_ERROR', message: '数据库异常', data: null }
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes('/security/identities')) {
      return Promise.resolve(jsonResponse(status, envelope))
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ConfigProvider locale={zhCN}>
        <AntdApp>
          <MemoryRouter>
            <RiskIdentitiesPage />
          </MemoryRouter>
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>,
  )
}

describe('RiskIdentitiesPage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['security_identities.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染风险身份列表：主IP、类型与风险等级标签', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetchWith({ items: [IDENTITY_ROW], page: 1, page_size: 20, total: 1 }),
    )
    renderPage()

    expect(await screen.findByText('1.2.3.4')).toBeInTheDocument()
    expect(screen.getByText('机器人')).toBeInTheDocument()
    expect(screen.getByText('高')).toBeInTheDocument()
    expect(screen.getByText('86')).toBeInTheDocument()
    expect(screen.getByText('acct-1001')).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
  })

  it('列表为空时展示空态', async () => {
    vi.stubGlobal('fetch', mockFetchWith({ items: [], page: 1, page_size: 20, total: 0 }))
    renderPage()

    // antd Empty 的 SVG title 与描述文本同名，用 findAllByText 断言存在即可
    expect((await screen.findAllByText('暂无数据')).length).toBeGreaterThan(0)
  }, 15000)

  it('接口报错时展示错误提示', async () => {
    vi.stubGlobal('fetch', mockFetchWith(null, 500))
    renderPage()

    expect(await screen.findByText('加载风险身份失败')).toBeInTheDocument()
    expect(screen.getByText('数据库异常')).toBeInTheDocument()
  })
})
