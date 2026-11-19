import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import IdentityDetailPage from '../IdentityDetailPage'
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

const IDENTITY = {
  id: 'idn-1',
  identity_key: 'ip:1.2.3.4',
  identity_type: 'BOT',
  identity_confidence: 90,
  confidence_source: ['browser_fingerprint', 'client_ip'],
  risk_score: 86,
  risk_level: 'HIGH',
  primary_ip: '1.2.3.4',
  asn: '',
  tls_fingerprint: '',
  browser_fingerprint: '',
  account_id: 'acct-1',
  jwt_subject: '',
  api_key_hash: '',
  oauth_client_id: '',
  device_type: 'DESKTOP',
  request_count: 100,
  first_seen_at: '2026-08-01T00:00:00Z',
  last_seen_at: '2026-08-31T12:00:00Z',
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-31T12:00:00Z',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ConfigProvider locale={zhCN}>
        <AntdApp>
          <MemoryRouter initialEntries={['/risk-identities/idn-1']}>
            <Routes>
              <Route
                path="/risk-identities/:id"
                element={<IdentityDetailPage />}
              />
            </Routes>
          </MemoryRouter>
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>,
  )
}

describe('IdentityDetailPage 封禁与解封', () => {
  let status: string
  let detailRequests: number
  let blockCalls: { url: string; body: unknown }[]
  let unblockCalls: string[]
  let actionError: string | null

  beforeEach(() => {
    status = 'ACTIVE'
    detailRequests = 0
    blockCalls = []
    unblockCalls = []
    actionError = null
    useAuthStore.setState({
      user: makeUser(['security_identities.read', 'security_identities.block']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (
          method === 'POST' &&
          url.endsWith('/security/identities/idn-1/block')
        ) {
          blockCalls.push({ url, body: JSON.parse(String(init?.body)) })
          if (actionError) {
            return Promise.resolve(
              jsonResponse(400, {
                code: 'BLOCK_FAILED',
                message: actionError,
                data: null,
              }),
            )
          }
          status = 'BLOCKED'
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { message: '已封禁' },
            }),
          )
        }
        if (
          method === 'POST' &&
          url.endsWith('/security/identities/idn-1/unblock')
        ) {
          unblockCalls.push(url)
          if (actionError) {
            return Promise.resolve(
              jsonResponse(400, {
                code: 'UNBLOCK_FAILED',
                message: actionError,
                data: null,
              }),
            )
          }
          status = 'ACTIVE'
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { message: '已解封' },
            }),
          )
        }
        if (method === 'GET' && url.endsWith('/security/identities/idn-1')) {
          detailRequests += 1
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                identity: { ...IDENTITY, status },
                ip_history: [],
                credentials: [],
                recent_events: [],
              },
            }),
          )
        }
        if (
          method === 'GET' &&
          url.endsWith('/security/identities/idn-1/behavior')
        ) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], page: 1, page_size: 500, total: 0 },
            }),
          )
        }
        if (
          method === 'GET' &&
          url.includes('/security/identities/idn-1/events?')
        ) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], page: 1, page_size: 20, total: 0 },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('read-only 仅显示状态标签，不显示封禁或解封操作', async () => {
    status = 'BLOCKED'
    useAuthStore.setState({
      user: makeUser(['security_identities.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(await screen.findByText('已封禁')).toBeInTheDocument()
    expect(screen.getByText('浏览器指纹、客户端 IP')).toBeInTheDocument()
    expect(screen.getByText('桌面设备')).toBeInTheDocument()
    expect(screen.getByText('JWT 主体')).toBeInTheDocument()
    expect(screen.getByText('OAuth 客户端 ID')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /^封\s*禁$/ }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /^解\s*封$/ }),
    ).not.toBeInTheDocument()
  })

  it('封禁校验 reason 必填且不超过 512，成功后调用 API 并刷新详情', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /^封\s*禁$/ }))
    const dialog = await screen.findByRole('dialog')

    fireEvent.click(screen.getByRole('button', { name: '确认封禁' }))
    expect(await screen.findByText('请输入封禁原因')).toBeInTheDocument()
    expect(blockCalls).toHaveLength(0)

    fireEvent.change(screen.getByLabelText('封禁原因'), {
      target: { value: 'x'.repeat(513) },
    })
    fireEvent.click(screen.getByRole('button', { name: '确认封禁' }))
    expect(
      await screen.findByText('封禁原因不超过 512 字符'),
    ).toBeInTheDocument()
    expect(blockCalls).toHaveLength(0)

    fireEvent.change(screen.getByLabelText('封禁原因'), {
      target: { value: '确认恶意扫描' },
    })
    fireEvent.click(screen.getByRole('button', { name: '确认封禁' }))
    await waitFor(() => expect(blockCalls).toHaveLength(1))
    expect(blockCalls[0]).toEqual({
      url: '/api/v1/security/identities/idn-1/block',
      body: { reason: '确认恶意扫描' },
    })
    expect(
      await screen.findByRole('button', { name: /^解\s*封$/ }),
    ).toBeInTheDocument()
    expect(screen.getByText('已封禁')).toBeInTheDocument()
    expect(detailRequests).toBe(2)
    expect(dialog).not.toBeVisible()
  })

  it('封禁失败展示真实错误且不刷新、不伪造状态', async () => {
    actionError = '封禁失败：策略发布冲突'
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /^封\s*禁$/ }))
    fireEvent.change(screen.getByLabelText('封禁原因'), {
      target: { value: '恶意扫描' },
    })
    fireEvent.click(screen.getByRole('button', { name: '确认封禁' }))

    expect(await screen.findByText(actionError)).toBeInTheDocument()
    expect(detailRequests).toBe(1)
    expect(screen.getByText('正常')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /^封\s*禁$/ }),
    ).toBeInTheDocument()
  })

  it('BLOCKED 显示解封，成功后刷新为正常状态', async () => {
    status = 'BLOCKED'
    renderPage()
    expect(await screen.findByText('已封禁')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /^解\s*封$/ }))
    await waitFor(() => expect(unblockCalls).toHaveLength(1))
    expect(unblockCalls[0]).toBe('/api/v1/security/identities/idn-1/unblock')
    expect(
      await screen.findByRole('button', { name: /^封\s*禁$/ }),
    ).toBeInTheDocument()
    expect(screen.getByText('正常')).toBeInTheDocument()
    expect(detailRequests).toBe(2)
  })

  it('解封失败展示真实错误并保持已封禁状态', async () => {
    status = 'BLOCKED'
    actionError = '解封失败：存储不可用'
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /^解\s*封$/ }))

    expect(await screen.findByText(actionError)).toBeInTheDocument()
    expect(detailRequests).toBe(1)
    expect(screen.getByText('已封禁')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /^解\s*封$/ }),
    ).toBeInTheDocument()
  })
})
