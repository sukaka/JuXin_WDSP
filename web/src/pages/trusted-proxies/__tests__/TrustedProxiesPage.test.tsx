import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import TrustedProxiesPage from '../TrustedProxiesPage'
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

const ADDRESS_ROW = {
  id: 'pa-1',
  name: '运维跳板机',
  address: '192.168.10.5',
  cidr: '',
  address_type: 'CUSTOM',
  source_type: 'MANUAL',
  description: '业务保留地址',
  status: 'ENABLED',
  created_at: '2026-09-01T08:00:00Z',
  updated_at: '2026-09-01T08:00:00Z',
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** 返回 mock fetch 与已捕获的 /protected-addresses 请求 URL 列表 */
function mockFetch(addressTotal: number) {
  const protectedUrls: string[] = []
  const fn = vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes('/protected-addresses')) {
      protectedUrls.push(url)
      return Promise.resolve(
        jsonResponse({ items: [ADDRESS_ROW], page: 1, page_size: 20, total: addressTotal }),
      )
    }
    if (url.includes('/trusted-proxies')) {
      return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }))
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
  return { fn, protectedUrls }
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ConfigProvider locale={zhCN}>
        <AntdApp>
          <MemoryRouter>
            <TrustedProxiesPage />
          </MemoryRouter>
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>,
  )
}

async function openProtectedTab() {
  fireEvent.click(await screen.findByText('保护地址'))
}

describe('TrustedProxiesPage 保护地址服务端分页', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['trusted_proxies.manage', 'protected_addresses.manage']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('首次加载带默认分页参数 page=1&page_size=20 并渲染列表', async () => {
    const { fn, protectedUrls } = mockFetch(1)
    vi.stubGlobal('fetch', fn)
    renderPage()
    await openProtectedTab()

    expect(await screen.findByText('运维跳板机')).toBeInTheDocument()
    expect(screen.getByText('192.168.10.5')).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
    expect(protectedUrls.length).toBeGreaterThan(0)
    expect(protectedUrls[0]).toContain('page=1')
    expect(protectedUrls[0]).toContain('page_size=20')
  })

  it('翻页后携带 page=2 重新请求，total 来自服务端', async () => {
    const { fn, protectedUrls } = mockFetch(40)
    vi.stubGlobal('fetch', fn)
    renderPage()
    await openProtectedTab()
    expect(await screen.findByText('共 40 条')).toBeInTheDocument()

    fireEvent.click(screen.getByTitle('2'))

    await waitFor(() => {
      expect(protectedUrls.some((u) => u.includes('page=2'))).toBe(true)
    })
  })

  it('切换地址类型筛选后重置回第一页', async () => {
    const { fn, protectedUrls } = mockFetch(40)
    vi.stubGlobal('fetch', fn)
    renderPage()
    await openProtectedTab()
    expect(await screen.findByText('共 40 条')).toBeInTheDocument()

    fireEvent.click(screen.getByTitle('2'))
    await waitFor(() => {
      expect(protectedUrls.some((u) => u.includes('page=2'))).toBe(true)
    })

    const placeholder = screen.getByText('地址类型')
    fireEvent.mouseDown(placeholder)
    const option = (await screen.findAllByText('自定义')).find((el) =>
      el.closest('.ant-select-item-option-content'),
    )
    expect(option).toBeTruthy()
    fireEvent.click(option as HTMLElement)

    await waitFor(() => {
      expect(
        protectedUrls.some((u) => u.includes('address_type=CUSTOM') && u.includes('page=1')),
      ).toBe(true)
    })
  })
})
