import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import DomainsTab from '../detail/DomainsTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, DomainItem } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'ops',
    display_name: '运维管理员',
    status: 'ACTIVE',
    roles: [{ code: 'OPS_ADMIN', name: '运维管理员' }],
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

const sampleDomain: DomainItem = {
  id: 'dom-1',
  application_id: 'app-1',
  hostname: 'shop.example.com',
  normalized_hostname: 'shop.example.com',
  domain_type: 'EXACT',
  is_primary: true,
  http_enabled: false,
  http_port: null,
  https_enabled: false,
  https_port: null,
  redirect_http_to_https: false,
  status: 'ACTIVE',
  created_at: '2026-11-01T00:00:00Z',
  updated_at: '2026-11-01T00:00:00Z',
}

function mockDomainsFetch(items: DomainItem[] = []) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (method === 'POST' && url.includes('/applications/app-1/domains')) {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: sampleDomain }))
    }
    if (method === 'PUT' && url.includes('/applications/app-1/domains/')) {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: sampleDomain }))
    }
    if (method === 'GET' && url.includes('/applications/app-1/domains')) {
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items } }))
    }
    return Promise.reject(new Error(`unexpected url: ${method} ${url}`))
  })
}

function renderTab(deploymentMode?: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <DomainsTab appId="app-1" deploymentMode={deploymentMode} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('DomainsTab 协议校验与透明串接提示 (P1-7 / P1-13)', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['domains.read', 'domains.create', 'domains.update']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('TRANSPARENT 模式在页签及新增弹窗展示域名与真实端口提示；REVERSE_PROXY 不展示', async () => {
    vi.stubGlobal('fetch', mockDomainsFetch([]))
    const { unmount } = renderTab('TRANSPARENT')
    expect(await screen.findByText('透明串接域名与目标端口说明')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /新增域名/ }))
    const dialog = await screen.findByRole('dialog')
    expect(
      within(dialog).getByText(/透明串接请填写业务真实访问域名及真实目标端口/),
    ).toBeInTheDocument()
    unmount()

    renderTab('REVERSE_PROXY')
    await screen.findByRole('button', { name: /新增域名/ })
    expect(screen.queryByText('透明串接域名与目标端口说明')).not.toBeInTheDocument()
  })

  it('新增域名取消勾选全部协议时禁用确定按钮并阻止提交，重新启用 HTTPS 后恢复可提交', async () => {
    const fetchMock = mockDomainsFetch([])
    vi.stubGlobal('fetch', fetchMock)
    renderTab('TRANSPARENT')

    fireEvent.click(await screen.findByRole('button', { name: /新增域名/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('域名'), {
      target: { value: 'app.example.com' },
    })

    const httpCheckbox = within(dialog).getByLabelText('启用 HTTP')
    const httpsCheckbox = within(dialog).getByLabelText('启用 HTTPS')
    const okBtn = within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ })

    expect(httpCheckbox).toBeChecked()
    expect(httpsCheckbox).not.toBeChecked()
    expect(okBtn).toBeEnabled()

    // 取消勾选 HTTP（此时 HTTP 与 HTTPS 均为未勾选）→ 禁用提交并给出告警
    fireEvent.click(httpCheckbox)
    expect(
      await within(dialog).findByText('HTTP 与 HTTPS 至少启用一个，否则无法提交保存'),
    ).toBeInTheDocument()
    expect(okBtn).toBeDisabled()

    fireEvent.click(okBtn)
    expect(
      (fetch as Mock).mock.calls.some((c) => c[1]?.method === 'POST'),
    ).toBe(false)

    // 启用 HTTPS 后恢复可提交并正常发起 POST
    fireEvent.click(httpsCheckbox)
    await waitFor(() => expect(okBtn).toBeEnabled())
    fireEvent.click(okBtn)
    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find((c) => c[1]?.method === 'POST')
      expect(postCall).toBeTruthy()
      const body = JSON.parse(String(postCall![1]?.body)) as Record<string, unknown>
      expect(body.hostname).toBe('app.example.com')
      expect(body.http_enabled).toBe(false)
      expect(body.https_enabled).toBe(true)
      expect(body.https_port).toBe(443)
    })
  })

  it('编辑 HTTP/HTTPS 均未启用的历史域名时禁用确定按钮并阻止 PUT 提交', async () => {
    const fetchMock = mockDomainsFetch([sampleDomain])
    vi.stubGlobal('fetch', fetchMock)
    renderTab('TRANSPARENT')

    expect(await screen.findByText('shop.example.com')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^编\s*辑$/ }))
    const dialog = await screen.findByRole('dialog')

    const okBtn = within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ })
    await waitFor(() => expect(okBtn).toBeDisabled())
    expect(
      within(dialog).getByText('HTTP 与 HTTPS 至少启用一个，否则无法提交保存'),
    ).toBeInTheDocument()

    fireEvent.click(okBtn)
    expect(fetchMock.mock.calls.some((c) => c[1]?.method === 'PUT')).toBe(false)
  })
})
