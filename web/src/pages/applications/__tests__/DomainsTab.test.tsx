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

  it('具备 protection_policies.read 权限时可在编辑/新增域名弹窗选择或清除防护策略并在列表展示', async () => {
    useAuthStore.setState({
      user: makeUser([
        'domains.read',
        'domains.create',
        'domains.update',
        'protection_policies.read',
      ]),
      csrfToken: null,
      initialized: true,
    })

    const boundDomain: DomainItem = {
      ...sampleDomain,
      id: 'dom-jxdr',
      hostname: 'jxdr.cn',
      normalized_hostname: 'jxdr.cn',
      https_enabled: true,
      https_port: 443,
      policy_id: 'pol-standard',
      policy_code: 'standard',
      policy_name: '标准策略',
      policy_mode: 'PROTECT',
    }
    const inheritDomain: DomainItem = {
      ...sampleDomain,
      id: 'dom-sub',
      hostname: 'blog.jxdr.cn',
      normalized_hostname: 'blog.jxdr.cn',
      is_primary: false,
      http_enabled: true,
      http_port: 80,
      policy_id: null,
    }

    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = init?.method ?? 'GET'
      if (method === 'GET' && url.includes('/applications/app-1/domains')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: [boundDomain, inheritDomain] },
          }),
        )
      }
      if (method === 'GET' && url.includes('/protection-policies')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              items: [
                {
                  id: 'pol-standard',
                  code: 'standard',
                  name: '标准策略',
                  status: 'ACTIVE',
                  protection_mode: 'PROTECT',
                  paranoia_level: 1,
                },
                {
                  id: 'pol-strict',
                  code: 'strict',
                  name: '严格策略',
                  status: 'ACTIVE',
                  protection_mode: 'PROTECT',
                  paranoia_level: 2,
                },
              ],
              page: 1,
              page_size: 100,
              total: 2,
            },
          }),
        )
      }
      if (method === 'PUT' && url.includes('/applications/app-1/domains/dom-jxdr')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: boundDomain }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${method} ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <DomainsTab
            appId="app-1"
            deploymentMode="REVERSE_PROXY"
            appProtectionMode="OBSERVE"
            appProtectionPolicy={{
              id: 'pol-relaxed',
              code: 'relaxed',
              name: '宽松策略',
              protection_mode: 'OBSERVE',
              paranoia_level: 1,
            }}
          />
        </AntdApp>
      </QueryClientProvider>,
    )

    // 列表中同时展示独立策略名与继承默认策略标签，且未打开弹窗前不请求策略列表
    expect(await screen.findByText('jxdr.cn')).toBeInTheDocument()
    expect(screen.getByText('标准策略')).toBeInTheDocument()
    expect(screen.getByText('继承（宽松策略）')).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some((c) => String(c[0]).includes('/protection-policies')),
    ).toBe(false)

    // 打开编辑弹窗后加载策略列表，切换到「严格策略」并提交 PUT
    const editButtons = screen.getAllByRole('button', { name: /^编\s*辑$/ })
    fireEvent.click(editButtons[0])
    const dialog = await screen.findByRole('dialog')
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some((c) => String(c[0]).includes('/protection-policies')),
      ).toBe(true),
    )

    const policyCombobox = within(dialog).getByLabelText('防护策略')
    fireEvent.mouseDown(policyCombobox)
    const strictOption = await screen.findByText(/严格策略（strict · 防护 · PL2）/)
    fireEvent.click(strictOption)

    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))
    await waitFor(() => {
      const putCall = fetchMock.mock.calls.find((c) => c[1]?.method === 'PUT')
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as Record<string, unknown>
      expect(body.hostname).toBe('jxdr.cn')
      expect(body.policy_id).toBe('pol-strict')
    })
  })

  it('缺少 protection_policies.read 权限时不请求策略接口，编辑提交省略 policy_id 以保留既有策略', async () => {
    const boundDomain: DomainItem = {
      ...sampleDomain,
      id: 'dom-keep',
      hostname: 'keep.jxdr.cn',
      normalized_hostname: 'keep.jxdr.cn',
      https_enabled: true,
      https_port: 443,
      policy_id: 'pol-standard',
      policy_code: 'standard',
      policy_name: '标准策略',
      policy_mode: 'PROTECT',
    }
    const fetchMock = mockDomainsFetch([boundDomain])
    vi.stubGlobal('fetch', fetchMock)
    renderTab('REVERSE_PROXY')

    expect(await screen.findByText('keep.jxdr.cn')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^编\s*辑$/ }))
    const dialog = await screen.findByRole('dialog')
    expect(
      within(dialog).getByText(/当前账号无查看防护策略权限，保存时将保留该域名现有防护策略不变/),
    ).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some((c) => String(c[0]).includes('/protection-policies')),
    ).toBe(false)

    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))
    await waitFor(() => {
      const putCall = fetchMock.mock.calls.find((c) => c[1]?.method === 'PUT')
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as Record<string, unknown>
      expect('policy_id' in body).toBe(false)
    })
  })
})
