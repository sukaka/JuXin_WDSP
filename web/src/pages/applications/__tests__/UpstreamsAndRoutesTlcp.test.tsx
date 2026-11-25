import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import UpstreamsTab from '../detail/UpstreamsTab'
import HeaderProxyTab from '../detail/HeaderProxyTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'ops',
    display_name: '运维管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '运维管理员' }],
    permissions,
    must_change_password: false,
  }
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('UpstreamsTab & HeaderProxyTab 国密 TLCP 协议支持', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser([
        'upstreams.read',
        'upstreams.create',
        'upstreams.update',
        'upstreams.test',
        'applications.read',
        'applications.update',
      ]),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('UpstreamsTab 支持选择 tlcp（国密）、展示 SNI/证书校验字段并发起 TLCP 连通性测试', async () => {
    const tlcpUpstream = {
      id: 'up-tlcp-1',
      application_id: 'app-1',
      name: '国密源站',
      scheme: 'tlcp',
      host: 'gm-origin.internal',
      normalized_host: 'gm-origin.internal',
      port: 443,
      weight: 10,
      priority: 0,
      status: 'ACTIVE',
      health_check_enabled: false,
      health_check_path: '/health',
      health_check_method: 'GET',
      health_check_interval_seconds: 30,
      health_check_timeout_seconds: 5,
      expected_status_codes: '200',
      connect_timeout_ms: 3000,
      response_header_timeout_ms: 10000,
      tls_server_name: 'gm.example.com',
      tls_verify: true,
      max_retries: 1,
      created_at: '2026-11-25T00:00:00Z',
      updated_at: '2026-11-25T00:00:00Z',
      version: 1,
    }

    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (init?.method === 'POST' && url.includes('/applications/app-1/upstreams')) {
        return Promise.resolve(jsonResponse(tlcpUpstream))
      }
      if (init?.method === 'POST' && url.includes('/upstreams/test')) {
        return Promise.resolve(
          jsonResponse({
            dns_result: 'ok',
            resolved_addresses: ['10.0.0.9'],
            tcp_connected: true,
            tls_handshake: true,
            tls_verify_result: 'ok',
            http_status: 200,
            response_time_ms: 18,
            error_code: '',
            error_message: '',
          }),
        )
      }
      if (url.includes('/applications/app-1/upstreams')) {
        return Promise.resolve(jsonResponse({ items: [tlcpUpstream] }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <UpstreamsTab appId="app-1" />
        </AntdApp>
      </QueryClientProvider>,
    )

    expect(await screen.findByText('tlcp://gm-origin.internal:443')).toBeInTheDocument()
    expect(screen.getByText('国密 TLCP')).toBeInTheDocument()

    // 新增源站并选择 TLCP (国密)
    fireEvent.click(screen.getByRole('button', { name: /新增源站/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(dialog).getByLabelText('协议'))
    fireEvent.click(await screen.findByText('TLCP (国密)'))

    // 切换为 tlcp 后自动展示 SNI 和证书校验，端口切为 443
    expect(await within(dialog).findByLabelText('加密域名（SNI）')).toBeInTheDocument()
    expect(within(dialog).getByText('校验源站证书')).toBeInTheDocument()

    fireEvent.change(
      within(dialog).getByPlaceholderText('IP 或域名，如 10.0.0.1 / origin.internal'),
      { target: { value: 'gm-origin.internal' } },
    )
    fireEvent.change(within(dialog).getByLabelText('加密域名（SNI）'), {
      target: { value: 'gm.example.com' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))

    await waitFor(() => {
      const postCall = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).includes('/applications/app-1/upstreams') && c[1]?.method === 'POST',
      )
      expect(postCall).toBeTruthy()
      const body = JSON.parse(String(postCall![1]?.body)) as Record<string, unknown>
      expect(body.scheme).toBe('tlcp')
      expect(body.port).toBe(443)
      expect(body.tls_server_name).toBe('gm.example.com')
      expect(body.tls_verify).toBe(true)
    })

    // 触发 TLCP 连通性测试
    fireEvent.click(screen.getByRole('button', { name: /测\s*试/ }))
    expect(await screen.findByText('国密 TLCP 1.1 加密回源探测')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '开始测试' }))
    expect(await screen.findByText('连通性测试通过')).toBeInTheDocument()
    const testCall = (fetch as Mock).mock.calls.find(
      (c) => String(c[0]).includes('/upstreams/test') && c[1]?.method === 'POST',
    )
    expect(JSON.parse(String(testCall![1]?.body))).toMatchObject({
      scheme: 'tlcp',
      host: 'gm-origin.internal',
      port: 443,
    })
  })

  it('HeaderProxyTab 路径转发支持选择 tlcp（国密）源站协议', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (url.includes('/header-config')) {
        return Promise.resolve(jsonResponse({ configured: false, version: 0, config: {} }))
      }
      if (init?.method === 'POST' && url.includes('/path-routes')) {
        return Promise.resolve(
          jsonResponse({
            route: {
              id: 'pr-gm',
              application_id: 'app-1',
              path_prefix: '/gm-api',
              upstream_scheme: 'tlcp',
              upstream_host: '10.0.0.50',
              upstream_port: 443,
              strip_prefix: false,
              priority: 100,
              status: 'ENABLED',
              description: '',
              created_at: '2026-11-25T00:00:00Z',
              updated_at: '2026-11-25T00:00:00Z',
              version: 1,
            },
            message: '路径转发已创建',
          }),
        )
      }
      if (url.includes('/path-routes')) {
        return Promise.resolve(jsonResponse({ items: [], page: 1, page_size: 20, total: 0 }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <HeaderProxyTab appId="app-1" />
        </AntdApp>
      </QueryClientProvider>,
    )

    fireEvent.click(await screen.findByRole('button', { name: /新增转发规则/ }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.change(within(drawer).getByPlaceholderText('如 /api/v1'), {
      target: { value: '/gm-api' },
    })
    fireEvent.mouseDown(within(drawer).getByLabelText('源站协议'))
    fireEvent.click(await screen.findByText('TLCP (国密)'))
    fireEvent.change(within(drawer).getByPlaceholderText('IP 或域名'), {
      target: { value: '10.0.0.50' },
    })
    fireEvent.click(within(drawer).getByRole('button', { name: /^保\s*存$/ }))

    await waitFor(() => {
      const postCall = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).includes('/path-routes') && c[1]?.method === 'POST',
      )
      expect(postCall).toBeTruthy()
      expect(JSON.parse(String(postCall![1]?.body))).toMatchObject({
        path_prefix: '/gm-api',
        upstream_scheme: 'tlcp',
        upstream_host: '10.0.0.50',
        upstream_port: 443,
      })
    })
  })
})
