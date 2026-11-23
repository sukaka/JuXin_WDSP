import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import UpstreamsTab from '../detail/UpstreamsTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

const upstreamItem = {
  id: 'up-1',
  application_id: 'app-1',
  name: '主源站',
  scheme: 'https',
  host: 'origin.example.com',
  normalized_host: 'origin.example.com',
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
  tls_server_name: '',
  tls_verify: true,
  max_retries: 1,
  created_at: '2026-07-01T00:00:00Z',
  updated_at: '2026-07-01T00:00:00Z',
  version: 1,
}

describe('UpstreamsTab 连通性测试中文化', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['upstreams.read', 'upstreams.test']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('错误码与 TLS 校验失败展示中文标签而非原始英文错误码', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (init?.method === 'POST' && url.includes('/upstreams/test')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                dns_result: 'ok',
                resolved_addresses: ['93.184.216.34'],
                tcp_connected: false,
                tls_handshake: false,
                tls_verify_result: 'x509: certificate has expired',
                http_status: 0,
                response_time_ms: 120,
                error_code: 'TLS_CERTIFICATE_ERROR',
                error_message: '证书已过期',
              },
            }),
          )
        }
        if (url.includes('/applications/app-1/upstreams')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [upstreamItem] } }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <UpstreamsTab appId="app-1" />
        </AntdApp>
      </QueryClientProvider>,
    )

    await screen.findByText('主源站')
    fireEvent.click(screen.getByRole('button', { name: /测\s*试/ }))
    const startTestBtn = await screen.findByRole('button', { name: '开始测试' })
    expect(screen.queryByText(/允许私网地址/)).not.toBeInTheDocument()
    fireEvent.click(startTestBtn)

    expect(await screen.findByText('测试失败：TLS 证书校验失败')).toBeInTheDocument()
    expect(screen.queryByText(/TLS_CERTIFICATE_ERROR/)).not.toBeInTheDocument()
    expect(screen.getByText('校验失败')).toBeInTheDocument()
    expect(screen.queryByText('x509: certificate has expired')).not.toBeInTheDocument()

    const testCall = (fetch as Mock).mock.calls.find(
      (c) => String(c[0]).includes('/upstreams/test') && c[1]?.method === 'POST',
    )
    expect(testCall).toBeTruthy()
    const testBody = JSON.parse(String(testCall![1]?.body)) as Record<string, unknown>
    expect('allow_private' in testBody).toBe(false)
  })
})

describe('UpstreamsTab 编辑/创建全字段保留 (B9-4)', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['upstreams.read', 'upstreams.create', 'upstreams.update']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('B9-4: 编辑未挂载健康检查与 TLS 字段的 http 源站时完整保留原值及 version', async () => {
    const httpUpstream = {
      ...upstreamItem,
      id: 'up-2',
      name: 'HTTP 源站',
      scheme: 'http',
      host: '10.0.0.2',
      normalized_host: '10.0.0.2',
      port: 8080,
      health_check_enabled: false,
      health_check_path: '/healthz',
      health_check_method: 'HEAD',
      health_check_interval_seconds: 15,
      health_check_timeout_seconds: 3,
      expected_status_codes: '200-299',
      tls_server_name: 'sni.internal',
      tls_verify: true,
      version: 4,
    }
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (init?.method === 'PUT' && url.includes('/upstreams/up-2')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { ...httpUpstream, version: 5 } }),
        )
      }
      if (url.includes('/applications/app-1/upstreams')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [httpUpstream] } }),
        )
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

    await screen.findByText('HTTP 源站')
    fireEvent.click(screen.getByRole('button', { name: /^编\s*辑$/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('编辑源站：HTTP 源站')).toBeInTheDocument()

    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))

    await waitFor(() => {
      const putCall = fetchMock.mock.calls.find(
        (c) => String(c[0]).includes('/upstreams/up-2') && c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as Record<string, unknown>
      expect(body).toEqual({
        name: 'HTTP 源站',
        scheme: 'http',
        host: '10.0.0.2',
        port: 8080,
        weight: 10,
        priority: 0,
        health_check_enabled: false,
        health_check_path: '/healthz',
        health_check_method: 'HEAD',
        health_check_interval_seconds: 15,
        health_check_timeout_seconds: 3,
        expected_status_codes: '200-299',
        connect_timeout_ms: 3000,
        response_header_timeout_ms: 10000,
        tls_server_name: 'sni.internal',
        tls_verify: true,
        max_retries: 1,
        version: 4,
      })
    })
  })

  it('B9-4: 创建 http 源站显式补全 health_check_* 默认值与 tls_verify: true', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      if (init?.method === 'POST' && url.includes('/applications/app-1/upstreams')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: upstreamItem }),
        )
      }
      if (url.includes('/applications/app-1/upstreams')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [] } }),
        )
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

    const addBtn = await screen.findByRole('button', { name: /新增源站/ })
    fireEvent.click(addBtn)

    const dialog = await screen.findByRole('dialog')
    const hostInput = within(dialog).getByPlaceholderText('IP 或域名，如 10.0.0.1 / origin.internal')
    fireEvent.change(hostInput, { target: { value: 'origin.internal' } })

    fireEvent.click(within(dialog).getByRole('button', { name: /^(OK|确\s*定)$/ }))

    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find(
        (c) => String(c[0]).includes('/applications/app-1/upstreams') && c[1]?.method === 'POST',
      )
      expect(postCall).toBeTruthy()
      const body = JSON.parse(String(postCall![1]?.body)) as Record<string, unknown>
      expect(body).toEqual({
        name: '',
        scheme: 'http',
        host: 'origin.internal',
        port: 80,
        weight: 10,
        priority: 0,
        health_check_enabled: false,
        health_check_path: '/health',
        health_check_method: 'GET',
        health_check_interval_seconds: 30,
        health_check_timeout_seconds: 5,
        expected_status_codes: '200',
        connect_timeout_ms: 3000,
        response_header_timeout_ms: 10000,
        tls_server_name: '',
        tls_verify: true,
        max_retries: 1,
      })
      expect('version' in body).toBe(false)
    })
  })
})
