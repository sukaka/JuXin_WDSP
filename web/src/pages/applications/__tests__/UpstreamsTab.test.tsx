import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
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
    fireEvent.click(await screen.findByRole('button', { name: '开始测试' }))

    expect(await screen.findByText('测试失败：TLS 证书校验失败')).toBeInTheDocument()
    expect(screen.queryByText(/TLS_CERTIFICATE_ERROR/)).not.toBeInTheDocument()
    expect(screen.getByText('校验失败')).toBeInTheDocument()
    expect(screen.queryByText('x509: certificate has expired')).not.toBeInTheDocument()
  })
})
