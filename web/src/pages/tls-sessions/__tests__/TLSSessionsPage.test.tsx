import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import TLSSessionsPage from '../TLSSessionsPage'
import AccessLogDetailDrawer from '../../access-logs/AccessLogDetailDrawer'
import { useAuthStore } from '../../../stores/auth'
import { filterMenusByRoles } from '../../../utils/menu'
import type { CurrentUser, TLSSessionItem, TLSSessionSummary } from '../../../types'

const summaryData: TLSSessionSummary = {
  total_handshakes: 120,
  allowed_count: 105,
  gm_count: 40,
  intl_count: 80,
  legacy_ssl_blocked_count: 10,
  policy_blocked_count: 3,
  handshake_failed_count: 2,
  by_protocol: [
    { protocol: 'TLS1.3', count: 70, is_gm: false, is_legacy: false },
    { protocol: 'TLCP1.1', count: 40, is_gm: true, is_legacy: false },
    { protocol: 'SSLv3', count: 10, is_gm: false, is_legacy: true },
  ],
  by_cipher_suite: [
    { cipher_suite: 'TLS_AES_128_GCM_SHA256', count: 70, is_gm: false },
    { cipher_suite: 'TLCP_ECC_SM4_GCM_SM3', count: 40, is_gm: true },
  ],
}

const sessionItems: TLSSessionItem[] = [
  {
    id: 'sess-gm-1',
    occurred_at: '2026-11-25T06:30:00Z',
    gateway_node_id: 'gw-node-1',
    application_id: 'app-1',
    sni: 'gm.bank.example.com',
    client_ip: '203.0.113.10',
    client_port: 54321,
    server_port: 443,
    detected_protocol: 'TLCP1.1',
    negotiated_protocol: 'TLCP1.1',
    cipher_suite: 'TLCP_ECC_SM4_GCM_SM3',
    is_gm: true,
    ja3_hash: 'e7d705a3286e19ea42f587b344ee6865',
    alpn: 'http/1.1',
    action: 'ALLOWED',
    error_reason: '',
  },
  {
    id: 'sess-legacy-1',
    occurred_at: '2026-11-25T06:31:00Z',
    gateway_node_id: 'gw-node-1',
    application_id: 'app-1',
    sni: 'legacy.bank.example.com',
    client_ip: '198.51.100.7',
    client_port: 40012,
    server_port: 443,
    detected_protocol: 'SSLv3',
    negotiated_protocol: '',
    cipher_suite: '',
    is_gm: false,
    ja3_hash: 'abcd1234',
    alpn: '',
    action: 'BLOCKED_LEGACY_SSL',
    error_reason: 'legacy SSLv3 blocked by policy',
  },
]

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <TLSSessionsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('TLSSessionsPage 加密会话分析', () => {
  beforeEach(() => {
    const user: CurrentUser = {
      id: 'u1',
      username: 'secops',
      display_name: '运维管理员',
      status: 'ACTIVE',
      roles: [{ code: 'SECURITY_ADMIN', name: '运维管理员' }],
      permissions: ['events.read'],
      must_change_password: false,
    }
    useAuthStore.setState({ user, initialized: true })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/tls-sessions/summary')) {
          return Promise.resolve(jsonResponse(summaryData))
        }
        if (url.includes('/tls-sessions')) {
          return Promise.resolve(
            jsonResponse({
              items: sessionItems,
              page: 1,
              page_size: 20,
              total: sessionItems.length,
            }),
          )
        }
        if (url.includes('/access-logs/log-gm-1')) {
          return Promise.resolve(
            jsonResponse({
              id: 'log-gm-1',
              occurred_at: '2026-11-25T06:30:00Z',
              request_id: 'req-gm-1',
              domain: 'gm.bank.example.com',
              gateway_node_id: 'gw-1',
              client_ip: '203.0.113.10',
              client_port: 54321,
              request_method: 'GET',
              request_uri: '/api/balance',
              request_path: '/api/balance',
              query_summary: '',
              http_version: 'HTTP/1.1',
              content_type: 'application/json',
              user_agent_summary: 'GM-Browser',
              referer_summary: '',
              response_status: 200,
              bytes_in: 120,
              bytes_out: 256,
              duration_ms: 15,
              waf_action: 'ALLOW',
              tls_protocol: 'TLCP1.1',
              tls_cipher_suite: 'TLCP_ECC_SM4_GCM_SM3',
              tls_is_gm: true,
              tls_ja3: 'e7d705a3286e19ea42f587b344ee6865',
              client_hello_version: 'TLCP1.1',
            }),
          )
        }
        return Promise.resolve(new Response(null, { status: 404 }))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染 KPI 统计、协议与算法套件分布，并支持打开行详情抽屉查看 JA3/ALPN/错误原因', async () => {
    renderPage()

    expect(await screen.findByText('SSL/HTTPS 加密会话分析')).toBeInTheDocument()
    expect(await screen.findByText('gm.bank.example.com')).toBeInTheDocument()
    expect(screen.getByText('总握手数')).toBeInTheDocument()
    expect(screen.getByText('120')).toBeInTheDocument()
    expect(screen.getByText('国密 TLCP 会话')).toBeInTheDocument()
    expect(screen.getByText('弱协议 SSLv2/v3 拦截')).toBeInTheDocument()
    expect(screen.getAllByText('TLCP_ECC_SM4_GCM_SM3').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('TLS_AES_128_GCM_SHA256')).toBeInTheDocument()

    // 无 applications.read 时不查询 /applications
    const calls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
    expect(calls.some((u) => u.includes('/applications'))).toBe(false)

    // 打开弱协议拦截行详情抽屉
    fireEvent.click(screen.getByText('legacy.bank.example.com'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('加密会话详情')).toBeInTheDocument()
    expect(within(drawer).getByText('abcd1234')).toBeInTheDocument()
    expect(within(drawer).getByText('legacy SSLv3 blocked by policy')).toBeInTheDocument()
  })

  it('按协议、国密、动作、SNI、客户端 IP 筛选携带正确查询参数', async () => {
    renderPage()
    await screen.findByText('gm.bank.example.com')

    fireEvent.mouseDown(screen.getByLabelText('协议版本'))
    fireEvent.click(await screen.findByTitle('TLCP1.1'))

    fireEvent.mouseDown(screen.getByLabelText('国密/国际'))
    fireEvent.click(await screen.findByText('仅国密 TLCP'))

    fireEvent.mouseDown(screen.getByLabelText('处置动作'))
    fireEvent.click(await screen.findByText('弱 SSL 拦截'))

    const sniInput = screen.getByPlaceholderText('SNI 域名')
    fireEvent.change(sniInput, { target: { value: 'gm.bank.example.com' } })
    fireEvent.click(
      sniInput.closest('.ant-input-search')?.querySelector('.ant-input-search-btn') as HTMLElement,
    )

    const ipInput = screen.getByPlaceholderText('客户端 IP')
    fireEvent.change(ipInput, { target: { value: '203.0.113.10' } })
    fireEvent.click(
      ipInput.closest('.ant-input-search')?.querySelector('.ant-input-search-btn') as HTMLElement,
    )

    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(
        urls.some(
          (u) =>
            u.includes('/tls-sessions?') &&
            u.includes('detected_protocol=TLCP1.1') &&
            u.includes('is_gm=true') &&
            u.includes('action=BLOCKED_LEGACY_SSL') &&
            u.includes('sni=gm.bank.example.com') &&
            u.includes('client_ip=203.0.113.10'),
        ),
      ).toBe(true)
    })
  })

  it('AccessLogDetailDrawer 在日志包含 TLS/国密字段时展示协议、算法套件与 JA3', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AccessLogDetailDrawer logId="log-gm-1" onClose={vi.fn()} />
      </QueryClientProvider>,
    )

    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('国密 SM2/TLCP')).toBeInTheDocument()
    expect(within(drawer).getByText('TLCP_ECC_SM4_GCM_SM3')).toBeInTheDocument()
    expect(
      within(drawer).getByText('e7d705a3286e19ea42f587b344ee6865'),
    ).toBeInTheDocument()
  })

  it('侧边栏菜单 /tls-sessions 受 events.read 权限门控且对纯审计员隐藏', () => {
    const withPerm = filterMenusByRoles(['SECURITY_ADMIN'], ['events.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(withPerm).toContain('/tls-sessions')

    const withoutPerm = filterMenusByRoles(['CUSTOM_ROLE'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(withoutPerm).not.toContain('/tls-sessions')

    const auditOnly = filterMenusByRoles(['AUDIT_ADMIN'], ['events.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(auditOnly).not.toContain('/tls-sessions')
  })
})
