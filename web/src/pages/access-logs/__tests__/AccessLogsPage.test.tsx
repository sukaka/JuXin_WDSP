import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ComponentProps } from 'react'
import AccessLogsPage from '../AccessLogsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import type EChart from '../../../components/EChart'

vi.mock('../../../components/EChart', () => ({
  default: ({ option }: ComponentProps<typeof EChart>) => {
    const series = (option.series ?? []) as Array<{ data?: Array<[number, number]> }>
    const total = series[0]?.data?.reduce((sum, point) => sum + point[1], 0) ?? 0
    return <div data-testid="request-trend-total">{total}</div>
  },
}))

const applicationID = '055c010d-f328-4c32-95f9-b995744068ae'
const traceID = '0123456789abcdef0123456789abcdef'
const log = {
  id: 'daf2d420-5de5-4168-841e-cca044235820',
  occurred_at: '2026-11-17T01:40:09Z',
  request_id: 'req-audit-1',
  application_id: applicationID,
  domain: 'shop.internal',
  gateway_node_id: 'gw-1',
  client_ip: '192.0.2.10',
  client_port: 51000,
  request_method: 'POST',
  request_uri: '/v1/login',
  request_path: '/v1/login',
  query_summary: '',
  http_version: 'HTTP/2.0',
  content_type: 'application/x-www-form-urlencoded',
  user_agent_summary: 'test-agent',
  referer_summary: '',
  response_status: 200,
  bytes_in: 64,
  bytes_out: 128,
  duration_ms: 58,
  waf_action: 'ALLOW',
  trace_id: traceID,
  span_id: '0123456789abcdef',
  endpoint_key: 'POST /v1/login',
  path_template: '/v1/login',
  ttfb_ms: 42,
  request_headers: { Authorization: ['masked'] },
  request_body: 'pwd=masked',
  response_headers: {},
  response_body: '',
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify({ code: 'SUCCESS', data: body }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AccessLogsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function triggerSearch(placeholder: string, value: string) {
  const input = screen.getByPlaceholderText(placeholder)
  fireEvent.change(input, { target: { value } })
  const button = input.closest('.ant-input-search')?.querySelector('.ant-input-search-btn')
  expect(button).toBeTruthy()
  fireEvent.click(button as HTMLElement)
}

describe('AccessLogsPage request audit', () => {
  beforeEach(() => {
    const user: CurrentUser = {
      id: 'u1', username: 'security', display_name: '安全管理员', status: 'ACTIVE',
      roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
      permissions: ['access_logs.read', 'access_logs.export'], must_change_password: false,
    }
    useAuthStore.setState({ user })
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/applications')) {
        return Promise.resolve(jsonResponse({ items: [{ id: applicationID, name: '商城', code: 'shop' }], total: 1 }))
      }
      if (url.includes('/access-logs/trend')) {
        return Promise.resolve(jsonResponse({
          items: [{ bucket: '2026-11-17T01:30:00Z', total: 2, blocked: 1, errors: 0 }],
          bucket_seconds: 900,
        }))
      }
      if (url.includes('/access-logs/')) {
        return Promise.resolve(jsonResponse(log))
      }
      if (url.includes('/access-logs')) {
        return Promise.resolve(jsonResponse({ items: [log], page: 1, page_size: 20, total: 1 }))
      }
      return Promise.resolve(new Response(null, { status: 404 }))
    }))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('把审计筛选用于列表和趋势，并在详情显示真实Trace与TTFB', async () => {
    renderPage()
    expect(await screen.findByText('/v1/login')).toBeInTheDocument()
    expect(await screen.findByTestId('request-trend-total')).toHaveTextContent('2')

    triggerSearch('Trace ID', traceID)
    triggerSearch('身份指纹', 'identity-hmac-1')
    triggerSearch('命中规则 ID', 'sensitive.field')
    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.map((call) => String(call[0]))
      expect(calls.some((url) => url.includes('/access-logs?') && url.includes('trace_id=' + traceID) && url.includes('identity_fingerprint=identity-hmac-1') && url.includes('rule_id=sensitive.field'))).toBe(true)
      expect(calls.some((url) => url.includes('/access-logs/trend?') && url.includes('trace_id=' + traceID) && url.includes('rule_id=sensitive.field'))).toBe(true)
    })

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText(traceID)).toBeInTheDocument()
    expect(within(drawer).getByText('42 ms')).toBeInTheDocument()
    expect(within(drawer).getByText('POST /v1/login')).toBeInTheDocument()
  })
})
