import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import IdentityDetailPage from '../IdentityDetailPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const chartProps = vi.hoisted(
  () => [] as { option: unknown; height?: number }[],
)
vi.mock('../../../components/EChart', () => ({
  default: (props: { option: unknown; height?: number }) => {
    chartProps.push(props)
    return <div data-testid="echart-stub" data-height={props.height} />
  },
}))

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
  let behaviorCalls: string[]
  let actionError: string | null
  let behaviorHandler: ((url: string) => unknown) | null
  let eventsHandler: (() => unknown) | null

  beforeEach(() => {
    chartProps.length = 0
    status = 'NORMAL'
    detailRequests = 0
    blockCalls = []
    unblockCalls = []
    behaviorCalls = []
    actionError = null
    behaviorHandler = null
    eventsHandler = null
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
              data: {
                identity: { ...IDENTITY, status },
                changed: true,
              },
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
          status = 'NORMAL'
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                identity: { ...IDENTITY, status },
                changed: true,
              },
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
          url.includes('/security/identities/idn-1/behavior?')
        ) {
          behaviorCalls.push(url)
          const payload = behaviorHandler
            ? behaviorHandler(url)
            : { items: [], page: 1, page_size: 200, total: 0 }
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: payload,
            }),
          )
        }
        if (
          method === 'GET' &&
          url.includes('/security/identities/idn-1/events?')
        ) {
          const payload = eventsHandler
            ? eventsHandler()
            : { items: [], page: 1, page_size: 20, total: 0 }
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: payload,
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

  it('NORMAL 状态渲染绿色正常标签', async () => {
    status = 'NORMAL'
    renderPage()

    expect(await screen.findByText('正常')).toBeInTheDocument()
  })

  it('行为趋势按 page_size=200 分页拉取完整 288 个 5 分钟窗口', async () => {
    const makeBucket = (idx: number) => ({
      window_type: '5m',
      window_start: new Date(Date.UTC(2026, 7, 30, 0, idx * 5)).toISOString(),
      request_count: idx + 1,
      unique_uri_count: 2,
      new_uri_count: 1,
      status_401_count: 0,
      status_403_count: 0,
      status_404_count: 0,
      status_405_count: 0,
      status_500_count: 0,
      auth_fail_count: 0,
      parameter_mutation_count: 0,
      sensitive_path_hits: 0,
      account_enum_count: 0,
      object_enum_count: 0,
    })
    behaviorHandler = (url) => {
      const qs = new URL(url, 'http://localhost').searchParams
      const page = Number(qs.get('page'))
      expect(qs.get('page_size')).toBe('200')
      if (page === 1) {
        return {
          items: Array.from({ length: 200 }, (_, i) => makeBucket(i)),
          page: 1,
          page_size: 200,
          total: 288,
        }
      }
      return {
        items: Array.from({ length: 88 }, (_, i) => makeBucket(200 + i)),
        page: 2,
        page_size: 200,
        total: 288,
      }
    }

    renderPage()
    fireEvent.click(await screen.findByRole('tab', { name: '行为趋势' }))

    expect(await screen.findByTestId('echart-stub')).toBeInTheDocument()
    await waitFor(() => expect(behaviorCalls).toHaveLength(2))
    expect(behaviorCalls[0]).toContain('page=1')
    expect(behaviorCalls[0]).toContain('page_size=200')
    expect(behaviorCalls[1]).toContain('page=2')
    expect(behaviorCalls[1]).toContain('page_size=200')
    const option = chartProps[chartProps.length - 1]?.option as {
      xAxis: { data: string[] }
    }
    expect(option.xAxis.data).toHaveLength(288)
  })

  it('行为趋势遇到空页时提前终止翻页，避免死循环', async () => {
    behaviorHandler = (url) => {
      const qs = new URL(url, 'http://localhost').searchParams
      const page = Number(qs.get('page'))
      if (page === 1) {
        return {
          items: [
            {
              window_type: '5m',
              window_start: '2026-08-30T00:00:00Z',
              request_count: 5,
              unique_uri_count: 1,
              new_uri_count: 0,
              status_401_count: 0,
              status_403_count: 0,
              status_404_count: 0,
              status_405_count: 0,
              status_500_count: 0,
              auth_fail_count: 0,
              parameter_mutation_count: 0,
              sensitive_path_hits: 0,
              account_enum_count: 0,
              object_enum_count: 0,
            },
          ],
          page: 1,
          page_size: 200,
          total: 600,
        }
      }
      return { items: [], page, page_size: 200, total: 600 }
    }

    renderPage()
    fireEvent.click(await screen.findByRole('tab', { name: '行为趋势' }))
    expect(await screen.findByTestId('echart-stub')).toBeInTheDocument()
    await waitFor(() => expect(behaviorCalls).toHaveLength(2))
  })

  it('行为事件标签页可正常渲染无 window 字段的后端事件', async () => {
    eventsHandler = () => ({
      items: [
        {
          id: 'ev-1',
          occurred_at: '2026-08-31T10:00:00Z',
          event_kind: 'RECON_SIGNAL',
          rule_code: 'URI_ENUM_01',
          rule_version: '1',
          signal: 'URI_ENUMERATION',
          risk_score_delta: 20,
          mode: 'OBSERVE',
          reason: '高频探测不同 URI',
          metadata: {},
          request_id: 'req-1',
          client_ip: '1.2.3.4',
          method: 'GET',
          path: '/admin/test',
          app_id: 'app-1',
          domain: 'example.com',
          gateway_node: 'gw-1',
          identity_confidence: 90,
          identity_evidence: ['client_ip'],
        },
      ],
      page: 1,
      page_size: 20,
      total: 1,
    })

    renderPage()
    fireEvent.click(await screen.findByRole('tab', { name: '行为事件' }))
    expect(await screen.findByText('高频探测不同 URI')).toBeInTheDocument()
    expect(screen.getByText('GET /admin/test')).toBeInTheDocument()
  })
})
