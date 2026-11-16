import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiGroupControlPage from '../ApiGroupControlPage'

vi.mock('../GroupControlTrend', () => ({
  default: () => <div data-testid="group-control-trend" />,
}))

const applicationId = '11111111-1111-1111-1111-111111111111'
const deviceFingerprint = 'b3c7a91e'.repeat(4)

function response(data: unknown, status = 200): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function applicationsResponse(): Response {
  return response({
    items: [{ id: applicationId, code: 'store-hub', name: '巡店协作平台' }],
    page: 1,
    page_size: 100,
    total: 1,
  })
}

function sharedDevicesResponse(
  overrides: Record<string, unknown> = {},
): Response {
  return response({
    items: [
      {
        application_id: applicationId,
        application_name: '巡店协作平台',
        device_fingerprint: deviceFingerprint,
        distinct_accounts: 3,
        event_count: 18,
        signal_count: 2,
        endpoint_count: 4,
        gateway_node_count: 2,
        first_seen_at: '2026-11-14T08:00:00Z',
        last_seen_at: '2026-11-14T09:00:00Z',
      },
    ],
    page: 1,
    page_size: 20,
    total: 1,
    partial: true,
    data_scope: 'NOTABLE_SECURITY_EVENTS',
    ...overrides,
  })
}

function sharedDeviceAccountsResponse(): Response {
  return response({
    items: [
      {
        principal_ref: 'd4e5f6a1'.repeat(4),
        event_count: 7,
        signal_count: 1,
        endpoint_count: 2,
        first_seen_at: '2026-11-14T08:00:00Z',
        last_seen_at: '2026-11-14T09:00:00Z',
      },
    ],
    page: 1,
    page_size: 20,
    total: 1,
    partial: true,
    data_scope: 'NOTABLE_SECURITY_EVENTS',
  })
}

function mockRequests() {
  vi.stubGlobal(
    'fetch',
    vi.fn((input) => {
      const url = String(input)
      if (url.includes('/applications?'))
        return Promise.resolve(applicationsResponse())
      if (url.includes('/api-security/group-control/shared-devices/accounts')) {
        return Promise.resolve(sharedDeviceAccountsResponse())
      }
      if (url.includes('/api-security/group-control/shared-devices')) {
        return Promise.resolve(sharedDevicesResponse())
      }
      return Promise.resolve(
        new Response(
          JSON.stringify({
            error: { code: 'NOT_FOUND', message: 'unexpected test URL' },
          }),
          { status: 404, headers: { 'Content-Type': 'application/json' } },
        ),
      )
    }),
  )
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <AntdApp>
        <ApiGroupControlPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

function sharedDeviceURLs(): URL[] {
  return vi
    .mocked(fetch)
    .mock.calls.map((call) => String(call[0]))
    .filter((url) => url.includes('/api-security/group-control/shared-devices'))
    .map((url) => new URL(url, 'http://test.local'))
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('ApiGroupControlPage', () => {
  it('展示真实聚合数据并说明非全量观察边界', async () => {
    mockRequests()
    renderPage()

    expect(await screen.findByText('巡店协作平台')).toBeInTheDocument()
    expect(screen.getByTitle(deviceFingerprint)).toBeInTheDocument()
    expect(screen.getByText('18')).toBeInTheDocument()
    expect(screen.getByText('当前为安全事件观察范围')).toBeInTheDocument()
    expect(
      screen.getByText(/不代表全量请求或实际活跃账号总数/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/principal-hmac/)).not.toBeInTheDocument()

    const urls = sharedDeviceURLs()
    expect(urls).toHaveLength(1)
    expect(urls[0].searchParams.get('min_accounts')).toBe('3')
    expect(urls[0].searchParams.get('page')).toBe('1')
    expect(urls[0].searchParams.get('page_size')).toBe('20')
    expect(urls[0].searchParams.has('start')).toBe(true)
    expect(urls[0].searchParams.has('end')).toBe(true)
    expect(urls[0].searchParams.has('application_id')).toBe(false)
  })

  it('校验设备指纹并提交应用、阈值和重置筛选', async () => {
    mockRequests()
    renderPage()
    await screen.findByText('巡店协作平台')

    fireEvent.change(screen.getByLabelText('设备指纹'), {
      target: { value: 'shared-terminal' },
    })
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))
    expect(
      await screen.findByText('设备指纹需为 32 位十六进制字符串'),
    ).toBeInTheDocument()
    expect(sharedDeviceURLs()).toHaveLength(1)

    fireEvent.change(screen.getByLabelText('设备指纹'), {
      target: { value: deviceFingerprint.toUpperCase() },
    })
    fireEvent.change(screen.getByLabelText('最少可信账号数'), {
      target: { value: '2' },
    })
    fireEvent.mouseDown(screen.getByLabelText('应用'))
    fireEvent.click(
      await screen.findByText('巡店协作平台 (store-hub)', {
        selector: '.ant-select-item-option-content',
      }),
    )
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))

    await waitFor(() => expect(sharedDeviceURLs()).toHaveLength(2))
    const filtered = sharedDeviceURLs()[1]
    expect(filtered.searchParams.get('device_fingerprint')).toBe(
      deviceFingerprint,
    )
    expect(filtered.searchParams.get('application_id')).toBe(applicationId)
    expect(filtered.searchParams.get('min_accounts')).toBe('2')
    expect(filtered.searchParams.get('page')).toBe('1')

    fireEvent.click(screen.getByRole('button', { name: /重\s*置/ }))
    await waitFor(() => expect(sharedDeviceURLs()).toHaveLength(3))
    const reset = sharedDeviceURLs()[2]
    expect(reset.searchParams.get('min_accounts')).toBe('3')
    expect(reset.searchParams.has('device_fingerprint')).toBe(false)
    expect(reset.searchParams.has('application_id')).toBe(false)
  })

  it('使用服务端分页参数切换页码', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input) => {
        const url = String(input)
        if (url.includes('/applications?'))
          return Promise.resolve(applicationsResponse())
        return Promise.resolve(sharedDevicesResponse({ total: 45 }))
      }),
    )
    renderPage()
    await screen.findByText('巡店协作平台')
    fireEvent.click(screen.getByTitle('2'))
    await waitFor(() => {
      const urls = sharedDeviceURLs()
      expect(urls).toHaveLength(2)
      expect(urls[1].searchParams.get('page')).toBe('2')
    })
  })

  it('展示无观察记录空态', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input) => {
        const url = String(input)
        if (url.includes('/applications?'))
          return Promise.resolve(applicationsResponse())
        return Promise.resolve(sharedDevicesResponse({ items: [], total: 0 }))
      }),
    )
    renderPage()
    expect(
      await screen.findByText('当前条件下暂无同设备多账号观察记录'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/需启用 API 动态防护与 JWT 信任验证/),
    ).toBeInTheDocument()
  })

  it('服务不可用时展示后端错误而不是演示数据', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input) => {
        const url = String(input)
        if (url.includes('/applications?'))
          return Promise.resolve(applicationsResponse())
        return Promise.resolve(
          new Response(
            JSON.stringify({
              code: 'SERVICE_UNAVAILABLE',
              message: '群控存储暂不可用',
            }),
            { status: 503, headers: { 'Content-Type': 'application/json' } },
          ),
        )
      }),
    )
    renderPage()
    expect(await screen.findByText('加载群控观察数据失败')).toBeInTheDocument()
    expect(screen.getByText('群控存储暂不可用')).toBeInTheDocument()
    expect(screen.queryByText('巡店协作平台')).not.toBeInTheDocument()
  })
})

describe('共享设备主体关联', () => {
  it('按当前应用、设备和时间范围加载脱敏主体关联', async () => {
    mockRequests()
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '主体关联' }))

    expect(await screen.findByRole('dialog')).toHaveTextContent(
      '共享设备主体关联',
    )
    const principalRef = 'd4e5f6a1'.repeat(4)
    expect(await screen.findByTitle(principalRef)).toBeInTheDocument()
    expect(screen.getByText('仅展示脱敏主体引用')).toBeInTheDocument()
    expect(screen.getByText(/不证明这些主体存在协同行为/)).toBeInTheDocument()

    const call = vi
      .mocked(fetch)
      .mock.calls.map((entry) => String(entry[0]))
      .find((url) =>
        url.includes('/api-security/group-control/shared-devices/accounts'),
      )
    expect(call).toBeDefined()
    const url = new URL(call!, 'http://test.local')
    expect(url.searchParams.get('application_id')).toBe(applicationId)
    expect(url.searchParams.get('device_fingerprint')).toBe(deviceFingerprint)
    expect(url.searchParams.get('page')).toBe('1')
    expect(url.searchParams.has('start')).toBe(true)
    expect(url.searchParams.has('end')).toBe(true)
  })

  it('主体关联读取失败时显示错误且不伪造主体', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input) => {
        const url = String(input)
        if (url.includes('/applications?'))
          return Promise.resolve(applicationsResponse())
        if (
          url.includes('/api-security/group-control/shared-devices/accounts')
        ) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                code: 'SERVICE_UNAVAILABLE',
                message: '主体关联暂不可用',
              }),
              { status: 503, headers: { 'Content-Type': 'application/json' } },
            ),
          )
        }
        return Promise.resolve(sharedDevicesResponse())
      }),
    )
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '主体关联' }))
    expect(await screen.findByText('加载主体关联失败')).toBeInTheDocument()
    expect(screen.getByText('主体关联暂不可用')).toBeInTheDocument()
    expect(screen.queryByTitle('d4e5f6a1'.repeat(4))).not.toBeInTheDocument()
  })
})
