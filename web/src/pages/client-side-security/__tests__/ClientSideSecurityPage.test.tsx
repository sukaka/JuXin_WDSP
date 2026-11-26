import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ClientSideSecurityPage from '../ClientSideSecurityPage'
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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const SAMPLE_APPS = [
  {
    id: 'app-1',
    code: 'checkout',
    name: '支付结账站点',
    status: 'ACTIVE',
    protection_mode: 'PROTECT',
    deployment_mode: 'REVERSE_PROXY',
    deployment_status: 'PUBLISHED',
    health_status: 'HEALTHY',
    created_at: '2026-11-01T00:00:00Z',
    updated_at: '2026-11-01T00:00:00Z',
    version: 1,
  },
]

const SAMPLE_SCRIPTS = [
  {
    id: 'scr-1',
    application_id: 'app-1',
    script_url: 'https://cdn.example.com/pay-sdk.js',
    script_origin: 'https://cdn.example.com',
    script_type: 'EXTERNAL',
    sri_hash: 'sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    observed_sri: 'sha384-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    status: 'AUTHORIZED',
    justification: '支付网关官方 3DS SDK',
    approved_by: 'secops',
    approved_at: '2026-11-20T08:00:00Z',
    sample_page_path: '/checkout',
    first_seen_at: '2026-11-18T00:00:00Z',
    last_seen_at: '2026-11-26T07:30:00Z',
    observed_count: 42,
    created_at: '2026-11-18T00:00:00Z',
    updated_at: '2026-11-26T07:30:00Z',
  },
  {
    id: 'scr-2',
    application_id: 'app-1',
    script_url: 'https://analytics.untrusted.example/tracker.js',
    script_origin: 'https://analytics.untrusted.example',
    script_type: 'EXTERNAL',
    sri_hash: '',
    observed_sri: 'sha384-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
    status: 'DISCOVERED',
    justification: '',
    approved_by: '',
    approved_at: null,
    sample_page_path: '/pay',
    first_seen_at: '2026-11-25T00:00:00Z',
    last_seen_at: '2026-11-26T08:00:00Z',
    observed_count: 5,
    created_at: '2026-11-25T00:00:00Z',
    updated_at: '2026-11-26T08:00:00Z',
  },
]

const SAMPLE_VIOLATIONS = [
  {
    id: 'vio-1',
    application_id: 'app-1',
    request_id: 'req-101',
    occurred_at: '2026-11-26T08:10:00Z',
    violation_type: 'SCRIPT_TAMPERED',
    script_url: 'https://cdn.example.com/pay-sdk.js',
    script_origin: 'https://cdn.example.com',
    expected_sri: 'sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    observed_sri: 'sha384-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
    page_path: '/checkout',
    violated_directive: 'script-src',
    blocked_uri: 'https://cdn.example.com/pay-sdk.js',
    action_taken: 'STRIPPED',
    reason: 'SRI 完整性校验失败',
    client_ip: '203.0.113.10',
    status: 'OPEN',
    note: '',
    handled_by: '',
    handled_at: null,
    created_at: '2026-11-26T08:10:00Z',
  },
]

function mockFetch() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/api/v1/applications') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: SAMPLE_APPS, total: 1, page: 1, page_size: 200 },
        }),
      )
    }
    if (url.includes('/api/v1/client-side/scripts/scr-2') && method === 'PUT') {
      const payload = JSON.parse(String(init?.body)) as Record<string, unknown>
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { script: { ...SAMPLE_SCRIPTS[1], ...payload } },
        }),
      )
    }
    if (
      url.includes('/api/v1/client-side/scripts/scr-2') &&
      method === 'DELETE'
    ) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { deleted: true, id: 'scr-2' },
        }),
      )
    }
    if (url.includes('/api/v1/client-side/scripts') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: SAMPLE_SCRIPTS, total: 2, page: 1, page_size: 20 },
        }),
      )
    }
    if (url.includes('/api/v1/client-side/scripts') && method === 'POST') {
      const payload = JSON.parse(String(init?.body)) as Record<string, unknown>
      return Promise.resolve(
        jsonResponse(201, {
          code: 'SUCCESS',
          message: 'created',
          data: {
            script: {
              id: 'scr-new',
              ...payload,
              script_origin: 'https://static.example.com',
              observed_sri: '',
              approved_by: 'secops',
              approved_at: '2026-11-26T08:15:00Z',
              sample_page_path: '',
              first_seen_at: null,
              last_seen_at: null,
              observed_count: 0,
              created_at: '2026-11-26T08:15:00Z',
              updated_at: '2026-11-26T08:15:00Z',
            },
          },
        }),
      )
    }
    if (
      url.includes('/api/v1/client-side/violations/vio-1/status') &&
      method === 'PUT'
    ) {
      const payload = JSON.parse(String(init?.body)) as Record<string, unknown>
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { violation: { ...SAMPLE_VIOLATIONS[0], ...payload } },
        }),
      )
    }
    if (url.includes('/api/v1/client-side/violations') && method === 'GET') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: SAMPLE_VIOLATIONS, total: 1, page: 1, page_size: 20 },
        }),
      )
    }
    if (
      url.includes('/api/v1/client-side/compliance-export') &&
      method === 'GET'
    ) {
      return Promise.resolve(
        new Response('\uFEFF应用,脚本地址,状态,授权依据\n支付结账站点,https://cdn.example.com/pay-sdk.js,已授权,支付网关官方 3DS SDK\n', {
          status: 200,
          headers: {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition':
              'attachment; filename="pci-dss-6-4-3-evidence.csv"',
          },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected request: ${method} ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <ClientSideSecurityPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ClientSideSecurityPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('Tab 1 展示脚本资产清单、SRI 不匹配标记、状态标签与导出 CSV 合规证据', async () => {
    useAuthStore.setState({
      user: makeUser([
        'applications.read',
        'client_side.read',
        'client_side.manage',
      ]),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(
      await screen.findByText('https://cdn.example.com/pay-sdk.js'),
    ).toBeInTheDocument()
    expect(screen.getByText('SRI 不匹配（疑似篡改）')).toBeInTheDocument()
    expect(screen.getByText('已授权')).toBeInTheDocument()
    expect(screen.getByText('新发现待审')).toBeInTheDocument()
    expect(screen.getByText('支付网关官方 3DS SDK')).toBeInTheDocument()

    fireEvent.click(
      screen.getByRole('button', { name: /导出 PCI DSS 合规证据/ }),
    )
    expect(
      await screen.findByText('PCI DSS 合规证据 CSV 导出成功'),
    ).toBeInTheDocument()
    expect(
      (fetch as Mock).mock.calls.some((c) =>
        String(c[0]).includes('/api/v1/client-side/compliance-export'),
      ),
    ).toBe(true)
  })

  it('只读权限（仅 client_side.read）保留 CSV 导出，隐藏新增、审批与删除操作', async () => {
    useAuthStore.setState({
      user: makeUser(['client_side.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(
      await screen.findByText('https://cdn.example.com/pay-sdk.js'),
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /导出 PCI DSS 合规证据/ }),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /新增预授权脚本/ }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /审批\/编辑/ }),
    ).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删除/ })).not.toBeInTheDocument()
  })

  it('新增预授权脚本弹窗强制要求 AUTHORIZED 填写 PCI DSS 4.0 6.4.3 业务授权依据', async () => {
    useAuthStore.setState({
      user: makeUser([
        'applications.read',
        'client_side.read',
        'client_side.manage',
      ]),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('https://cdn.example.com/pay-sdk.js')

    fireEvent.click(screen.getByRole('button', { name: /新增预授权脚本/ }))
    fireEvent.change(
      await screen.findByPlaceholderText(
        '如 https://cdn.example.com/checkout.min.js',
      ),
      { target: { value: 'https://static.example.com/widget.js' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '确认新增' }))
    expect(
      await screen.findByText(
        'PCI DSS 4.0 6.4.3 要求：设为「已授权」时必须填写业务授权依据',
      ),
    ).toBeInTheDocument()

    fireEvent.change(
      screen.getByPlaceholderText(
        '如：支付网关官方 SDK，用于 3DS 鉴权表单，已经安全团队代码审查与 SRI 锁定',
      ),
      { target: { value: '收银台验证码组件，已通过安全代码审计' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '确认新增' }))
    expect(
      await screen.findByText('脚本资产已新增；需经配置发布同步到网关节点'),
    ).toBeInTheDocument()

    const postCall = (fetch as Mock).mock.calls.find(
      (c) =>
        String(c[0]).endsWith('/api/v1/client-side/scripts') &&
        c[1]?.method === 'POST',
    )
    expect(postCall).toBeTruthy()
    const body = JSON.parse(String(postCall![1]?.body)) as Record<
      string,
      unknown
    >
    expect(body).toEqual({
      application_id: 'app-1',
      script_url: 'https://static.example.com/widget.js',
      script_type: 'EXTERNAL',
      sri_hash: '',
      status: 'AUTHORIZED',
      justification: '收银台验证码组件，已通过安全代码审计',
    })
  })

  it('审批/编辑抽屉支持一键采纳观测 SRI 并保存审批，删除确认后调用 DELETE', async () => {
    useAuthStore.setState({
      user: makeUser([
        'applications.read',
        'client_side.read',
        'client_side.manage',
      ]),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('https://analytics.untrusted.example/tracker.js')

    const reviewButtons = screen.getAllByRole('button', { name: /审批\/编辑/ })
    fireEvent.click(reviewButtons[1])
    expect(
      await screen.findByText('脚本审批与 SRI 维护（PCI DSS 6.4.3）'),
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '采纳为固定 SRI' }))
    fireEvent.change(
      screen.getByPlaceholderText(
        '说明该脚本为什么必须加载在支付/登录等页面，以及安全验证方式',
      ),
      { target: { value: '经确认系非必要第三方脚本，保持待审观察' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存审批' }))
    expect(
      await screen.findByText('脚本审批与配置已更新；发布后生效至网关'),
    ).toBeInTheDocument()

    const putCall = (fetch as Mock).mock.calls.find(
      (c) =>
        String(c[0]).endsWith('/api/v1/client-side/scripts/scr-2') &&
        c[1]?.method === 'PUT',
    )
    expect(putCall).toBeTruthy()
    const putBody = JSON.parse(String(putCall![1]?.body)) as Record<
      string,
      unknown
    >
    expect(putBody.sri_hash).toBe(
      'sha384-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
    )

    const deleteButtons = screen.getAllByRole('button', { name: /删除/ })
    fireEvent.click(deleteButtons[1])
    fireEvent.click(await screen.findByRole('button', { name: '确认删除' }))
    expect(await screen.findByText('脚本记录已删除')).toBeInTheDocument()
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some(
          (c) =>
            String(c[0]).endsWith('/api/v1/client-side/scripts/scr-2') &&
            c[1]?.method === 'DELETE',
        ),
      ).toBe(true)
    })
  })

  it('Tab 2 展示篡改与 CSP 违规告警并可通过处置弹窗提交状态与备注', async () => {
    useAuthStore.setState({
      user: makeUser([
        'applications.read',
        'client_side.read',
        'client_side.manage',
      ]),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('https://cdn.example.com/pay-sdk.js')

    fireEvent.click(
      screen.getByRole('tab', {
        name: '篡改与 CSP 违规告警（PCI DSS 11.6.1）',
      }),
    )
    expect(
      await screen.findByText('脚本篡改（SRI 异常）'),
    ).toBeInTheDocument()
    expect(screen.getByText('已剥离脚本')).toBeInTheDocument()
    expect(screen.getByText('script-src')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '处置' }))
    expect(
      await screen.findByText('处置篡改与 CSP 违规告警'),
    ).toBeInTheDocument()
    fireEvent.change(
      screen.getByPlaceholderText('记录排查结论、工单号或后续整改措施'),
      { target: { value: '已通知前端回滚 CDN 资源并核验构建流水线' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存处置' }))
    expect(await screen.findByText('违规告警处置状态已更新')).toBeInTheDocument()

    const putCall = (fetch as Mock).mock.calls.find(
      (c) =>
        String(c[0]).endsWith('/api/v1/client-side/violations/vio-1/status') &&
        c[1]?.method === 'PUT',
    )
    expect(putCall).toBeTruthy()
    const body = JSON.parse(String(putCall![1]?.body)) as Record<
      string,
      unknown
    >
    expect(body).toEqual({
      status: 'OPEN',
      note: '已通知前端回滚 CDN 资源并核验构建流水线',
    })
  })

  it('GET 403 展示无权限提示', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(403, {
            code: 'FORBIDDEN',
            message: '无权限',
            data: null,
          }),
        ),
      ),
    )
    useAuthStore.setState({
      user: makeUser(['client_side.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })
})
