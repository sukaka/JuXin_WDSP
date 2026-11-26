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
import { CLIENT_SIDE_LIMITS } from '../../../api/clientSide'
import {
  buildCspPreview,
  isValidCspOriginToken,
  mapClientSideFieldErrorPath,
  validateCspOrigins,
} from '../../../utils/clientSide'
import ClientSideTab from '../detail/ClientSideTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const APP_ID = 'app-1'
const APP_CODE = 'checkout'

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

const UNCONFIGURED = {
  policy: {
    id: '',
    schema_version: 1,
    application_id: APP_ID,
    mode: 'OFF',
    version: 0,
    csp_mode: 'OFF',
    sensitive_paths: null,
    probe_enabled: false,
    strip_unauthorized_scripts: false,
    allowed_script_origins: null,
    allowed_connect_origins: null,
    allowed_form_origins: null,
    custom_csp_directives: '',
    updated_by: '',
    created_at: '',
    updated_at: '',
  },
  summary: { state: 'NOT_CONFIGURED', draft_version: 0, published_version: 0 },
}

const DRAFT_PENDING = {
  policy: {
    id: 'cs-1',
    schema_version: 1,
    application_id: APP_ID,
    mode: 'PROTECT',
    version: 3,
    csp_mode: 'ENFORCE',
    sensitive_paths: ['/checkout', '/pay'],
    probe_enabled: true,
    strip_unauthorized_scripts: true,
    allowed_script_origins: ["'self'", 'https://cdn.example.com'],
    allowed_connect_origins: ["'self'", 'https://api.example.com'],
    allowed_form_origins: ["'self'"],
    custom_csp_directives: "object-src 'none'; frame-ancestors 'none'",
    updated_by: 'secops',
    created_at: '2026-11-10T00:00:00Z',
    updated_at: '2026-11-26T08:00:00Z',
  },
  summary: { state: 'DRAFT_PENDING', draft_version: 3, published_version: 1 },
}

function mockFetch(getData: unknown = UNCONFIGURED, putStatus = 200) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes(`/applications/${APP_ID}/client-side-policy`)) {
      if (method === 'PUT') {
        if (putStatus === 409) {
          return Promise.resolve(
            jsonResponse(409, {
              code: 'RESOURCE_CONFLICT',
              message: '策略已被其他人修改，请刷新后重试',
              data: null,
            }),
          )
        }
        if (putStatus === 400) {
          return Promise.resolve(
            jsonResponse(400, {
              code: 'INVALID_ARGUMENT',
              message: '参数校验失败',
              details: [
                {
                  field: 'custom_csp_directives',
                  message: '自定义指令包含非法控制字符',
                },
              ],
            }),
          )
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              policy: { ...DRAFT_PENDING.policy, version: 4 },
            },
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: getData }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <ClientSideTab appId={APP_ID} appCode={APP_CODE} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ClientSideTab', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('未配置空态：展示默认 OFF 模式、状态摘要、共享上限常量与关闭态 CSP 预览', async () => {
    useAuthStore.setState({
      user: makeUser(['client_side.read', 'client_side.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('未配置')).toBeInTheDocument()
    expect(
      screen.getByText('尚未配置客户端供应链安全策略，当前维持默认透传行为'),
    ).toBeInTheDocument()
    expect(screen.getByText('关闭（不启用客户端防护）')).toBeInTheDocument()
    expect(screen.getByText(APP_CODE)).toBeInTheDocument()
    expect(screen.getByTestId('csp-header-preview')).toHaveTextContent(
      '当前 CSP 模式为「关闭」',
    )
    expect(CLIENT_SIDE_LIMITS.maxSensitivePaths).toBe(64)
    expect(CLIENT_SIDE_LIMITS.maxPathLen).toBe(512)
    expect(CLIENT_SIDE_LIMITS.maxOrigins).toBe(64)
    expect(CLIENT_SIDE_LIMITS.maxCustomDirectivesLen).toBe(2048)
    expect(CLIENT_SIDE_LIMITS.maxJustificationLen).toBe(1000)
  })

  it('草稿待发布态：实时渲染编译后 CSP Header 预览并按精确 DTO 契约提交 PUT', async () => {
    vi.stubGlobal('fetch', mockFetch(DRAFT_PENDING))
    useAuthStore.setState({
      user: makeUser(['client_side.read', 'client_side.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('草稿待发布')).toBeInTheDocument()
    expect(screen.getByText('v3')).toBeInTheDocument()
    expect(screen.getByText('v1')).toBeInTheDocument()

    await waitFor(() => {
      const preview = screen.getByTestId('csp-header-preview')
      expect(preview).toHaveTextContent('Content-Security-Policy:')
      expect(preview).toHaveTextContent(
        "script-src 'self' https://cdn.example.com; connect-src 'self' https://api.example.com; form-action 'self'; object-src 'none'; frame-ancestors 'none'; report-uri /_wdsp/csp/v1/report",
      )
    })

    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：为结账页开启 CSP 学习上报与防窃取探针',
      ),
      { target: { value: '为支付结账页开启强制 CSP 与脚本防篡改' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('草稿已保存；发布并获节点回执后才会生效'),
    ).toBeInTheDocument()

    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).endsWith(`/applications/${APP_ID}/client-side-policy`) &&
          c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body)) as Record<
        string,
        unknown
      >
      expect(body).toEqual({
        mode: 'PROTECT',
        expected_version: 3,
        csp_mode: 'ENFORCE',
        sensitive_paths: ['/checkout', '/pay'],
        probe_enabled: true,
        strip_unauthorized_scripts: true,
        allowed_script_origins: ["'self'", 'https://cdn.example.com'],
        allowed_connect_origins: ["'self'", 'https://api.example.com'],
        allowed_form_origins: ["'self'"],
        custom_csp_directives: "object-src 'none'; frame-ancestors 'none'",
        reason: '为支付结账页开启强制 CSP 与脚本防篡改',
      })
    })
  })

  it('校验拦截自定义 CSP 指令中的换行符，防响应头注入', async () => {
    useAuthStore.setState({
      user: makeUser(['client_side.read', 'client_side.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')

    fireEvent.change(
      screen.getByPlaceholderText(
        "如 object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
      ),
      { target: { value: "object-src 'none'\r\nX-Injected: bad" } },
    )
    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：为结账页开启 CSP 学习上报与防窃取探针',
      ),
      { target: { value: '测试换行拦截' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText(
        '自定义 CSP 指令不允许包含换行或控制字符（防止响应头注入）',
      ),
    ).toBeInTheDocument()
  })

  it('409 冲突提示刷新重试，400 字段级错误回显到对应表单项', async () => {
    vi.stubGlobal('fetch', mockFetch(UNCONFIGURED, 409))
    useAuthStore.setState({
      user: makeUser(['client_side.read', 'client_side.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：为结账页开启 CSP 学习上报与防窃取探针',
      ),
      { target: { value: '冲突测试' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('策略已被其他人修改，请刷新后重试'),
    ).toBeInTheDocument()

    vi.stubGlobal('fetch', mockFetch(UNCONFIGURED, 400))
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('自定义指令包含非法控制字符'),
    ).toBeInTheDocument()
  })

  it('只读权限（仅 client_side.read）隐藏保存按钮与变更理由', async () => {
    useAuthStore.setState({
      user: makeUser(['client_side.read']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    expect(
      screen.queryByRole('button', { name: '保存草稿' }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText('变更理由')).not.toBeInTheDocument()
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
    renderTab()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('CSP 预览工具在开启探针时自动补全 script-src 与 connect-src 的 self，并正确映射数组字段路径', () => {
    const preview = buildCspPreview({
      mode: 'OBSERVE',
      csp_mode: 'REPORT_ONLY',
      probe_enabled: true,
      allowed_script_origins: ['https://cdn.example.com'],
      allowed_connect_origins: [],
      allowed_form_origins: ["'self'"],
      custom_csp_directives: "base-uri 'self';",
    })
    expect(preview.active).toBe(true)
    expect(preview.headerName).toBe('Content-Security-Policy-Report-Only')
    expect(preview.headerValue).toBe(
      "script-src 'self' https://cdn.example.com; connect-src 'self'; form-action 'self'; base-uri 'self'; report-uri /_wdsp/csp/v1/report",
    )
    expect(mapClientSideFieldErrorPath('sensitive_paths[0]')).toEqual([
      'sensitive_paths',
    ])
    expect(mapClientSideFieldErrorPath('allowed_script_origins[2]')).toEqual([
      'allowed_script_origins',
    ])
  })

  it('CSP 来源校验允许 http/https/ws/wss 源并拒绝 ftp/javascript 等非法协议', () => {
    expect(
      validateCspOrigins(
        [
          "'self'",
          'https://cdn.example.com',
          'http://api.example.com:8080',
          'ws://ws.example.com',
          'wss://ws.example.com:8443/stream',
          'wss:',
          '*.example.com',
        ],
        '允许数据外传目标',
      ),
    ).toBeNull()
    expect(isValidCspOriginToken('wss://ws.example.com')).toBe(true)
    expect(isValidCspOriginToken('ws://localhost:3000')).toBe(true)
    expect(isValidCspOriginToken('ftp://files.example.com')).toBe(false)
    expect(isValidCspOriginToken('javascript://alert(1)')).toBe(false)
    expect(
      validateCspOrigins(['ftp://files.example.com'], '允许数据外传目标'),
    ).toContain('非法来源')
  })
})
