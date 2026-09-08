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
import JwtTrustTab from '../detail/JwtTrustTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const APP_ID = 'app-1'
const APP_CODE = 'shop'

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
    application_id: APP_ID,
    mode: 'OFF',
    version: 0,
    selectors: null,
    issuers: null,
    updated_by: '',
    created_at: '',
    updated_at: '',
  },
  summary: { state: 'NOT_CONFIGURED', draft_version: 0, published_version: 0 },
}

const DRAFT_PENDING = {
  policy: {
    id: 'p1',
    application_id: APP_ID,
    mode: 'OBSERVE',
    version: 3,
    selectors: [
      { methods: ['GET', 'POST'], path_prefix: '/api', token_required: true },
    ],
    issuers: [
      {
        issuer: 'https://idp.example.com/',
        audiences: ['shop-api'],
        algorithms: ['RS256'],
        key_source: {
          type: 'STATIC_JWKS',
          jwks: '{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}',
        },
        clock_skew_seconds: 30,
      },
    ],
    updated_by: 'secops',
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-05T10:00:00Z',
  },
  summary: { state: 'DRAFT_PENDING', draft_version: 3, published_version: 1 },
}

function mockFetch(getData: unknown = UNCONFIGURED, putStatus = 200) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes(`/applications/${APP_ID}/jwt-trust-policy/preflight`)) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { policy: UNCONFIGURED.policy, checks: [], publishable: true },
        }),
      )
    }
    if (url.includes(`/applications/${APP_ID}/jwt-trust-policy`)) {
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
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              policy: { ...UNCONFIGURED.policy, version: 1, mode: 'OFF' },
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
        <JwtTrustTab appId={APP_ID} appCode={APP_CODE} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('JwtTrustTab', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('未配置空态：展示未配置状态、默认 OFF 模式与提示', async () => {
    useAuthStore.setState({
      user: makeUser(['jwt_trust.read', 'jwt_trust.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('未配置')).toBeInTheDocument()
    expect(
      screen.getByText('尚未配置 JWT 信任策略，当前不校验业务 Token'),
    ).toBeInTheDocument()
    expect(screen.getByText('关闭（不校验 Token）')).toBeInTheDocument()
    expect(screen.getByText('无草稿')).toBeInTheDocument()
    expect(screen.getByText('未随发布下发')).toBeInTheDocument()
    expect(screen.getByText(APP_CODE)).toBeInTheDocument()
  })

  it('草稿待发布态：展示草稿与已生效版本差异提示', async () => {
    vi.stubGlobal('fetch', mockFetch(DRAFT_PENDING))
    useAuthStore.setState({
      user: makeUser(['jwt_trust.read', 'jwt_trust.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('草稿待发布')).toBeInTheDocument()
    expect(screen.getByText('草稿已保存，尚未生效')).toBeInTheDocument()
    expect(screen.getByText('v3')).toBeInTheDocument()
    expect(screen.getByText('v1')).toBeInTheDocument()
  })

  it('模式切换：选择强制验证后展示发布门禁提示', async () => {
    useAuthStore.setState({
      user: makeUser(['jwt_trust.read', 'jwt_trust.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    fireEvent.click(
      screen.getByText('强制验证（非法 Token 401 / 验证不可用 503）'),
    )
    expect(
      await screen.findByText(
        /强制验证要求应用 API 动态管线已启用且为 PROTECT/,
      ),
    ).toBeInTheDocument()
  })

  it('静态 JWKS 粘贴私钥材料：立即拒绝并清空，不回显已粘贴内容', async () => {
    useAuthStore.setState({
      user: makeUser(['jwt_trust.read', 'jwt_trust.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    fireEvent.click(screen.getByRole('button', { name: /添加发行方/ }))
    const textarea = (await screen.findByPlaceholderText(
      '{"keys":[{"kty":"RSA","kid":"...","n":"...","e":"AQAB"}]}',
    )) as HTMLTextAreaElement
    fireEvent.change(textarea, {
      target: {
        value:
          '{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB","d":"private-secret"}]}',
      },
    })
    expect(await screen.findByText(/已拒绝并清空输入/)).toBeInTheDocument()
    await waitFor(() => expect(textarea.value).toBe(''))
  })

  it('保存成功：PUT 携带 expected_version 与 reason', async () => {
    useAuthStore.setState({
      user: makeUser(['jwt_trust.read', 'jwt_trust.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    fireEvent.change(
      screen.getByPlaceholderText('说明本次变更原因，如：接入新的身份发行方'),
      {
        target: { value: '初始接入' },
      },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('草稿已保存；发布并获节点回执后才会生效'),
    ).toBeInTheDocument()
    const putCall = (fetch as Mock).mock.calls.find(
      (c) =>
        String(c[0]).includes(`/applications/${APP_ID}/jwt-trust-policy`) &&
        c[1]?.method === 'PUT',
    )
    expect(putCall).toBeTruthy()
    const body = JSON.parse(String(putCall![1]?.body)) as Record<
      string,
      unknown
    >
    expect(body.expected_version).toBe(0)
    expect(body.mode).toBe('OFF')
    expect(body.reason).toBe('初始接入')
    expect(body.selectors).toEqual([])
    expect(body.issuers).toEqual([])
  })

  it('409 冲突：提示刷新后重试', async () => {
    vi.stubGlobal('fetch', mockFetch(UNCONFIGURED, 409))
    useAuthStore.setState({
      user: makeUser(['jwt_trust.read', 'jwt_trust.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    fireEvent.change(
      screen.getByPlaceholderText('说明本次变更原因，如：接入新的身份发行方'),
      {
        target: { value: '初始接入' },
      },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('策略已被其他人修改，请刷新后重试'),
    ).toBeInTheDocument()
  })

  it('只读权限（无 jwt_trust.manage）：隐藏保存/预检与变更理由', async () => {
    useAuthStore.setState({
      user: makeUser(['jwt_trust.read']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')
    expect(
      screen.queryByRole('button', { name: '保存草稿' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: '发布预检' }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText('变更理由')).not.toBeInTheDocument()
  })

  it('GET 403：展示无权限提示', async () => {
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
      user: makeUser(['jwt_trust.read']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })
})
