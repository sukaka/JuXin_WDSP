import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiPolicyPage from '../ApiPolicyPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
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

const policyData = {
  edition: 'ENTERPRISE',
  api_dynamic_protection: true,
  mode: 'OBSERVE',
  mode_source: 'db',
  limits: {
    max_body_parse_bytes: 1048576,
    max_body_sample_bytes: 65536,
    max_json_depth: 32,
    max_field_count: 512,
  },
}

const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input)
  if (url.includes('/api-security/policy/publish')) {
    return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { message: '已发布' } }))
  }
  if (url.includes('/api-security/policy')) {
    if (init?.method === 'PUT') {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { policy: { ...policyData, mode: 'PROTECT' }, message: '防护模式已保存' },
        }),
      )
    }
    return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: policyData }))
  }
  return Promise.reject(new Error(`unexpected url: ${url}`))
})

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiPolicyPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiPolicyPage', () => {
  beforeEach(() => {
    fetchMock.mockClear()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染当前策略：防护模式 StatusTag、中文模式来源、产品形态、开关与解析限制', async () => {
    useAuthStore.setState({ user: makeUser(['api_policy.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('观察')).toBeInTheDocument()
    expect(screen.getByText('数据库')).toBeInTheDocument()
    expect(screen.getByText('企业版')).toBeInTheDocument()
    expect(screen.getByText('已启用')).toBeInTheDocument()
    expect(screen.getByText('1.00 MB')).toBeInTheDocument()
    expect(screen.getByText('64.0 KB')).toBeInTheDocument()
    expect(screen.getByText('32')).toBeInTheDocument()
    expect(screen.getByText('512')).toBeInTheDocument()
  })

  it('无 edit/publish 权限：不显示模式 Radio、保存与「发布到网关」', async () => {
    useAuthStore.setState({ user: makeUser(['api_policy.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('观察')
    expect(screen.queryByRole('radio')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^保\s*存$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /发布到网关/ })).not.toBeInTheDocument()
  })

  it('有 edit/publish 权限：显示模式 Radio、保存与「发布到网关」', async () => {
    useAuthStore.setState({
      user: makeUser(['api_policy.read', 'api_policy.edit', 'api_policy.publish']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('观察')
    expect(screen.getAllByRole('radio')).toHaveLength(3)
    expect(screen.getByRole('button', { name: /^保\s*存$/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /发布到网关/ })).toBeInTheDocument()
  })

  it('修改模式：选择「防护」后保存，二次确认并以 PUT 提交', async () => {
    useAuthStore.setState({
      user: makeUser(['api_policy.read', 'api_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('观察')
    fireEvent.click(screen.getByRole('radio', { name: '防护' }))
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*认\s*保\s*存/ }))
    await waitFor(() => {
      const putCalls = fetchMock.mock.calls.filter(
        ([input, init]) => String(input).includes('/api-security/policy') && init?.method === 'PUT',
      )
      expect(putCalls).toHaveLength(1)
    })
    expect(JSON.parse(String(fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT')?.[1]?.body))).toEqual({
      mode: 'PROTECT',
    })
  })
})
