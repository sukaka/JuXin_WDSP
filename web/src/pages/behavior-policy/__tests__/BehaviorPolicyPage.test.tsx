import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BehaviorPolicyPage from '../BehaviorPolicyPage'
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

const POLICY = {
  id: 'bp-1',
  scope: 'GLOBAL',
  enabled: true,
  mode: 'OBSERVE',
  version: 3,
  uri_enum_unique_threshold: 30,
  uri_enum_new_ratio_threshold: 0.6,
  not_found_ratio_threshold: 0.5,
  not_found_min_requests: 20,
  method_enum_threshold: 4,
  param_mutation_threshold: 10,
  auth_fail_threshold: 8,
  low_slow_sensitive_min_hits: 3,
  sensitive_paths: ['/admin'],
  scores: {
    URI_ENUMERATION: 10,
    NOT_FOUND_ENUMERATION: 8,
    SENSITIVE_PATH_PROBE: 15,
    METHOD_ENUMERATION: 5,
    PARAMETER_MUTATION: 12,
    AUTH_FAIL_PROBE: 10,
    LOW_SLOW_RECON: 20,
  },
  whitelist_ips: ['10.0.0.1'],
  whitelist_uas: [],
  updated_by: 'admin',
  updated_at: '2026-08-31T10:00:00Z',
}

function mockFetch() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/security/behavior-policy')) {
      if (init?.method === 'PUT') return ok({ policy: { ...POLICY, version: POLICY.version + 1 } })
      return ok({ policy: POLICY })
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <BehaviorPolicyPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('BehaviorPolicyPage', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GET 回填：阈值、分值、敏感路径与开关按策略渲染', async () => {
    useAuthStore.setState({
      user: makeUser(['behavior_policy.read', 'behavior_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    // 等 GET 回填生效（useEffect setFieldsValue 异步刷新）
    const threshold = (await screen.findByLabelText('URI枚举阈值（唯一URI数）')) as HTMLInputElement
    await waitFor(() => expect(threshold.value).toBe('30'))
    // InputNumber step=0.05 时显示值按步长精度格式化为 0.60
    expect((screen.getByLabelText('新URI比例（0-1）') as HTMLInputElement).value).toBe('0.60')
    expect((screen.getByLabelText('404最小请求数') as HTMLInputElement).value).toBe('20')
    expect((screen.getByLabelText('URI枚举分值') as HTMLInputElement).value).toBe('10')
    expect((screen.getByLabelText('低慢侦察分值') as HTMLInputElement).value).toBe('20')
    expect(screen.getByRole('switch')).toBeChecked()
    // 敏感路径与白名单 tags 回填
    expect(screen.getByText('/admin')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
    // 模式禁用态 + 后续阶段说明
    expect(screen.getByText('阻断动作将在后续阶段开放')).toBeInTheDocument()
    // 页脚版本信息
    expect(screen.getByText(/版本 v3/)).toBeInTheDocument()
  }, 15000)

  it('无 behavior_policy.edit 权限时不展示保存按钮且表单禁用', async () => {
    useAuthStore.setState({
      user: makeUser(['behavior_policy.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    await screen.findByLabelText('URI枚举阈值（唯一URI数）')
    expect(screen.queryByRole('button', { name: '保存策略' })).not.toBeInTheDocument()
    expect(screen.getByRole('switch')).toBeDisabled()
  }, 15000)

  it('PUT 成功：全量提交携带 version 并提示保存成功', async () => {
    useAuthStore.setState({
      user: makeUser(['behavior_policy.read', 'behavior_policy.edit']),
      csrfToken: null,
      initialized: true,
    })
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    // 等 GET 回填生效后再提交（未回填时必填校验会拦截 PUT）
    const threshold = (await screen.findByLabelText('URI枚举阈值（唯一URI数）')) as HTMLInputElement
    await waitFor(() => expect(threshold.value).toBe('30'))
    fireEvent.click(screen.getByRole('button', { name: '保存策略' }))

    expect(await screen.findByText('行为策略已保存')).toBeInTheDocument()
    const putCall = fetchMock.mock.calls.find(
      (c) => (c[1] as RequestInit | undefined)?.method === 'PUT',
    )
    expect(putCall).toBeDefined()
    const body = JSON.parse(String((putCall![1] as RequestInit).body)) as Record<string, unknown>
    expect(body.version).toBe(3)
    expect(body.scope).toBe('GLOBAL')
    expect(body.mode).toBe('OBSERVE')
    expect(body.enabled).toBe(true)
    expect(body.uri_enum_unique_threshold).toBe(30)
    expect(body.sensitive_paths).toEqual(['/admin'])
    expect(body.scores).toMatchObject({ URI_ENUMERATION: 10, LOW_SLOW_RECON: 20 })
    expect(body.whitelist_ips).toEqual(['10.0.0.1'])
  }, 15000)
})
