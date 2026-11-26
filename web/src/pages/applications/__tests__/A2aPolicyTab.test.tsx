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
import { API_A2A_LIMITS } from '../../../api/apiA2a'
import {
  mapA2aFieldErrorPath,
  validateA2aPathPrefixes,
  validateA2aPatterns,
  validateAllowedCallerAgents,
} from '../../../utils/apiA2a'
import A2aPolicyTab from '../detail/A2aPolicyTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const APP_ID = 'app-a2a-1'
const APP_CODE = 'agent-hub'

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
    card_discovery_enabled: true,
    a2a_path_prefixes: ['/a2a', '/.well-known/agent.json', '/.well-known/agent-card.json'],
    allowed_caller_agents: null,
    max_delegation_depth: 3,
    enforce_scope_attenuation: true,
    loop_window_seconds: 60,
    max_calls_per_task_window: 20,
    lethal_trifecta_enabled: true,
    confidential_read_patterns: ['/api/v1/secrets', 'read_secret'],
    external_egress_patterns: ['send_email', 'webhook'],
    updated_by: '',
    created_at: '',
    updated_at: '',
  },
  summary: { state: 'NOT_CONFIGURED', draft_version: 0, published_version: 0 },
}

const DRAFT_PENDING = {
  policy: {
    id: 'a2a-pol-1',
    schema_version: 1,
    application_id: APP_ID,
    mode: 'PROTECT',
    version: 3,
    card_discovery_enabled: true,
    a2a_path_prefixes: ['/a2a', '/.well-known/agent-card.json'],
    allowed_caller_agents: ['orchestrator-agent', 'billing-agent'],
    max_delegation_depth: 4,
    enforce_scope_attenuation: true,
    loop_window_seconds: 120,
    max_calls_per_task_window: 30,
    lethal_trifecta_enabled: true,
    confidential_read_patterns: ['/api/v1/secrets', 'query_pii'],
    external_egress_patterns: ['send_email', 'upload_external'],
    updated_by: 'secops',
    created_at: '2026-11-20T00:00:00Z',
    updated_at: '2026-11-26T09:00:00Z',
  },
  summary: { state: 'DRAFT_PENDING', draft_version: 3, published_version: 1 },
}

function mockFetch(getData: unknown = UNCONFIGURED, putStatus = 200) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes(`/applications/${APP_ID}/a2a-policy`)) {
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
                  field: 'a2a_path_prefixes[0]',
                  message: '路径前缀必须以 / 开头',
                },
              ],
            }),
          )
        }
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { policy: { ...DRAFT_PENDING.policy, version: 4 } },
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
        <A2aPolicyTab appId={APP_ID} appCode={APP_CODE} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('A2aPolicyTab（应用级 A2A 安全治理策略）', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('未配置空态：展示默认 OFF 模式、状态摘要与前后端对齐上限常量', async () => {
    useAuthStore.setState({
      user: makeUser(['api_a2a.read', 'api_a2a.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('未配置')).toBeInTheDocument()
    expect(
      screen.getByText('尚未配置 A2A 安全治理策略，当前维持默认透传行为'),
    ).toBeInTheDocument()
    expect(screen.getByText('关闭（不启用 A2A 安全检测）')).toBeInTheDocument()
    expect(screen.getByText(APP_CODE)).toBeInTheDocument()

    expect(API_A2A_LIMITS.maxPathPrefixes).toBe(32)
    expect(API_A2A_LIMITS.maxPathLen).toBe(256)
    expect(API_A2A_LIMITS.maxAllowedAgents).toBe(64)
    expect(API_A2A_LIMITS.maxAgentNameLen).toBe(128)
    expect(API_A2A_LIMITS.minDelegationDepth).toBe(1)
    expect(API_A2A_LIMITS.maxDelegationDepth).toBe(10)
    expect(API_A2A_LIMITS.minLoopWindow).toBe(5)
    expect(API_A2A_LIMITS.maxLoopWindow).toBe(3600)
    expect(API_A2A_LIMITS.minMaxCalls).toBe(1)
    expect(API_A2A_LIMITS.maxMaxCalls).toBe(10000)
    expect(API_A2A_LIMITS.maxPatterns).toBe(64)
    expect(API_A2A_LIMITS.maxPatternLen).toBe(256)
  })

  it('草稿待发布态：按精确 DTO 契约提交 PUT（含 expected_version 与 reason）', async () => {
    vi.stubGlobal('fetch', mockFetch(DRAFT_PENDING))
    useAuthStore.setState({
      user: makeUser(['api_a2a.read', 'api_a2a.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('草稿待发布')).toBeInTheDocument()
    expect(screen.getByText('v3')).toBeInTheDocument()
    expect(screen.getByText('v1')).toBeInTheDocument()

    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：为多智能体编排接口开启 RFC 8693 委派限制与循环熔断',
      ),
      { target: { value: '开启多智能体委派衰减与循环熔断防护' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('A2A 策略草稿已保存；发布并获节点回执后才会生效'),
    ).toBeInTheDocument()

    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).endsWith(`/applications/${APP_ID}/a2a-policy`) &&
          c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body))
      expect(body).toEqual({
        mode: 'PROTECT',
        expected_version: 3,
        card_discovery_enabled: true,
        a2a_path_prefixes: ['/a2a', '/.well-known/agent-card.json'],
        allowed_caller_agents: ['orchestrator-agent', 'billing-agent'],
        max_delegation_depth: 4,
        enforce_scope_attenuation: true,
        loop_window_seconds: 120,
        max_calls_per_task_window: 30,
        lethal_trifecta_enabled: true,
        confidential_read_patterns: ['/api/v1/secrets', 'query_pii'],
        external_egress_patterns: ['send_email', 'upload_external'],
        reason: '开启多智能体委派衰减与循环熔断防护',
      })
    })
  })

  it('409 版本冲突提示刷新重试，400 字段级数组路径错误映射回表单', async () => {
    vi.stubGlobal('fetch', mockFetch(UNCONFIGURED, 409))
    useAuthStore.setState({
      user: makeUser(['api_a2a.read', 'api_a2a.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    await screen.findByText('未配置')

    fireEvent.change(
      screen.getByPlaceholderText(
        '说明本次变更原因，如：为多智能体编排接口开启 RFC 8693 委派限制与循环熔断',
      ),
      { target: { value: '冲突验证' } },
    )
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(
      await screen.findByText('策略已被其他人修改，请刷新后重试'),
    ).toBeInTheDocument()

    vi.stubGlobal('fetch', mockFetch(UNCONFIGURED, 400))
    fireEvent.click(screen.getByRole('button', { name: '保存草稿' }))
    expect(await screen.findByText('路径前缀必须以 / 开头')).toBeInTheDocument()
  })

  it('只读权限（仅 api_a2a.read）隐藏保存按钮与变更理由', async () => {
    useAuthStore.setState({
      user: makeUser(['api_a2a.read']),
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
          jsonResponse(403, { code: 'FORBIDDEN', message: '无权限', data: null }),
        ),
      ),
    )
    useAuthStore.setState({
      user: makeUser(['api_a2a.read']),
      csrfToken: null,
      initialized: true,
    })
    renderTab()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('校验器与字段错误路径映射对齐后端边界约束', () => {
    expect(validateA2aPathPrefixes(['/a2a', '/.well-known/agent.json'])).toBeNull()
    expect(validateA2aPathPrefixes(['a2a'])).toContain('必须以 / 开头')
    expect(validateA2aPathPrefixes(['/a2a?x=1'])).toContain('不能包含查询参数')
    expect(
      validateAllowedCallerAgents(['agent-1', 'orchestrator']),
    ).toBeNull()
    expect(
      validateAllowedCallerAgents(['a'.repeat(129)]),
    ).toContain('不能超过 128 字符')
    expect(
      validateA2aPatterns(['/api/v1/secrets', 'read_secret'], '机密读取模式'),
    ).toBeNull()
    expect(
      validateA2aPatterns(['bad\npattern'], '外部外传模式'),
    ).toContain('不能包含换行或控制字符')
    expect(mapA2aFieldErrorPath('a2a_path_prefixes[0]')).toEqual([
      'a2a_path_prefixes',
    ])
    expect(mapA2aFieldErrorPath('confidential_read_patterns[2]')).toEqual([
      'confidential_read_patterns',
    ])
    expect(mapA2aFieldErrorPath('max_delegation_depth')).toEqual([
      'max_delegation_depth',
    ])
  })
})
