import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiA2aPage from '../ApiA2aPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import { validateAgentUrl } from '../../../utils/apiA2a'

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
  { id: 'app-1', code: 'agent-hub', name: '多智能体编排中心' },
  { id: 'app-2', code: 'finance', name: '财务网关' },
]

const SAMPLE_AGENTS = [
  {
    id: 'ag-1',
    application_id: 'app-1',
    agent_name: 'billing-agent',
    agent_url: 'https://agents.example.com/billing',
    agent_version: '1.2.0',
    status: 'DISCOVERED',
    description: '账单查询智能体',
    skills: ['invoice.read', 'refund.create'],
    allowed_skills: ['invoice.read'],
    auth_schemes: ['bearer', 'oauth2'],
    first_seen_at: '2026-11-25T10:00:00Z',
    last_seen_at: '2026-11-26T09:30:00Z',
    observed_count: 42,
    created_at: '2026-11-25T10:00:00Z',
    updated_at: '2026-11-26T09:30:00Z',
  },
  {
    id: 'ag-2',
    application_id: 'app-2',
    agent_name: 'audit-agent',
    agent_url: 'https://agents.example.com/audit',
    agent_version: '2.0.1',
    status: 'APPROVED',
    description: '合规审计智能体',
    skills: ['ledger.read'],
    allowed_skills: ['ledger.read'],
    auth_schemes: ['mtls'],
    first_seen_at: '2026-11-24T08:00:00Z',
    last_seen_at: '2026-11-26T09:00:00Z',
    observed_count: 15,
    created_at: '2026-11-24T08:00:00Z',
    updated_at: '2026-11-26T09:00:00Z',
  },
]

const SAMPLE_EVENTS = [
  {
    id: 'ev-1',
    application_id: 'app-1',
    request_id: 'req-a2a-01',
    occurred_at: '2026-11-26T10:15:00Z',
    event_type: 'A2A_LOOP_KILLED',
    method: 'tasks/send',
    agent_name: 'billing-agent',
    delegation_depth: 4,
    rule_id: 'a2a.recursive_loop_detected',
    action_taken: 'KILLED',
    reason: '60s 窗口内同任务递归调用 21 次超过阈值 20',
    client_ip: '10.0.12.8',
    created_at: '2026-11-26T10:15:00Z',
  },
  {
    id: 'ev-2',
    application_id: 'app-2',
    request_id: 'req-a2a-02',
    occurred_at: '2026-11-26T10:20:00Z',
    event_type: 'A2A_LETHAL_TRIFECTA',
    method: 'message/send',
    agent_name: 'rogue-agent',
    delegation_depth: 2,
    rule_id: 'a2a.lethal_trifecta_blocked',
    action_taken: 'BLOCKED',
    reason: '会话已读取机密数据后尝试触发外部 webhook 外泄',
    client_ip: '10.0.12.9',
    created_at: '2026-11-26T10:20:00Z',
  },
]

function buildFetchMock() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/api/v1/applications')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: SAMPLE_APPS, total: SAMPLE_APPS.length, page: 1, page_size: 200 },
        }),
      )
    }
    if (url.includes('/api/v1/api-security/a2a/agents')) {
      if (method === 'POST') {
        const body = JSON.parse(String(init?.body ?? '{}'))
        return Promise.resolve(
          jsonResponse(201, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              agent: {
                id: 'ag-new',
                ...body,
                observed_count: 0,
                created_at: '2026-11-26T11:00:00Z',
                updated_at: '2026-11-26T11:00:00Z',
              },
            },
          }),
        )
      }
      if (method === 'PUT') {
        const body = JSON.parse(String(init?.body ?? '{}'))
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { agent: { ...SAMPLE_AGENTS[0], ...body } },
          }),
        )
      }
      if (method === 'DELETE') {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { deleted: true, id: 'ag-1' },
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            items: SAMPLE_AGENTS,
            total: SAMPLE_AGENTS.length,
            page: 1,
            page_size: 20,
          },
        }),
      )
    }
    if (url.includes('/api/v1/api-security/a2a/events')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: {
            items: SAMPLE_EVENTS,
            total: SAMPLE_EVENTS.length,
            page: 1,
            page_size: 20,
          },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage(permissions: string[]) {
  useAuthStore.setState({
    user: makeUser(permissions),
    csrfToken: null,
    initialized: true,
  })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <ApiA2aPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApiA2aPage（A2A 与 AgBOM 治理）', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', buildFetchMock())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('AgBOM 列表展示 Agent 名称/地址/版本/技能/认证方案/审批状态/观测计数', async () => {
    renderPage(['api_a2a.read', 'api_a2a.manage', 'applications.read'])
    expect(await screen.findByText('billing-agent')).toBeInTheDocument()
    expect(screen.getByText('https://agents.example.com/billing')).toBeInTheDocument()
    expect(screen.getByText('1.2.0')).toBeInTheDocument()
    expect(screen.getByText('invoice.read')).toBeInTheDocument()
    expect(screen.getByText('refund.create')).toBeInTheDocument()
    expect(screen.getByText('bearer')).toBeInTheDocument()
    expect(screen.getByText('oauth2')).toBeInTheDocument()
    expect(screen.getByText('自动发现待审')).toBeInTheDocument()
    expect(screen.getByText('已批准')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('多智能体编排中心')).toBeInTheDocument()
  })

  it('登记 Agent 弹窗：填写后提交 POST /api-security/a2a/agents 精确载荷', async () => {
    renderPage(['api_a2a.read', 'api_a2a.manage', 'applications.read'])
    await screen.findByText('billing-agent')

    fireEvent.click(screen.getByRole('button', { name: /登记 Agent/ }))
    const dialog = await screen.findByRole('dialog')

    fireEvent.change(within(dialog).getByPlaceholderText('如：billing-agent'), {
      target: { value: 'support-agent' },
    })
    fireEvent.change(
      within(dialog).getByPlaceholderText('如：https://agents.example.com/billing'),
      { target: { value: 'https://agents.example.com/support' } },
    )
    fireEvent.change(
      within(dialog).getByPlaceholderText('记录该 Agent 的业务职责、所属团队与审批结论'),
      { target: { value: '客服只读智能体' } },
    )
    fireEvent.click(within(dialog).getByRole('button', { name: '确认登记' }))

    await waitFor(() => {
      const postCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/api-security/a2a/agents') &&
          c[1]?.method === 'POST',
      )
      expect(postCall).toBeTruthy()
      const body = JSON.parse(String(postCall![1]?.body))
      expect(body).toEqual({
        application_id: 'app-1',
        agent_name: 'support-agent',
        agent_url: 'https://agents.example.com/support',
        agent_version: '1.0.0',
        status: 'APPROVED',
        description: '客服只读智能体',
        skills: [],
        allowed_skills: [],
        auth_schemes: ['bearer'],
      })
    })
  })

  it('审批/编辑抽屉支持采纳已发现技能并提交 PUT，删除 Popconfirm 提交 DELETE', async () => {
    renderPage(['api_a2a.read', 'api_a2a.manage', 'applications.read'])
    const billingRow = (await screen.findByText('billing-agent')).closest('tr') as HTMLElement

    fireEvent.click(within(billingRow).getByRole('button', { name: /审批\/编辑/ }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.click(within(drawer).getByRole('button', { name: '全部采纳为允许技能' }))
    fireEvent.change(within(drawer).getByPlaceholderText('记录审批依据、责任人或封禁原因'), {
      target: { value: '安全评审通过，允许账单与退款技能' },
    })
    fireEvent.click(within(drawer).getByRole('button', { name: '保存审批' }))

    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).endsWith('/api-security/a2a/agents/ag-1') &&
          c[1]?.method === 'PUT',
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String(putCall![1]?.body))
      expect(body).toEqual({
        status: 'DISCOVERED',
        description: '安全评审通过，允许账单与退款技能',
        allowed_skills: ['invoice.read', 'refund.create'],
      })
    })

    // 删除 Popconfirm
    fireEvent.click(within(billingRow).getByRole('button', { name: /删\s*除/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认删除' }))
    await waitFor(() => {
      const delCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).endsWith('/api-security/a2a/agents/ag-1') &&
          c[1]?.method === 'DELETE',
      )
      expect(delCall).toBeTruthy()
    })
  })

  it('切换到「A2A 安全事件」页签后按需拉取并展示委派/循环/三要素事件', async () => {
    renderPage(['api_a2a.read', 'applications.read'])
    await screen.findByText('billing-agent')
    // 切换前未请求事件接口
    expect(
      (fetch as Mock).mock.calls.some((c) =>
        String(c[0]).includes('/api-security/a2a/events'),
      ),
    ).toBe(false)

    fireEvent.click(screen.getByRole('tab', { name: 'A2A 安全事件（委派/循环/三要素）' }))
    expect(await screen.findByText('tasks/send')).toBeInTheDocument()
    expect(screen.getByText('message/send')).toBeInTheDocument()
    expect(screen.getByText('递归循环熔断')).toBeInTheDocument()
    expect(screen.getByText('致命三要素阻断')).toBeInTheDocument()
    expect(screen.getByText('检测到递归循环调用')).toBeInTheDocument()
    expect(screen.getByText('命中致命三要素外泄链')).toBeInTheDocument()
    expect(screen.getByText('10.0.12.8')).toBeInTheDocument()
    expect(screen.getByText('10.0.12.9')).toBeInTheDocument()
  })

  it('只读权限（仅 api_a2a.read）隐藏登记/审批/删除按钮且不触发 applications 列表请求', async () => {
    renderPage(['api_a2a.read'])
    await screen.findByText('billing-agent')
    expect(screen.queryByRole('button', { name: /登记 Agent/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /审批\/编辑/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删\s*除/ })).not.toBeInTheDocument()
    expect(
      (fetch as Mock).mock.calls.some((c) =>
        String(c[0]).includes('/api/v1/applications'),
      ),
    ).toBe(false)
  })

  it('AgBOM agent_url 校验与网关/后端对齐（允许 http(s) 与单 / 相对路径，拒绝 // 协议相对地址与内嵌凭据）', async () => {
    expect(validateAgentUrl('')).toBeNull()
    expect(validateAgentUrl('https://agents.example.com/billing')).toBeNull()
    expect(validateAgentUrl('/a2a/billing')).toBeNull()
    expect(validateAgentUrl('//evil.example.com/agent')).toContain('单 / 开头')
    expect(validateAgentUrl('https://user:pass@agents.example.com/billing')).toContain('不含内嵌凭据')
    expect(validateAgentUrl('javascript:alert(1)')).toContain('合法 http(s) URL')

    // 弹窗表单内提交 //evil.com 被拦截
    renderPage(['api_a2a.read', 'api_a2a.manage', 'applications.read'])
    await screen.findByText('billing-agent')
    fireEvent.click(screen.getByRole('button', { name: /登记 Agent/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如：billing-agent'), {
      target: { value: 'bad-agent' },
    })
    fireEvent.change(
      within(dialog).getByPlaceholderText('如：https://agents.example.com/billing'),
      { target: { value: '//evil.com/agent' } },
    )
    fireEvent.click(within(dialog).getByRole('button', { name: '确认登记' }))
    expect(
      await within(dialog).findByText(/单 \/ 开头的相对路径/),
    ).toBeInTheDocument()
  })
})
