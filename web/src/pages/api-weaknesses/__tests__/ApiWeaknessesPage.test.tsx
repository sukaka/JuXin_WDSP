import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiWeaknessesPage from '../ApiWeaknessesPage'
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

/** 三个生命周期阶段的弱点样本（NEW / CONFIRMED / FIXED） */
const weaknesses: Record<string, Record<string, unknown>> = {
  w1: {
    id: 'w1',
    endpoint_id: 'e1',
    endpoint_key: 'GET /v1/users',
    weakness_code: 'UNAUTHENTICATED_SENSITIVE_API',
    weakness_name: '未认证敏感接口被调用',
    category: 'AUTHN',
    severity: 'HIGH',
    status: 'NEW',
    evidence: { hits: 3 },
    first_seen: '2026-08-01T02:00:00Z',
    last_seen: '2026-08-10T02:00:00Z',
    trigger_count: 3,
    owner: '',
    due_date: null,
    fixed_at: null,
    retested_at: null,
    created_at: '2026-08-01T02:00:00Z',
    updated_at: '2026-08-10T02:00:00Z',
  },
  w2: {
    id: 'w2',
    endpoint_id: 'e2',
    endpoint_key: 'GET /v1/orders',
    weakness_code: 'DEPRECATED_STILL_CALLED',
    weakness_name: '已下线接口仍被调用',
    category: 'LIFECYCLE',
    severity: 'MEDIUM',
    status: 'CONFIRMED',
    evidence: {},
    first_seen: '2026-08-02T02:00:00Z',
    last_seen: '2026-08-11T02:00:00Z',
    trigger_count: 9,
    owner: '',
    due_date: null,
    fixed_at: null,
    retested_at: null,
    created_at: '2026-08-02T02:00:00Z',
    updated_at: '2026-08-11T02:00:00Z',
  },
  w3: {
    id: 'w3',
    endpoint_id: 'e3',
    endpoint_key: 'GET /v1/cards',
    weakness_code: 'SENSITIVE_IN_QUERY',
    weakness_name: '敏感数据出现在 URL 查询串',
    category: 'SENSITIVE',
    severity: 'HIGH',
    status: 'FIXED',
    evidence: {},
    first_seen: '2026-08-03T02:00:00Z',
    last_seen: '2026-08-12T02:00:00Z',
    trigger_count: 5,
    owner: 'zhangsan',
    due_date: '2026-08-20T00:00:00Z',
    fixed_at: '2026-08-13T02:00:00Z',
    retested_at: null,
    created_at: '2026-08-03T02:00:00Z',
    updated_at: '2026-08-13T02:00:00Z',
  },
  w4: {
    id: 'w4',
    endpoint_id: 'e4',
    endpoint_key: 'GET /v1/customers/{id}',
    weakness_code: 'SENSITIVE_RESPONSE_UNMASKED',
    weakness_name: '响应敏感信息未观察到成功脱敏',
    category: 'SENSITIVE',
    severity: 'MEDIUM',
    status: 'NEW',
    evidence: {
      rule: 'SENSITIVE_RESPONSE_UNMASKED',
      endpoint_key: 'GET /v1/customers/{id}',
      sample_count: 3,
      window_hours: 24,
      first_seen: '2026-08-13T02:00:00Z',
      last_seen: '2026-08-14T02:00:00Z',
    },
    first_seen: '2026-08-13T02:00:00Z',
    last_seen: '2026-08-14T02:00:00Z',
    trigger_count: 1,
    owner: '',
    due_date: null,
    fixed_at: null,
    retested_at: null,
    created_at: '2026-08-13T02:00:00Z',
    updated_at: '2026-08-14T02:00:00Z',
  },
}

const actionsById: Record<string, Record<string, unknown>[]> = {
  w1: [
    {
      id: 'a1',
      weakness_id: 'w1',
      action: 'DERIVED',
      actor: 'system',
      note: '',
      created_at: '2026-08-01T02:00:00Z',
    },
  ],
  w2: [],
  w3: [],
}

/** 当前列表返回的弱点 ID 集合（各用例按需设置） */
let listIds: string[]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiWeaknessesPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiWeaknessesPage', () => {
  let assignBodies: unknown[]
  let retestBodies: unknown[]

  beforeEach(() => {
    assignBodies = []
    retestBodies = []
    listIds = ['w1']
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (method === 'POST' && url.includes('/assign')) {
          assignBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                weakness: {
                  ...weaknesses.w2,
                  status: 'TO_FIX',
                  owner: 'zhangsan',
                },
              },
            }),
          )
        }
        if (method === 'POST' && url.includes('/retest')) {
          retestBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { weakness: { ...weaknesses.w3, status: 'ARCHIVED' } },
            }),
          )
        }
        const detailMatch = url.match(/\/api-security\/weaknesses\/(w\d)/)
        if (method === 'GET' && detailMatch) {
          const id = detailMatch[1]
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                weakness: weaknesses[id],
                actions: actionsById[id] ?? [],
              },
            }),
          )
        }
        if (method === 'GET' && url.includes('/api-security/weaknesses')) {
          const items = listIds.map((id) => weaknesses[id])
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items, page: 1, page_size: 20, total: items.length },
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

  it('详情抽屉：操作按钮按状态机可用性禁用（NEW 仅可确认/忽略）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_weakness.read', 'api_weakness.handle']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('未认证敏感接口被调用')
    expect(within(drawer).getByText('派生证据')).toBeInTheDocument()
    expect(within(drawer).queryByText('派生证据（evidence）')).not.toBeInTheDocument()
    expect(within(drawer).getByText(/系统 ·/)).toBeInTheDocument()
    expect(within(drawer).queryByText(/^system ·/)).not.toBeInTheDocument()

    expect(
      within(drawer).getByRole('button', { name: /确\s*认/ }),
    ).toBeEnabled()
    expect(
      within(drawer).getByRole('button', { name: /忽\s*略/ }),
    ).toBeEnabled()
    expect(
      within(drawer).getByRole('button', { name: /指\s*派/ }),
    ).toBeDisabled()
    expect(
      within(drawer).getByRole('button', { name: '整改完成' }),
    ).toBeDisabled()
    expect(
      within(drawer).getByRole('button', { name: /复\s*测/ }),
    ).toBeDisabled()
    expect(
      within(drawer).getByRole('button', { name: /归\s*档/ }),
    ).toBeDisabled()
  })

  it('指派：提交 owner，CONFIRMED → TO_FIX', async () => {
    listIds = ['w2']
    useAuthStore.setState({
      user: makeUser(['api_weakness.read', 'api_weakness.handle']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('已下线接口仍被调用')

    fireEvent.click(within(drawer).getByRole('button', { name: /指\s*派/ }))
    await screen.findByText('指派整改')
    fireEvent.change(screen.getByLabelText('整改负责人'), {
      target: { value: 'zhangsan' },
    })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(assignBodies).toHaveLength(1))
    expect(assignBodies[0]).toEqual({ owner: 'zhangsan' })
  })

  it('复测：提交 PASS 并展示复测结果反馈', async () => {
    listIds = ['w3']
    useAuthStore.setState({
      user: makeUser(['api_weakness.read', 'api_weakness.handle']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('敏感数据出现在 URL 查询串')

    fireEvent.click(within(drawer).getByRole('button', { name: /复\s*测/ }))
    await screen.findByText('复测结果')
    // 默认选中「通过（PASS）」，直接提交
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(retestBodies).toHaveLength(1))
    expect(retestBodies[0]).toEqual({ result: 'PASS' })
    // 复测结果即时反馈（PASS → 归档关闭）
    expect(
      await screen.findByText('复测通过，弱点已归档关闭'),
    ).toBeInTheDocument()
  })

  it('按服务端字段展示响应脱敏观测弱点的列表与详情', async () => {
    listIds = ['w4']
    useAuthStore.setState({
      user: makeUser(['api_weakness.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    expect(
      screen.getByText(
        /响应涉敏未观察到成功脱敏仅是观测信号，不代表 TLS 未加密，也不代表漏洞已证实/,
      ),
    ).toBeInTheDocument()
    const row = await screen.findByRole('row', {
      name: /SENSITIVE_RESPONSE_UNMASKED/,
    })
    expect(
      within(row).getByText('响应敏感信息未观察到成功脱敏'),
    ).toBeInTheDocument()
    expect(within(row).getByText('敏感数据')).toBeInTheDocument()
    expect(within(row).getByText('中')).toBeInTheDocument()

    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('SENSITIVE_RESPONSE_UNMASKED')
    expect(
      within(drawer).getByText('弱点详情：响应敏感信息未观察到成功脱敏'),
    ).toBeInTheDocument()
    expect(
      within(drawer).getByText('GET /v1/customers/{id}'),
    ).toBeInTheDocument()
    expect(within(drawer).getByText('敏感数据')).toBeInTheDocument()
    expect(within(drawer).getByText('中')).toBeInTheDocument()
    expect(
      JSON.parse(drawer.querySelector('pre')?.textContent ?? '{}'),
    ).toEqual(weaknesses.w4.evidence)
  })

  it('无 api_weakness.handle 权限：不显示处置按钮', async () => {
    useAuthStore.setState({
      user: makeUser(['api_weakness.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('未认证敏感接口被调用')
    expect(within(drawer).getByText('派生证据')).toBeInTheDocument()
    expect(within(drawer).queryByText('派生证据（evidence）')).not.toBeInTheDocument()
    expect(within(drawer).getByText(/系统 ·/)).toBeInTheDocument()
    expect(within(drawer).queryByText(/^system ·/)).not.toBeInTheDocument()

    expect(
      within(drawer).queryByRole('button', { name: /确\s*认/ }),
    ).not.toBeInTheDocument()
    expect(
      within(drawer).queryByRole('button', { name: /指\s*派/ }),
    ).not.toBeInTheDocument()
    expect(
      within(drawer).queryByRole('button', { name: /复\s*测/ }),
    ).not.toBeInTheDocument()
  })

  it('支持对象授权分类筛选', async () => {
    useAuthStore.setState({
      user: makeUser(['api_weakness.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByRole('button', { name: /详\s*情/ })
    fireEvent.mouseDown(screen.getAllByRole('combobox')[2])
    fireEvent.click(await screen.findByText('对象授权'))
    await waitFor(() => {
      expect(
        vi
          .mocked(fetch)
          .mock.calls.some(([input]) =>
            String(input).includes('category=AUTHZ'),
          ),
      ).toBe(true)
    })
  })
})
