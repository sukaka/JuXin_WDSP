import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiAuthzPage from '../ApiAuthzPage'
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

const baselines = [
  {
    id: 'b1',
    endpoint_id: 'e1',
    role: 'admin',
    method: 'GET',
    action: 'READ',
    allowed: true,
    source: 'MANUAL',
    confidence: 0.8,
    confirmed: false,
    created_by: 'sec',
    created_at: '2026-08-01T02:00:00Z',
    updated_at: '2026-08-10T02:00:00Z',
  },
  {
    id: 'b2',
    endpoint_id: 'e2',
    role: 'ops',
    method: 'POST',
    action: 'EXPORT',
    allowed: false,
    source: 'OBSERVED',
    confidence: 0.6,
    confirmed: true,
    created_by: 'sec',
    created_at: '2026-08-02T02:00:00Z',
    updated_at: '2026-08-11T02:00:00Z',
  },
]

const ownershipItems = [
  {
    id: 'o1',
    endpoint_id: 'e1',
    identity_fingerprint: 'idfp-1',
    object_type: 'order',
    object_id: '42',
    first_seen: '2026-08-01T02:00:00Z',
    last_seen: '2026-08-12T02:00:00Z',
    access_count: 7,
  },
]

const fieldPermissions = [
  {
    id: 'fp1',
    endpoint_id: 'e1',
    field_path: 'user.phone',
    direction: 'RESPONSE',
    attribute: 'SENSITIVE',
    role: null,
    tenant: null,
    created_by: 'sec',
    created_at: '2026-08-01T02:00:00Z',
    updated_at: '2026-08-10T02:00:00Z',
  },
  {
    id: 'fp2',
    endpoint_id: 'e1',
    field_path: 'user.id',
    direction: 'REQUEST',
    attribute: 'READ_ONLY',
    role: 'admin',
    tenant: null,
    created_by: 'sec',
    created_at: '2026-08-02T02:00:00Z',
    updated_at: '2026-08-11T02:00:00Z',
  },
]

const endpointOptions = {
  items: [
    { id: 'e1', endpoint_key: 'GET /v1/users/{id}' },
    { id: 'e2', endpoint_key: 'POST /v1/orders' },
  ],
  page: 1,
  page_size: 100,
  total: 2,
}

const evaluateResult = {
  endpoint_id: 'e1',
  identity: 'idfp-1',
  object_id: '42',
  verdict: 'HIGH_CONFIDENCE',
  allowed: false,
  confidence: 0.9,
  evidence: {
    own_match: false,
    object_owner_count: 1,
    identity_object_count: 0,
    identity_event_count: 0,
    endpoint_ownership_rows: 3,
  },
  comment: '该对象已有属主且访问者不是属主，判定越权（高置信）',
  evaluated_at: '2026-08-17T01:00:00Z',
}

/** 各用例可覆盖的列表内容 */
let baselineItems: Record<string, unknown>[]
let fieldPermItems: Record<string, unknown>[]
let confirmBodies: unknown[]
let createFieldPermBodies: unknown[]

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiAuthzPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiAuthzPage', () => {
  beforeEach(() => {
    baselineItems = baselines
    fieldPermItems = fieldPermissions
    confirmBodies = []
    createFieldPermBodies = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (url.includes('/api-security/authz/evaluate')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: evaluateResult }))
        }
        if (method === 'POST' && url.includes('/api-security/authz/role-baselines/b1/confirm')) {
          confirmBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { ...baselines[0], confirmed: true } }),
          )
        }
        if (method === 'POST' && url.includes('/api-security/authz/field-permissions')) {
          createFieldPermBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: fieldPermissions[0] }))
        }
        if (url.includes('/api-security/authz/role-baselines')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: baselineItems, page: 1, page_size: 20, total: baselineItems.length },
            }),
          )
        }
        if (url.includes('/api-security/authz/ownership')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: ownershipItems, page: 1, page_size: 20, total: ownershipItems.length },
            }),
          )
        }
        if (url.includes('/api-security/authz/field-permissions')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: fieldPermItems, page: 1, page_size: 20, total: fieldPermItems.length },
            }),
          )
        }
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointOptions }))
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('角色基线 Tab：渲染角色/方法/动作、来源与确认状态 Tag、分页总数', async () => {
    useAuthStore.setState({ user: makeUser(['api_authorization.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('admin')).toBeInTheDocument()
    expect(screen.getByText('ops')).toBeInTheDocument()
    expect(screen.getByText('EXPORT')).toBeInTheDocument()
    expect(screen.getByText('人工登记')).toBeInTheDocument()
    expect(screen.getByText('观测学习')).toBeInTheDocument()
    expect(screen.getByText('候选')).toBeInTheDocument()
    expect(screen.getByText('已确认')).toBeInTheDocument()
    // 接口列按 endpoint_id 映射为接口键展示
    expect(screen.getByText('POST /v1/orders')).toBeInTheDocument()
    expect(screen.getByText('共 2 条')).toBeInTheDocument()
  })

  it('无 manage 权限：不显示「新建基线」与行内编辑/确认/删除', async () => {
    useAuthStore.setState({ user: makeUser(['api_authorization.read']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('admin')
    expect(screen.queryByRole('button', { name: /新建基线/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^编\s*辑$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^确\s*认$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^删\s*除$/ })).not.toBeInTheDocument()
  })

  it('有 manage 权限：候选行点「确认」并二次确认后发起 confirm（confirmed=true）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await screen.findByText('admin')
    // b1 为候选（确认），b2 已确认（撤回）
    expect(screen.getByRole('button', { name: /^确\s*认$/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^撤\s*回$/ })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^确\s*认$/ }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(confirmBodies).toHaveLength(1))
    expect(confirmBodies[0]).toEqual({ confirmed: true })
  })

  it('对象权属 Tab：只读渲染身份指纹/对象/访问次数，无任何操作按钮', async () => {
    // 基线 Tab 保持挂载，置空避免其行内按钮干扰只读断言
    baselineItems = []
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: /对象权属/ }))
    expect(await screen.findByText('idfp-1')).toBeInTheDocument()
    expect(screen.getByText('order')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^编\s*辑$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^删\s*除$/ })).not.toBeInTheDocument()
  })

  it('字段权限 Tab：属性 Tag 文案、role/tenant 空值显示「默认」行', async () => {
    // 基线 Tab 保持挂载，置空避免角色码文本与 fp2.role 冲突
    baselineItems = []
    useAuthStore.setState({ user: makeUser(['api_authorization.read']), csrfToken: null, initialized: true })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: /字段权限/ }))
    expect(await screen.findByText('user.phone')).toBeInTheDocument()
    expect(screen.getByText('敏感')).toBeInTheDocument()
    expect(screen.getByText('只读')).toBeInTheDocument()
    // fp1 role/tenant 均空 + fp2 tenant 空 → 三个「默认」Tag；fp2 role=admin 原样展示
    expect(screen.getAllByText('默认')).toHaveLength(3)
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

  it('字段权限新建：提交方向/属性/字段路径与空 role/tenant（默认行语义）', async () => {
    // 置空基线/字段权限列表，避免下拉选项文本与表格接口列冲突
    baselineItems = []
    fieldPermItems = []
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: /字段权限/ }))
    fireEvent.click(await screen.findByRole('button', { name: /新建字段权限/ }))
    const dialog = await screen.findByRole('dialog')
    // 弹窗内三个 Select（接口/方向/属性），接口为第一个 combobox
    fireEvent.mouseDown(within(dialog).getAllByRole('combobox')[0])
    fireEvent.click(await screen.findByText('GET /v1/users/{id}'))
    fireEvent.change(within(dialog).getByLabelText('字段路径'), { target: { value: 'user.phone' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(createFieldPermBodies).toHaveLength(1))
    expect(createFieldPermBodies[0]).toEqual({
      endpoint_id: 'e1',
      field_path: 'user.phone',
      direction: 'REQUEST',
      attribute: 'READABLE',
      role: '',
      tenant: '',
    })
  })

  it('BOLA 评估：选接口+身份+对象后展示五档结论、置信度与证据计数', async () => {
    // 置空基线列表，避免下拉选项文本与表格接口列冲突
    baselineItems = []
    useAuthStore.setState({ user: makeUser(['api_authorization.read']), csrfToken: null, initialized: true })
    renderPage()
    // 评估卡片内的端点选择器（antd Select 的 placeholder 不是 input 属性，按 combobox 角色取）
    const evalCard = screen.getByText('BOLA 评估工具').closest('.ant-card') as HTMLElement
    fireEvent.mouseDown(within(evalCard).getByRole('combobox'))
    fireEvent.click(await screen.findByText('GET /v1/users/{id}'))
    fireEvent.change(screen.getByLabelText('身份指纹'), { target: { value: 'idfp-1' } })
    fireEvent.change(screen.getByLabelText('对象 ID'), { target: { value: '42' } })
    fireEvent.click(screen.getByRole('button', { name: /评\s*估/ }))
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(
        urls.some(
          (u) =>
            u.includes('/api-security/authz/evaluate') &&
            u.includes('endpoint_id=e1') &&
            u.includes('identity=idfp-1') &&
            u.includes('object_id=42'),
        ),
      ).toBe(true)
    })
    expect(await screen.findByText('高置信·越权')).toBeInTheDocument()
    expect(screen.getByText('倾向越权')).toBeInTheDocument()
    expect(screen.getByText('置信度 90%')).toBeInTheDocument()
    expect(screen.getByText(/该对象已有属主且访问者不是属主/)).toBeInTheDocument()
    expect(screen.getByText('对象属主数')).toBeInTheDocument()
    expect(screen.getByText('API 权属记录数')).toBeInTheDocument()
  })
})
