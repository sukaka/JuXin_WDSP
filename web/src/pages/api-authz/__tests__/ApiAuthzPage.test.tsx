import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiAuthzPage from '../ApiAuthzPage'
import { validateReauthorizationWindow } from '../reauthorization'
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

const applicationOptions = {
  items: [{ id: 'app1', code: 'SHOP', name: '商城应用' }],
  page: 1,
  page_size: 100,
  total: 1,
}

const relationCandidates = [
  {
    id: 'candidate1',
    application_id: 'app1',
    endpoint_id: 'e1',
    object_type: 'order',
    object_ref: 'objref:01abcdef0123456789',
    principal_id: 'principal:01abcdef0123456789',
    tenant_id: 'tenant-a',
    source: 'OBSERVED_ACCESS',
    status: 'PENDING',
    source_count: 1,
    observation_count: 5,
    confidence_inputs: {},
    first_seen: '2026-09-08T01:00:00Z',
    last_seen: '2026-09-09T01:00:00Z',
    created_at: '2026-09-08T01:00:00Z',
    updated_at: '2026-09-09T01:00:00Z',
  },
]

const relationFixtures = [
  {
    id: 'rel-confirmed',
    application_id: 'app1',
    object_type: 'order',
    object_ref: 'objref:confirmed-0001',
    principal_id: 'principal:confirmed-0001',
    tenant_id: 'tenant-a',
    relation: 'OWNER',
    source: 'MANUAL',
    status: 'CONFIRMED',
    valid_from: '2026-09-01T02:00:00Z',
    valid_until: null,
    confirmed_by: 'sec',
    confirmed_at: '2026-09-01T02:00:00Z',
    reason: '初始登记',
    created_at: '2026-09-01T02:00:00Z',
    updated_at: '2026-09-01T02:00:00Z',
  },
  {
    id: 'rel-revoked',
    application_id: 'app1',
    object_type: 'order',
    object_ref: 'objref:revoked-0001',
    principal_id: 'principal:revoked-0001',
    tenant_id: 'tenant-a',
    relation: 'OWNER',
    source: 'MANUAL',
    status: 'REVOKED',
    valid_from: '2026-08-01T02:00:00Z',
    valid_until: null,
    confirmed_by: 'sec',
    confirmed_at: '2026-08-01T02:00:00Z',
    reason: '离职撤销',
    created_at: '2026-08-01T02:00:00Z',
    updated_at: '2026-09-05T02:00:00Z',
  },
  {
    id: 'rel-expired',
    application_id: 'app1',
    object_type: 'invoice',
    object_ref: 'objref:expired-0001',
    principal_id: 'principal:expired-0001',
    tenant_id: null,
    relation: 'OWNER',
    source: 'IMPORT',
    status: 'EXPIRED',
    valid_from: '2026-07-01T02:00:00Z',
    valid_until: '2026-08-01T02:00:00Z',
    confirmed_by: 'sec',
    confirmed_at: '2026-07-01T02:00:00Z',
    reason: '临时授权到期',
    created_at: '2026-07-01T02:00:00Z',
    updated_at: '2026-08-01T02:00:00Z',
  },
  {
    id: 'rel-shared',
    application_id: 'app1',
    object_type: 'order',
    object_ref: 'objref:shared-source-0001',
    principal_id: 'principal:shared-recipient-0001',
    tenant_id: 'tenant-a',
    relation: 'SHARED_WITH',
    source: 'MANUAL',
    status: 'CONFIRMED',
    valid_from: '2026-09-02T02:00:00Z',
    valid_until: '2026-12-01T02:00:00Z',
    confirmed_by: 'sec',
    confirmed_at: '2026-09-02T02:00:00Z',
    reason: '共享审批',
    created_at: '2026-09-02T02:00:00Z',
    updated_at: '2026-09-02T02:00:00Z',
  },
]

/** 各用例可覆盖的列表内容 */
let baselineItems: Record<string, unknown>[]
let fieldPermItems: Record<string, unknown>[]
let relationItems: Record<string, unknown>[]
let confirmBodies: unknown[]
let relationConfirmBodies: unknown[]
let createFieldPermBodies: unknown[]
let createRelationRequests: { url: string; method: string; body: unknown }[]
let revokeRequests: { url: string; method: string; body: unknown }[]
let reauthRequests: { url: string; method: string; body: unknown }[]
let createRelationConflict: boolean

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
    relationItems = []
    confirmBodies = []
    relationConfirmBodies = []
    createFieldPermBodies = []
    createRelationRequests = []
    revokeRequests = []
    reauthRequests = []
    createRelationConflict = false
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (url.includes('/api-security/authz/evaluate')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: evaluateResult }))
        }
        if (url.includes('/applications?')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: applicationOptions }))
        }
        if (url.includes('/api-security/authz/coverage')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: {
            application_id: 'app1', pending_candidates: 1, confirmed_relations: 0, decisions: 0,
            unknown_decisions: 0, observe_violations: 0, verified_identity_rate: 0.8,
            model_coverage_rate: 0.6, confirmed_relation_rate: 0.4, unknown_rate: 0.1,
          } }))
        }
        if (method === 'POST' && /\/api-security\/authz\/relations\/candidates\/[^/]+\/confirm/.test(url)) {
          relationConfirmBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: relationFixtures[0] }))
        }
        if (url.includes('/api-security/authz/relations/candidates')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: {
            items: relationCandidates, page: 1, page_size: 20, total: 1,
          } }))
        }
        if (method === 'POST' && /\/api-security\/authz\/relations\/[^/]+\/reauthorize/.test(url)) {
          reauthRequests.push({ url, method, body: JSON.parse(String(init?.body)) })
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { ...relationFixtures[1], status: 'CONFIRMED' } }))
        }
        if (method === 'POST' && /\/api-security\/authz\/relations\/[^/]+\/revoke/.test(url)) {
          revokeRequests.push({ url, method, body: JSON.parse(String(init?.body)) })
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { ...relationFixtures[3], status: 'REVOKED' } }))
        }
        if (method === 'POST' && /\/api-security\/authz\/relations$/.test(url)) {
          const body = JSON.parse(String(init?.body)) as unknown
          createRelationRequests.push({ url, method, body })
          if (createRelationConflict) {
            return Promise.resolve(jsonResponse(409, { code: 'RESOURCE_CONFLICT', message: '对象关系已存在', data: null }))
          }
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: relationFixtures[3] }))
        }
        if (url.includes('/api-security/authz/relations')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: {
            items: relationItems, page: 1, page_size: 20, total: relationItems.length,
          } }))
        }
        if (url.includes('/api-security/authz/decisions')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: {
            items: [], page: 1, page_size: 20, total: 0,
          } }))
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
    useAuthStore.setState({ user: makeUser(['api_authorization.read', 'api_asset.read']), csrfToken: null, initialized: true })
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

  it('对象授权 Tab：按应用展示覆盖率和候选，read 权限不能确认关系', async () => {
    useAuthStore.setState({ user: makeUser(['api_authorization.read', 'applications.read']), csrfToken: null, initialized: true })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: /^对象授权$/ }))
    const applicationSelect = (await screen.findByText('选择应用后查看对象授权')).closest('.ant-select') as HTMLElement
    fireEvent.mouseDown(within(applicationSelect).getByRole('combobox'))
    fireEvent.click(await screen.findByText('商城应用（SHOP）'))
    expect(await screen.findByText('VERIFIED 身份占比')).toBeInTheDocument()
    expect(screen.getByText('对象模型覆盖')).toBeInTheDocument()
    expect(screen.getByText('已确认关系占比')).toBeInTheDocument()
    expect(screen.getByText('UNKNOWN 率')).toBeInTheDocument()
    expect(await screen.findByText('order')).toBeInTheDocument()
    expect(screen.getByText('tenant-a')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^确\s*认$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^拒\s*绝$/ })).not.toBeInTheDocument()
  }, 60_000)

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
      user: makeUser(['api_authorization.read', 'api_authorization.manage', 'api_asset.read']),
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
    useAuthStore.setState({ user: makeUser(['api_authorization.read', 'api_asset.read']), csrfToken: null, initialized: true })
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

  /** 进入「对象授权」页签、选择商城应用并切换到「对象关系」子页签 */
  async function openRelationsTab() {
    fireEvent.click(screen.getByRole('tab', { name: /^对象授权$/ }))
    const applicationSelect = (await screen.findByText('选择应用后查看对象授权')).closest('.ant-select') as HTMLElement
    fireEvent.mouseDown(within(applicationSelect).getByRole('combobox'))
    fireEvent.click(await screen.findByText('商城应用（SHOP）'))
    fireEvent.click(await screen.findByRole('tab', { name: /^对象关系/ }))
  }

  it('对象关系 Tab：按 record.relation 展示所有者/共享接收人，不隐藏历史状态', async () => {
    relationItems = relationFixtures
    useAuthStore.setState({ user: makeUser(['api_authorization.read', 'applications.read']), csrfToken: null, initialized: true })
    renderPage()
    await openRelationsTab()
    expect(await screen.findByText('已撤销')).toBeInTheDocument()
    expect(screen.getByText('已过期')).toBeInTheDocument()
    expect(screen.getAllByText('所有者')).toHaveLength(3)
    expect(screen.getByText('共享接收人')).toBeInTheDocument()
    expect(screen.getByText('objref:confirmed-0001')).toBeInTheDocument()
    expect(screen.getByText('objref:revoked-0001')).toBeInTheDocument()
    expect(screen.getByText('objref:expired-0001')).toBeInTheDocument()
    expect(screen.getByText('objref:shared-source-0001')).toBeInTheDocument()
  })

  it('无 relation_manage 权限：共享登记、撤销与重新授权入口均不展示', async () => {
    relationItems = relationFixtures
    useAuthStore.setState({ user: makeUser(['api_authorization.read', 'applications.read']), csrfToken: null, initialized: true })
    renderPage()
    await openRelationsTab()
    await screen.findByText('共享接收人')
    expect(screen.queryByRole('button', { name: '手工登记关系' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '撤销' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重新授权' })).not.toBeInTheDocument()
  })

  it('重新授权入口：CONFIRMED 行不展示，REVOKED/EXPIRED 行展示', async () => {
    relationItems = relationFixtures
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.relation_manage', 'applications.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await openRelationsTab()
    await screen.findByText('已撤销')
    expect(screen.getAllByRole('button', { name: '重新授权' })).toHaveLength(2)
  }, 60_000)

  it('重新授权：原因+生效/失效时间 POST 到 reauthorize，成功提示、关弹窗并刷新关系/覆盖率', async () => {
    relationItems = relationFixtures
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.relation_manage', 'applications.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await openRelationsTab()
    const buttons = await screen.findAllByRole('button', { name: '重新授权' })
    // 行顺序与 relationFixtures 一致：rel-revoked 为第一条可重新授权记录
    fireEvent.click(buttons[0])
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('授权原因'), { target: { value: '  业务恢复需要  ' } })
    const validFrom = within(dialog).getByLabelText('生效时间')
    fireEvent.change(validFrom, { target: { value: '2026-09-10 10:00:00' } })
    fireEvent.keyDown(validFrom, { key: 'Enter', code: 'Enter' })
    const validUntil = within(dialog).getByLabelText(/^失效时间/)
    fireEvent.change(validUntil, { target: { value: '2026-09-20 10:00:00' } })
    fireEvent.keyDown(validUntil, { key: 'Enter', code: 'Enter' })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认重新授权' }))
    await waitFor(() => expect(reauthRequests).toHaveLength(1))
    const req = reauthRequests[0]
    expect(req.method).toBe('POST')
    expect(req.url).toContain('/api/v1/api-security/authz/relations/rel-revoked/reauthorize')
    expect(req.body).toEqual({
      reason: '业务恢复需要',
      valid_from: new Date(2026, 8, 10, 10, 0, 0).toISOString(),
      valid_until: new Date(2026, 8, 20, 10, 0, 0).toISOString(),
    })
    expect(await screen.findByText('关系已重新授权')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    // 成功后关系与覆盖率查询被刷新（重新发起 GET）
    await waitFor(() => {
      const gets = (fetch as Mock).mock.calls.filter((c) => !(c[1]?.method) || c[1]?.method === 'GET').map((c) => String(c[0]))
      expect(gets.filter((u) => u.includes('/api-security/authz/coverage')).length).toBeGreaterThanOrEqual(2)
      expect(gets.filter((u) => u.includes('/api-security/authz/relations?')).length).toBeGreaterThanOrEqual(2)
    })
  }, 70_000)

  it('普通访问候选只能确认为 OWNER，不提供 SHARED_WITH 确认入口', async () => {
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.relation_manage', 'applications.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: /^对象授权$/ }))
    const applicationSelect = (await screen.findByText('选择应用后查看对象授权')).closest('.ant-select') as HTMLElement
    fireEvent.mouseDown(within(applicationSelect).getByRole('combobox'))
    fireEvent.click(await screen.findByText('商城应用（SHOP）'))
    fireEvent.click(await screen.findByRole('button', { name: /^确\s*认$/ }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByDisplayValue('OWNER')).toBeDisabled()
    expect(within(dialog).queryByText(/SHARED_WITH/)).not.toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText('审核原因'), { target: { value: '  候选审批通过  ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认关系' }))
    await waitFor(() => expect(relationConfirmBodies).toHaveLength(1))
    expect(relationConfirmBodies[0]).toEqual({ relation: 'OWNER', reason: '候选审批通过' })
  }, 60_000)

  it('共享创建：按共享源→接收人方向提交真实 HMAC 引用、有效期与审计原因', async () => {
    relationItems = [relationFixtures[3]]
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.relation_manage', 'applications.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await openRelationsTab()
    fireEvent.click(await screen.findByRole('button', { name: '手工登记关系' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/共享方向：object_ref 是被共享的对象（共享源），principal_id 是共享接收人/)).toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText('对象类型'), { target: { value: ' order ' } })
    fireEvent.change(within(dialog).getByLabelText('共享源对象 HMAC 引用（object_ref）'), { target: { value: ' objref:shared-source-new ' } })
    fireEvent.change(within(dialog).getByLabelText('共享接收人（principal_id）'), { target: { value: ' principal:shared-recipient-new ' } })
    const validFrom = within(dialog).getByLabelText('生效时间（可选，默认立即）')
    fireEvent.change(validFrom, { target: { value: '2026-11-20 10:00:00' } })
    fireEvent.keyDown(validFrom, { key: 'Enter', code: 'Enter' })
    const validUntil = within(dialog).getByLabelText('失效时间（可选）')
    fireEvent.change(validUntil, { target: { value: '2026-11-21 10:00:00' } })
    fireEvent.keyDown(validUntil, { key: 'Enter', code: 'Enter' })
    fireEvent.change(within(dialog).getByLabelText('证据引用（可选）'), { target: { value: ' ticket-42 ' } })
    fireEvent.change(within(dialog).getByLabelText('审计原因'), { target: { value: '  共享审批 TICKET-42  ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认登记' }))
    await waitFor(() => expect(createRelationRequests).toHaveLength(1))
    expect(createRelationRequests[0].url).toBe('/api/v1/api-security/authz/relations')
    expect(createRelationRequests[0].body).toEqual({
      application_id: 'app1',
      object_type: 'order',
      object_ref: 'objref:shared-source-new',
      principal_id: 'principal:shared-recipient-new',
      relation: 'SHARED_WITH',
      source: 'MANUAL',
      valid_from: new Date(2026, 10, 20, 10, 0, 0).toISOString(),
      valid_until: new Date(2026, 10, 21, 10, 0, 0).toISOString(),
      evidence_ref: 'ticket-42',
      reason: '共享审批 TICKET-42',
    })
    expect(await screen.findByText('共享关系已创建')).toBeInTheDocument()
  }, 70_000)

  it('共享创建 409：展示服务端冲突原因并保留弹窗与输入', async () => {
    createRelationConflict = true
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.relation_manage', 'applications.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await openRelationsTab()
    fireEvent.click(await screen.findByRole('button', { name: '手工登记关系' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('对象类型'), { target: { value: 'order' } })
    fireEvent.change(within(dialog).getByLabelText('共享源对象 HMAC 引用（object_ref）'), { target: { value: 'objref:duplicate-source' } })
    fireEvent.change(within(dialog).getByLabelText('共享接收人（principal_id）'), { target: { value: 'principal:duplicate-recipient' } })
    fireEvent.change(within(dialog).getByLabelText('审计原因'), { target: { value: '重复共享审批' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认登记' }))
    await waitFor(() => expect(createRelationRequests).toHaveLength(1))
    expect(await screen.findByText('对象关系已存在')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('共享源对象 HMAC 引用（object_ref）')).toHaveValue('objref:duplicate-source')
  }, 60_000)

  it('共享撤销：确认共享源与接收人方向，POST 到目标关系并提交审计原因', async () => {
    relationItems = [relationFixtures[3]]
    useAuthStore.setState({
      user: makeUser(['api_authorization.read', 'api_authorization.relation_manage', 'applications.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()
    await openRelationsTab()
    fireEvent.click(await screen.findByRole('button', { name: '撤销' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('撤销共享接收人关系')).toBeInTheDocument()
    expect(within(dialog).getByText(/共享源对象/)).toBeInTheDocument()
    expect(within(dialog).getByText('principal:shared-recipient-0001')).toBeInTheDocument()
    fireEvent.change(within(dialog).getByLabelText('撤销原因'), { target: { value: '  共享审批到期  ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认撤销' }))
    await waitFor(() => expect(revokeRequests).toHaveLength(1))
    expect(revokeRequests[0].url).toBe('/api/v1/api-security/authz/relations/rel-shared/revoke')
    expect(revokeRequests[0].body).toEqual({ reason: '共享审批到期' })
    expect(await screen.findByText('对象关系已撤销')).toBeInTheDocument()
  }, 60_000)

  it('重新授权时间窗口：失效时间必须严格晚于生效时间', () => {
    const value = (iso: string) => ({ toISOString: () => iso })
    const from = value('2026-09-10T10:00:00.000Z')

    expect(validateReauthorizationWindow(from, value('2026-09-10T09:59:59.000Z'))).toBe('失效时间必须晚于生效时间')
    expect(validateReauthorizationWindow(from, value('2026-09-10T10:00:00.000Z'))).toBe('失效时间必须晚于生效时间')
    expect(validateReauthorizationWindow(from, value('2026-09-10T10:00:01.000Z'))).toBeUndefined()
    expect(validateReauthorizationWindow(from)).toBeUndefined()
  })

  it('跨模块权限门控：缺少 api_asset.read 与 applications.read 时不发起未授权列表请求', async () => {
    useAuthStore.setState({ user: makeUser(['api_authorization.read']), csrfToken: null, initialized: true })
    renderPage()
    expect(await screen.findByText('admin')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: /^对象授权$/ }))
    expect(await screen.findByText('选择应用后查看对象授权')).toBeInTheDocument()

    const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
    expect(urls.some((u) => u.includes('/api-security/endpoints'))).toBe(false)
    expect(urls.some((u) => u.includes('/applications'))).toBe(false)
  })
})
