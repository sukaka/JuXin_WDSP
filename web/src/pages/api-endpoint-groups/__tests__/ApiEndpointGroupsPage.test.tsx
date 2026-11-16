import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApiEndpointGroupsPage from '../ApiEndpointGroupsPage'
import type { ApiEndpointItem } from '../../../api/apiAssets'
import type { ApiEndpointGroup } from '../../../api/apiEndpointGroups'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const APPLICATIONS = [
  { id: 'app-1', code: 'SHOP', name: '商城应用' },
  { id: 'app-2', code: 'CRM', name: '客户应用' },
]

function makeGroup(
  overrides: Partial<ApiEndpointGroup> = {},
): ApiEndpointGroup {
  return {
    id: 'group-1',
    application_id: 'app-1',
    application_name: '商城应用',
    code: 'ORDER_CENTER',
    name: '订单中心',
    description: '订单业务接口',
    enabled: true,
    endpoint_count: 0,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

function makeEndpoint(
  id: string,
  applicationId: string,
  path: string,
): ApiEndpointItem {
  return {
    id,
    application_id: applicationId,
    application_name:
      APPLICATIONS.find((application) => application.id === applicationId)
        ?.name ?? '',
    directory_path: '',
    http_method: 'GET',
    normalized_path: path,
    raw_path_example: path,
    endpoint_key: `GET ${path}`,
    protocol_type: 'REST',
    api_confidence: 0.9,
    asset_status: 'CONFIRMED',
    learning_status: 'LEARNED',
    is_api: true,
    hit_count: 1,
    first_seen_at: '2026-01-01T00:00:00Z',
    last_seen_at: '2026-01-02T00:00:00Z',
    classification_locked: false,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }
}

interface TestState {
  groups: ApiEndpointGroup[]
  endpoints: ApiEndpointItem[]
  members: Record<string, string[]>
}

function envelope(data: unknown, status = 200): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function errorResponse(message: string, status = 400): Response {
  return new Response(
    JSON.stringify({ code: 'INVALID_ARGUMENT', message, data: null }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function pageOf<T>(items: T[], url: URL) {
  const page = Number(url.searchParams.get('page') ?? 1)
  const pageSize = Number(url.searchParams.get('page_size') ?? 20)
  return {
    items: items.slice((page - 1) * pageSize, page * pageSize),
    page,
    page_size: pageSize,
    total: items.length,
  }
}

function installApi(state: TestState) {
  const root = '/api/v1/api-security/endpoint-groups'
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost')
    const path = url.pathname
    const method = init?.method ?? 'GET'

    if (path === '/api/v1/applications') {
      return Promise.resolve(
        envelope({
          items: APPLICATIONS,
          page: 1,
          page_size: 100,
          total: APPLICATIONS.length,
        }),
      )
    }
    if (path === '/api/v1/api-security/endpoints') {
      const applicationId = url.searchParams.get('application_id')
      const keyword = url.searchParams.get('keyword')?.toLowerCase()
      const items = state.endpoints.filter(
        (endpoint) =>
          (!applicationId || endpoint.application_id === applicationId) &&
          (!keyword || endpoint.endpoint_key.toLowerCase().includes(keyword)),
      )
      return Promise.resolve(envelope(pageOf(items, url)))
    }
    if (path === root && method === 'GET') {
      const applicationId = url.searchParams.get('application_id')
      const items = state.groups.filter(
        (group) => !applicationId || group.application_id === applicationId,
      )
      return Promise.resolve(envelope(pageOf(items, url)))
    }
    if (path === root && method === 'POST') {
      const body = JSON.parse(String(init?.body)) as {
        application_id: string
        code: string
        name: string
        description: string
        enabled: boolean
      }
      const group = makeGroup({
        id: `group-${state.groups.length + 1}`,
        application_id: body.application_id,
        application_name:
          APPLICATIONS.find(
            (application) => application.id === body.application_id,
          )?.name ?? '',
        code: body.code,
        name: body.name,
        description: body.description,
        enabled: body.enabled,
      })
      state.groups.push(group)
      state.members[group.id] = []
      return Promise.resolve(envelope(group, 201))
    }

    const memberMatch = path.match(
      /^\/api\/v1\/api-security\/endpoint-groups\/([^/]+)\/endpoints(?:\/([^/]+))?$/,
    )
    if (memberMatch) {
      const groupId = memberMatch[1]
      const memberIds = state.members[groupId] ?? []
      if (method === 'GET') {
        const items = memberIds
          .map((id) => state.endpoints.find((endpoint) => endpoint.id === id))
          .filter((endpoint): endpoint is ApiEndpointItem => Boolean(endpoint))
          .map((endpoint) => ({
            id: endpoint.id,
            application_id: endpoint.application_id,
            http_method: endpoint.http_method,
            normalized_path: endpoint.normalized_path,
            endpoint_key: endpoint.endpoint_key,
            asset_status: endpoint.asset_status,
            added_at: '2026-01-03T00:00:00Z',
          }))
        return Promise.resolve(envelope(pageOf(items, url)))
      }
      if (method === 'POST') {
        const body = JSON.parse(String(init?.body)) as { endpoint_id: string }
        if (!memberIds.includes(body.endpoint_id))
          memberIds.push(body.endpoint_id)
        state.members[groupId] = memberIds
        const group = state.groups.find((item) => item.id === groupId)
        if (group) group.endpoint_count = memberIds.length
        return Promise.resolve(envelope(null, 201))
      }
      if (method === 'DELETE' && memberMatch[2]) {
        state.members[groupId] = memberIds.filter((id) => id !== memberMatch[2])
        const group = state.groups.find((item) => item.id === groupId)
        if (group) group.endpoint_count = state.members[groupId].length
        return Promise.resolve(envelope(null))
      }
    }

    const groupMatch = path.match(
      /^\/api\/v1\/api-security\/endpoint-groups\/([^/]+)$/,
    )
    if (groupMatch) {
      const index = state.groups.findIndex(
        (group) => group.id === groupMatch[1],
      )
      if (index < 0) return Promise.resolve(errorResponse('分组不存在', 404))
      if (method === 'GET') {
        return Promise.resolve(envelope(state.groups[index]))
      }
      if (method === 'PUT') {
        const body = JSON.parse(String(init?.body)) as Partial<ApiEndpointGroup>
        state.groups[index] = { ...state.groups[index], ...body }
        return Promise.resolve(envelope(state.groups[index]))
      }
      if (method === 'DELETE') {
        state.groups.splice(index, 1)
        delete state.members[groupMatch[1]]
        return Promise.resolve(envelope(null))
      }
    }
    return Promise.reject(new Error(`unexpected request: ${method} ${path}`))
  })
}

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'user-1',
    username: 'security',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

function renderPage(
  permissions = ['api_endpoint_group.read', 'api_endpoint_group.manage'],
) {
  useAuthStore.getState().setSession(makeUser(permissions), 'test-csrf')
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ConfigProvider locale={zhCN}>
        <AntdApp>
          <MemoryRouter>
            <ApiEndpointGroupsPage />
          </MemoryRouter>
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>,
  )
}

function clickSelectOption(label: string) {
  const option = screen
    .getAllByText(label)
    .find((element) => element.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

describe('ApiEndpointGroupsPage', () => {
  beforeEach(() => {
    useAuthStore.getState().reset()
  })

  afterEach(() => {
    useAuthStore.getState().reset()
    vi.unstubAllGlobals()
  })

  it('按应用筛选并使用服务端分页，切换筛选时回到第一页', async () => {
    const state: TestState = {
      groups: Array.from({ length: 21 }, (_, index) =>
        makeGroup({
          id: `group-${index + 1}`,
          application_id: index === 20 ? 'app-2' : 'app-1',
          application_name: index === 20 ? '客户应用' : '商城应用',
          code: `GROUP_${index + 1}`,
          name: `分组 ${index + 1}`,
        }),
      ),
      endpoints: [],
      members: {},
    }
    const fetchMock = installApi(state)
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    expect(await screen.findByText('共 21 个分组')).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('2'))
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(
          ([input]) =>
            String(input).includes('/endpoint-groups?') &&
            String(input).includes('page=2'),
        ),
      ).toBe(true)
    })

    fireEvent.mouseDown(screen.getByText('全部应用'))
    clickSelectOption('客户应用（CRM）')
    await waitFor(() => {
      expect(
        fetchMock.mock.calls.some(([input]) => {
          const url = String(input)
          return (
            url.includes('/endpoint-groups?') &&
            url.includes('application_id=app-2') &&
            url.includes('page=1')
          )
        }),
      ).toBe(true)
    })
    expect(await screen.findByText('分组 21')).toBeInTheDocument()
    expect(screen.getByText('共 1 个分组')).toBeInTheDocument()
  })

  it('新建时归一化编码并提交真实 POST，成功后重新读取列表', async () => {
    const state: TestState = { groups: [], endpoints: [], members: {} }
    const fetchMock = installApi(state)
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /新建分组/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(dialog).getByText('选择应用'))
    clickSelectOption('商城应用（SHOP）')
    fireEvent.change(within(dialog).getByPlaceholderText('如 ORDER_CENTER'), {
      target: { value: '  order_center  ' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('如：订单中心'), {
      target: { value: '订单中心' },
    })
    fireEvent.change(
      within(dialog).getByPlaceholderText('说明该组覆盖的业务功能与接口边界'),
      { target: { value: '下单与订单查询' } },
    )
    fireEvent.click(within(dialog).getByRole('button', { name: /创\s*建/ }))

    await waitFor(() => expect(state.groups).toHaveLength(1))
    expect(state.groups[0]).toMatchObject({
      application_id: 'app-1',
      code: 'ORDER_CENTER',
      name: '订单中心',
      description: '下单与订单查询',
      enabled: true,
    })
    const createCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith('/api-security/endpoint-groups') &&
        init?.method === 'POST',
    )
    expect(createCall?.[1]?.headers).toMatchObject({
      'X-CSRF-Token': 'test-csrf',
    })
    expect(await screen.findByText('订单中心')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('编码格式错误时不发创建请求，服务端失败时保留表单并展示错误', async () => {
    const state: TestState = { groups: [], endpoints: [], members: {} }
    const fetchMock = installApi(state)
    vi.stubGlobal('fetch', fetchMock)
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建分组/ }))
    const dialog = await screen.findByRole('dialog')

    fireEvent.change(within(dialog).getByPlaceholderText('如 ORDER_CENTER'), {
      target: { value: '1-INVALID' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('如：订单中心'), {
      target: { value: '非法编码分组' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /创\s*建/ }))
    expect(
      await within(dialog).findByText(
        '须以大写字母开头，仅含大写字母、数字和下划线',
      ),
    ).toBeInTheDocument()
    expect(
      fetchMock.mock.calls.some(([, init]) => init?.method === 'POST'),
    ).toBe(false)

    fireEvent.mouseDown(within(dialog).getByText('选择应用'))
    clickSelectOption('商城应用（SHOP）')
    fireEvent.change(within(dialog).getByPlaceholderText('如 ORDER_CENTER'), {
      target: { value: 'VALID_GROUP' },
    })
    fetchMock.mockImplementationOnce(() =>
      Promise.resolve(errorResponse('分组编码已存在', 409)),
    )
    fireEvent.click(within(dialog).getByRole('button', { name: /创\s*建/ }))
    expect(
      await within(dialog).findByText('分组编码已存在'),
    ).toBeInTheDocument()
    expect(state.groups).toHaveLength(0)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  it('编辑、启停和删除均等待真实写请求完成后刷新', async () => {
    const state: TestState = {
      groups: [makeGroup()],
      endpoints: [],
      members: { 'group-1': [] },
    }
    const fetchMock = installApi(state)
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    fireEvent.click(
      await screen.findByRole('button', { name: '编辑分组-订单中心' }),
    )
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如：订单中心'), {
      target: { value: '订单核心' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => expect(state.groups[0].name).toBe('订单核心'))
    const updateCall = fetchMock.mock.calls.find(
      ([, init]) => init?.method === 'PUT',
    )
    expect(JSON.parse(String(updateCall?.[1]?.body))).toEqual({
      code: 'ORDER_CENTER',
      name: '订单核心',
      description: '订单业务接口',
      enabled: true,
    })

    fireEvent.click(await screen.findByRole('button', { name: '停用' }))
    await waitFor(() => expect(state.groups[0].enabled).toBe(false))
    fireEvent.click(await screen.findByRole('button', { name: '启用' }))
    await waitFor(() => expect(state.groups[0].enabled).toBe(true))

    fireEvent.click(
      await screen.findByRole('button', { name: '删除分组-订单核心' }),
    )
    const confirm = await screen.findByRole('dialog')
    fireEvent.click(within(confirm).getByRole('button', { name: /删\s*除/ }))
    await waitFor(() => expect(state.groups).toHaveLength(0))
    expect(
      await screen.findByText('暂无接口分组，可点击“新建分组”开始整理业务接口'),
    ).toBeInTheDocument()
  })

  it('成员抽屉添加和移除同应用真实接口，并刷新成员与分组计数', async () => {
    const state: TestState = {
      groups: [makeGroup()],
      endpoints: [
        makeEndpoint('endpoint-1', 'app-1', '/v1/orders'),
        makeEndpoint('endpoint-2', 'app-2', '/v1/customers'),
      ],
      members: { 'group-1': [] },
    }
    const fetchMock = installApi(state)
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    fireEvent.click(
      await screen.findByRole('button', { name: '管理成员-订单中心' }),
    )
    const drawer = await screen.findByRole('dialog')
    expect(
      await within(drawer).findByText('暂无接口成员，请从上方选择真实接口添加'),
    ).toBeInTheDocument()
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    clickSelectOption('GET /v1/orders')
    fireEvent.click(within(drawer).getByRole('button', { name: /添加成员/ }))

    await waitFor(() =>
      expect(state.members['group-1']).toEqual(['endpoint-1']),
    )
    expect(await within(drawer).findByText('/v1/orders')).toBeInTheDocument()
    expect(state.groups[0].endpoint_count).toBe(1)
    const candidateCall = fetchMock.mock.calls.find(([input]) =>
      String(input).includes('/api-security/endpoints?'),
    )
    expect(String(candidateCall?.[0])).toContain('application_id=app-1')
    const addCall = fetchMock.mock.calls.find(
      ([input, init]) =>
        String(input).endsWith('/endpoint-groups/group-1/endpoints') &&
        init?.method === 'POST',
    )
    expect(JSON.parse(String(addCall?.[1]?.body))).toEqual({
      endpoint_id: 'endpoint-1',
    })

    fireEvent.click(
      within(drawer).getByRole('button', {
        name: '移除成员-GET /v1/orders',
      }),
    )
    fireEvent.click(await screen.findByRole('button', { name: /^移\s*除$/ }))
    await waitFor(() => expect(state.members['group-1']).toEqual([]))
    expect(state.groups[0].endpoint_count).toBe(0)
    expect(
      await within(drawer).findByText('暂无接口成员，请从上方选择真实接口添加'),
    ).toBeInTheDocument()
  })

  it('只读权限保留列表和成员查看，隐藏所有写入口且不请求候选接口', async () => {
    const state: TestState = {
      groups: [makeGroup({ endpoint_count: 1 })],
      endpoints: [makeEndpoint('endpoint-1', 'app-1', '/v1/orders')],
      members: { 'group-1': ['endpoint-1'] },
    }
    const fetchMock = installApi(state)
    vi.stubGlobal('fetch', fetchMock)
    renderPage(['api_endpoint_group.read'])

    expect(await screen.findByText('订单中心')).toBeInTheDocument()
    expect(screen.getByText('只读')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /新建分组/ })).toBeNull()
    expect(
      screen.queryByRole('button', { name: '编辑分组-订单中心' }),
    ).toBeNull()
    expect(screen.queryByRole('button', { name: '停用' })).toBeNull()
    expect(
      screen.queryByRole('button', { name: '删除分组-订单中心' }),
    ).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '管理成员-订单中心' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('/v1/orders')).toBeInTheDocument()
    expect(within(drawer).queryByText('搜索并选择同应用接口')).toBeNull()
    expect(
      within(drawer).queryByRole('button', { name: /添加成员/ }),
    ).toBeNull()
    expect(within(drawer).queryByRole('button', { name: /移除/ })).toBeNull()
    expect(
      fetchMock.mock.calls.some(([input]) =>
        String(input).includes('/api/v1/api-security/endpoints?'),
      ),
    ).toBe(false)
  })

  it('列表与空成员加载失败时显示后端错误，不展示伪数据', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = new URL(String(input), 'http://localhost').pathname
      if (path === '/api/v1/applications') {
        return Promise.resolve(
          envelope({ items: APPLICATIONS, page: 1, page_size: 100, total: 2 }),
        )
      }
      if (path === '/api/v1/api-security/endpoint-groups') {
        return Promise.resolve(errorResponse('分组服务暂不可用', 503))
      }
      return Promise.reject(new Error(`unexpected request: ${path}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    renderPage()

    expect(await screen.findByText('加载接口分组失败')).toBeInTheDocument()
    expect(screen.getByText('分组服务暂不可用')).toBeInTheDocument()
    expect(screen.queryByText('订单中心')).toBeNull()
  })
})
