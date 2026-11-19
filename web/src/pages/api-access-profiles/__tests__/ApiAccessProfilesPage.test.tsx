import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { App } from 'antd'
import ApiAccessProfilesPage from '../ApiAccessProfilesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../../../api/apiSecurity', () => ({
  apiBehaviorProfilesApi: {
    list: vi.fn(),
  },
  apiObjectModelsApi: {
    list: vi.fn(),
    patch: vi.fn(),
  },
}))

import { apiBehaviorProfilesApi, apiObjectModelsApi } from '../../../api/apiSecurity'

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

const behaviorRow = {
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  endpoint_id: '11111111-1111-1111-1111-111111111111',
  endpoint_key: 'GET /api/v1/orders/{id}',
  identity_fingerprint: 'auth:deadbeef',
  window_seconds: 3600,
  request_count: 12,
  avg_rate: 0.0033,
  status_code_dist: { '2xx': 10, '5xx': 2 },
  hour_dist: { '8': 5, '9': 7 },
  updated_at: '2026-08-08T12:00:00Z',
}

const objectRow = {
  id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  endpoint_id: '11111111-1111-1111-1111-111111111111',
  endpoint_key: 'GET /api/v1/orders/{id}',
  object_segment: 'path:2',
  identifier_type: 'numeric',
  example_hash: 'cafebabe',
  sample_count: 10,
  first_seen: '2026-08-01T00:00:00Z',
  last_seen: '2026-08-08T12:00:00Z',
  updated_at: '2026-08-08T12:00:00Z',
}

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <App>{ui}</App>
    </QueryClientProvider>,
  )
}

describe('ApiAccessProfilesPage', () => {
  beforeEach(() => {
    vi.mocked(apiBehaviorProfilesApi.list).mockReset()
    vi.mocked(apiObjectModelsApi.list).mockReset()
    vi.mocked(apiObjectModelsApi.patch).mockReset()
    vi.mocked(apiBehaviorProfilesApi.list).mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 })
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20 })
    vi.mocked(apiObjectModelsApi.patch).mockResolvedValue(objectRow)
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
  })

  it('默认渲染环境维度 Tab：行为画像列表', async () => {
    vi.mocked(apiBehaviorProfilesApi.list).mockResolvedValue({
      items: [behaviorRow],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiAccessProfilesPage />)
    await waitFor(() => {
      expect(screen.getByText('auth:deadbeef')).toBeInTheDocument()
    })
    expect(screen.getByText('GET /api/v1/orders/{id}')).toBeInTheDocument()
    expect(screen.getByText('环境维度 · 行为画像')).toBeInTheDocument()
    expect(screen.getByText('对象维度 · 对象模型')).toBeInTheDocument()
    expect(apiBehaviorProfilesApi.list).toHaveBeenCalled()
  })

  it('行为画像点击行打开详情抽屉：状态码与时段分布', async () => {
    vi.mocked(apiBehaviorProfilesApi.list).mockResolvedValue({
      items: [behaviorRow],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiAccessProfilesPage />)
    await waitFor(() => {
      expect(screen.getByText('auth:deadbeef')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('auth:deadbeef'))
    await waitFor(() => {
      expect(screen.getByText('行为画像详情')).toBeInTheDocument()
    })
    expect(screen.getByText('状态码分布')).toBeInTheDocument()
    expect(screen.getByText('2xx：10')).toBeInTheDocument()
    expect(screen.getByText('调用时段分布（UTC，按 24h 回看重算）')).toBeInTheDocument()
  })

  it('切换到对象维度 Tab：对象模型列表与形态过滤', async () => {
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({
      items: [objectRow],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiAccessProfilesPage />)
    fireEvent.click(screen.getByText('对象维度 · 对象模型'))
    await waitFor(() => {
      expect(screen.getByText('path:2')).toBeInTheDocument()
    })
    expect(screen.getByText('数字')).toBeInTheDocument()
    expect(apiObjectModelsApi.list).toHaveBeenCalled()
  })

  it('对象模型点击行打开详情抽屉：示例哈希与脱敏说明', async () => {
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({
      items: [objectRow],
      total: 1,
      page: 1,
      page_size: 20,
    })
    wrap(<ApiAccessProfilesPage />)
    fireEvent.click(screen.getByText('对象维度 · 对象模型'))
    await waitFor(() => {
      expect(screen.getByText('path:2')).toBeInTheDocument()
    })
    fireEvent.click(screen.getByText('path:2'))
    await waitFor(() => {
      expect(screen.getByText('对象模型详情')).toBeInTheDocument()
    })
    expect(screen.getByText('cafebabe')).toBeInTheDocument()
    expect(screen.getByText('脱敏说明')).toBeInTheDocument()
  })

  async function openObjectModelDetail() {
    wrap(<ApiAccessProfilesPage />)
    fireEvent.click(screen.getByText('对象维度 · 对象模型'))
    fireEvent.click(await screen.findByText('path:2'))
    expect(await screen.findByText('对象模型详情')).toBeInTheDocument()
  }

  it('旧 OWNER 对象模型可展示与编辑，PATCH 不携带 required_relations', async () => {
    const ownerRow = { ...objectRow, required_relation: 'OWNER' }
    useAuthStore.setState({ user: makeUser(['api_runtime.read', 'api_authorization.manage']), csrfToken: null, initialized: true })
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [ownerRow], total: 1, page: 1, page_size: 20 })
    vi.mocked(apiObjectModelsApi.patch).mockResolvedValue(ownerRow)
    await openObjectModelDetail()
    expect(screen.getAllByText('所有者').length).toBeGreaterThanOrEqual(2)
    fireEvent.click(screen.getByRole('button', { name: '编辑要求关系' }))
    const dialog = (await screen.findByText('编辑对象要求关系')).closest('[role="dialog"]') as HTMLElement
    expect(within(dialog).getByText(/仅要求主体是对象所有者/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '保存关系配置' }))
    await waitFor(() => expect(apiObjectModelsApi.patch).toHaveBeenCalledWith(objectRow.id, { required_relation: 'OWNER' }))
    expect(await screen.findByText('对象要求关系已更新')).toBeInTheDocument()
  })

  it('ANY_OF 编辑固定为 OWNER + SHARED_WITH，并按规范顺序提交', async () => {
    const ownerRow = { ...objectRow, required_relation: 'OWNER' }
    const anyOfRow = { ...objectRow, required_relation: 'ANY_OF', required_relations: ['OWNER', 'SHARED_WITH'] as Array<'OWNER' | 'SHARED_WITH'> }
    useAuthStore.setState({ user: makeUser(['api_runtime.read', 'api_authorization.manage']), csrfToken: null, initialized: true })
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [ownerRow], total: 1, page: 1, page_size: 20 })
    vi.mocked(apiObjectModelsApi.patch).mockResolvedValue(anyOfRow)
    await openObjectModelDetail()
    fireEvent.click(screen.getByRole('button', { name: '编辑要求关系' }))
    const dialog = (await screen.findByText('编辑对象要求关系')).closest('[role="dialog"]') as HTMLElement
    fireEvent.mouseDown(within(dialog).getByRole('combobox'))
    fireEvent.click(await screen.findByText('任一关系'))
    expect(within(dialog).getByText('共享接收人')).toBeInTheDocument()
    expect(within(dialog).getByText(/当前固定为「所有者」或「共享接收人」/)).toBeInTheDocument()
    expect(within(dialog).queryByText(/DELEGATED_TO/)).not.toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '保存关系配置' }))
    await waitFor(() => expect(apiObjectModelsApi.patch).toHaveBeenCalledWith(objectRow.id, {
      required_relation: 'ANY_OF',
      required_relations: ['OWNER', 'SHARED_WITH'],
    }))
  })

  it('既有 ANY_OF 展示真实关系集合，保存时将逆序输入规范化', async () => {
    const reversedAnyOfRow = { ...objectRow, required_relation: 'ANY_OF', required_relations: ['SHARED_WITH', 'OWNER'] as Array<'OWNER' | 'SHARED_WITH'> }
    useAuthStore.setState({ user: makeUser(['api_runtime.read', 'api_authorization.manage']), csrfToken: null, initialized: true })
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [reversedAnyOfRow], total: 1, page: 1, page_size: 20 })
    vi.mocked(apiObjectModelsApi.patch).mockResolvedValue({ ...reversedAnyOfRow, required_relations: ['OWNER', 'SHARED_WITH'] })
    await openObjectModelDetail()
    expect(screen.getAllByText('任一关系').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('任一满足的关系')).toBeInTheDocument()
    expect(screen.getByText('共享接收人')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '编辑要求关系' }))
    const dialog = (await screen.findByText('编辑对象要求关系')).closest('[role="dialog"]') as HTMLElement
    fireEvent.click(within(dialog).getByRole('button', { name: '保存关系配置' }))
    await waitFor(() => expect(apiObjectModelsApi.patch).toHaveBeenCalledWith(objectRow.id, {
      required_relation: 'ANY_OF',
      required_relations: ['OWNER', 'SHARED_WITH'],
    }))
  })

  it('无 api_authorization.manage 权限时不展示要求关系编辑入口', async () => {
    const anyOfRow = { ...objectRow, required_relation: 'ANY_OF', required_relations: ['OWNER', 'SHARED_WITH'] as Array<'OWNER' | 'SHARED_WITH'> }
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [anyOfRow], total: 1, page: 1, page_size: 20 })
    await openObjectModelDetail()
    expect(screen.getByText('任一满足的关系')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑要求关系' })).not.toBeInTheDocument()
    expect(apiObjectModelsApi.patch).not.toHaveBeenCalled()
  })

  it('委托等本切片不支持的关系不提供编辑入口', async () => {
    const delegatedRow = { ...objectRow, required_relation: 'DELEGATED_TO' }
    useAuthStore.setState({ user: makeUser(['api_runtime.read', 'api_authorization.manage']), csrfToken: null, initialized: true })
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [delegatedRow], total: 1, page: 1, page_size: 20 })
    await openObjectModelDetail()
    expect(screen.getByText(/当前配置不属于本功能支持的「所有者」或「任一关系/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑要求关系' })).not.toBeInTheDocument()
    expect(apiObjectModelsApi.patch).not.toHaveBeenCalled()
  })
})
