import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import CatalogsTab from '../CatalogsTab'
import ApiMcpPage from '../ApiMcpPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../../../api/mcp', () => ({
  mcpApi: {
    listCatalogs: vi.fn(),
    getCatalog: vi.fn(),
    createCatalog: vi.fn(),
    updateCatalog: vi.fn(),
    deleteCatalog: vi.fn(),
    reviewTool: vi.fn(),
    listBindings: vi.fn(),
  },
}))

import { mcpApi } from '../../../api/mcp'

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

const catalogSummary = {
  id: 'c1',
  name: 'pay-tools',
  service_identity: 'mcp://pay.example.com',
  protocol_version: '2025-11-25',
  source: 'MANUAL_IMPORT',
  status: 'ENABLED',
  catalog_hash: `mcp-catalog-sha256:v1:${'a'.repeat(64)}`,
  version: 2,
  created_by: 'sec',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-05T00:00:00Z',
  tool_count: 3,
  approved_count: 1,
  pending_count: 1,
  rejected_count: 1,
}

const tools = [
  {
    id: 't1',
    catalog_id: 'c1',
    tool_name: 'echo',
    tool_version: '1.0.0',
    description_digest: 'd1',
    description_preview: '回显参数',
    tool_hash: `mcp-tool-sha256:v1:${'b'.repeat(64)}`,
    capability_tags: [],
    risk_level: 'LOW',
    data_classification: 'PUBLIC',
    allowed_principals: [],
    allowed_roles: [],
    allowed_tenants: [],
    approval_required: false,
    max_calls_per_minute: 0,
    arg_constraints: [],
    review_status: 'APPROVED',
    reviewed_by: 'sec',
    reviewed_at: '2026-10-02T00:00:00Z',
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-02T00:00:00Z',
  },
  {
    id: 't2',
    catalog_id: 'c1',
    tool_name: 'charge',
    tool_version: '2.1.0',
    description_digest: 'd2',
    description_preview: '扣款（合成数据）',
    tool_hash: `mcp-tool-sha256:v1:${'c'.repeat(64)}`,
    capability_tags: ['payment'],
    risk_level: 'HIGH',
    data_classification: 'CONFIDENTIAL',
    allowed_principals: ['principal:0a1b'],
    allowed_roles: ['finance'],
    allowed_tenants: [],
    approval_required: true,
    max_calls_per_minute: 10,
    arg_constraints: [{ field: 'url', kind: 'domain_suffix', allow: ['.example.com'] }],
    review_status: 'PENDING_REVIEW',
    created_at: '2026-10-03T00:00:00Z',
    updated_at: '2026-10-03T00:00:00Z',
  },
  {
    id: 't3',
    catalog_id: 'c1',
    tool_name: 'refund',
    tool_version: '1.2.0',
    description_digest: 'd3',
    description_preview: '',
    tool_hash: `mcp-tool-sha256:v1:${'d'.repeat(64)}`,
    capability_tags: [],
    risk_level: 'MEDIUM',
    data_classification: 'INTERNAL',
    allowed_principals: [],
    allowed_roles: [],
    allowed_tenants: [],
    approval_required: false,
    max_calls_per_minute: 5,
    arg_constraints: [],
    review_status: 'REJECTED',
    reviewed_by: 'sec',
    reviewed_at: '2026-10-04T00:00:00Z',
    created_at: '2026-10-03T00:00:00Z',
    updated_at: '2026-10-04T00:00:00Z',
  },
]

const catalogDetail = { catalog: { ...catalogSummary, tool_count: undefined, approved_count: undefined, pending_count: undefined, rejected_count: undefined }, tools }

const FULL = ['api_spec.read', 'api_spec.manage']

function renderUi(ui: React.ReactElement, permissions: string[]) {
  useAuthStore.setState({ user: makeUser(permissions), csrfToken: null, initialized: true })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>{ui}</AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApiMcpPage / CatalogsTab（NG-MCP G1 目录列表与审核状态机）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(mcpApi.listCatalogs).mockResolvedValue({ items: [catalogSummary], total: 1 })
    vi.mocked(mcpApi.getCatalog).mockResolvedValue(catalogDetail as never)
    vi.mocked(mcpApi.reviewTool).mockImplementation((_c, _t, body) =>
      Promise.resolve({ ...tools[1], ...body, reviewed_by: 'sec', reviewed_at: '2026-10-06T00:00:00Z' } as never),
    )
    vi.mocked(mcpApi.listBindings).mockResolvedValue({ items: [], total: 0 })
  })

  it('目录列表：名称/服务身份/审核统计/catalog_hash 短显/状态；覆盖范围与待审核提示语', async () => {
    renderUi(<ApiMcpPage />, FULL)
    expect(await screen.findByText('pay-tools')).toBeInTheDocument()
    expect(screen.getByText('mcp://pay.example.com')).toBeInTheDocument()
    expect(screen.getByText('通过 1')).toBeInTheDocument()
    expect(screen.getByText('待审 1')).toBeInTheDocument()
    expect(screen.getByText('拒绝 1')).toBeInTheDocument()
    expect(screen.getByText(`${'a'.repeat(12)}…`)).toBeInTheDocument()
    expect(screen.getByText('启用')).toBeInTheDocument()
    // M05 覆盖范围提示（stdio/出网未覆盖明示）
    expect(screen.getByText(/未经反代的 MCP（stdio\/本地进程）与工具进程出网不在覆盖内/)).toBeInTheDocument()
    // 导入/再导入后待审核状态明确展示语
    expect(screen.getByText(/新工具与语义变更行恒落「待审核」/)).toBeInTheDocument()
  })

  it('详情抽屉：工具行三态徽章/定级/允许维度/tool_hash 短显/预算', async () => {
    renderUi(<CatalogsTab />, FULL)
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    expect(await screen.findByText('echo')).toBeInTheDocument()
    expect(screen.getByText('已通过')).toBeInTheDocument()
    expect(screen.getByText('待审核')).toBeInTheDocument()
    expect(screen.getByText('已拒绝')).toBeInTheDocument()
    expect(screen.getByText('机密')).toBeInTheDocument()
    expect(screen.getByText(`${'c'.repeat(12)}…`)).toBeInTheDocument()
    expect(screen.getByText(/主体 1 项 · 角色 1 项 · 租户 不约束/)).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
    // 审核状态机固定说明（旧审批不继承）
    expect(screen.getAllByText(/旧审批不继承/).length).toBeGreaterThanOrEqual(1)
  })

  it('审核对话框：REJECTED 警示 + 提交载荷逐键（action/定级/允许维度/预算）', async () => {
    renderUi(<CatalogsTab />, FULL)
    fireEvent.click(await screen.findByRole('button', { name: '详情' }))
    const chargeRow = (await screen.findByText('charge')).closest('tr') as HTMLElement
    fireEvent.click(within(chargeRow).getByRole('button', { name: '审核' }))
    // 详情抽屉与审核弹窗同为 dialog——弹窗后挂载取最后一个
    const dialogs = await screen.findAllByRole('dialog')
    const dialog = dialogs[dialogs.length - 1]
    // 行值回填（定级/允许维度/预算）
    expect(within(dialog).getByText('高（HIGH）')).toBeInTheDocument()
    fireEvent.click(within(dialog).getByText('拒绝（REJECTED，不下发）'))
    expect(await within(dialog).findByText(/拒绝后该工具不出现在发布快照/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '提交审核' }))
    await waitFor(() =>
      expect(mcpApi.reviewTool).toHaveBeenCalledWith('c1', 't2', {
        action: 'REJECTED',
        risk_level: 'HIGH',
        data_classification: 'CONFIDENTIAL',
        allowed_principals: ['principal:0a1b'],
        allowed_roles: ['finance'],
        allowed_tenants: [],
        approval_required: true,
        max_calls_per_minute: 10,
      }),
    )
  })

  it('导入编辑器：必填校验（目录名/服务身份/工具名）', async () => {
    renderUi(<CatalogsTab />, FULL)
    fireEvent.click(await screen.findByRole('button', { name: /导入工具目录/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认导入' }))
    expect(await screen.findByText('目录名必填')).toBeInTheDocument()
    expect(screen.getByText('服务身份必填')).toBeInTheDocument()
    expect(screen.getByText('工具名必填')).toBeInTheDocument()
    expect(mcpApi.createCatalog).not.toHaveBeenCalled()
  })

  it('权限隐藏：无 manage 时写操作按钮全部隐藏（非禁用）', async () => {
    renderUi(<CatalogsTab />, ['api_spec.read'])
    await screen.findByText('pay-tools')
    expect(screen.queryByRole('button', { name: /导入工具目录/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '再导入' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
    // 详情抽屉内审核按钮同样隐藏
    fireEvent.click(screen.getByRole('button', { name: '详情' }))
    await screen.findByText('charge')
    expect(screen.queryByRole('button', { name: '审核' })).not.toBeInTheDocument()
  })
})
