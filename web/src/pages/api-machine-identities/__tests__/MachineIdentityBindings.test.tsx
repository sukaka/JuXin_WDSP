import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import MachineIdentityBindingsTab from '../MachineIdentityBindingsTab'
import { ApiError } from '../../../api/client'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../../../api/machineIdentity', () => ({
  machineIdentityApi: {
    listBindings: vi.fn(),
    createBinding: vi.fn(),
    updateBinding: vi.fn(),
    deleteBinding: vi.fn(),
  },
}))
vi.mock('../../../api/applications', () => ({
  applicationsApi: { list: vi.fn() },
}))

import { machineIdentityApi } from '../../../api/machineIdentity'
import { applicationsApi } from '../../../api/applications'

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

const bindings = [
  {
    id: 'b1', application_id: 'app1', path_exact: '/api/v1/billing', path_prefix: '',
    mode: 'PROTECT', proof_required: true, version: 2,
    created_by: 'sec', created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-05T00:00:00Z',
  },
  {
    id: 'b2', application_id: 'app2', path_exact: '', path_prefix: '/api/v1/reports/',
    mode: 'OBSERVE', proof_required: false, version: 1,
    created_by: 'sec', created_at: '2026-10-02T00:00:00Z', updated_at: '2026-10-02T00:00:00Z',
  },
]

const FULL = ['jwt_trust.read', 'jwt_trust.manage']

function renderTab(permissions: string[]) {
  useAuthStore.setState({ user: makeUser(permissions), csrfToken: null, initialized: true })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MachineIdentityBindingsTab />
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 取下拉选项（表格单元格同文案避让——取 option-content 容器内者） */
async function clickOption(text: string) {
  const option = (await screen.findAllByText(text)).find((el) =>
    el.closest('.ant-select-item-option-content'),
  ) as HTMLElement
  fireEvent.click(option)
}

describe('MachineIdentityBindingsTab（NG-ID G1 绑定管理）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(machineIdentityApi.listBindings).mockResolvedValue({ items: bindings, total: 2 })
    vi.mocked(machineIdentityApi.createBinding).mockResolvedValue(bindings[0])
    vi.mocked(machineIdentityApi.updateBinding).mockResolvedValue({ ...bindings[1], mode: 'PROTECT', version: 2 })
    vi.mocked(machineIdentityApi.deleteBinding).mockResolvedValue({ status: 'deleted' })
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [
        { id: 'app1', code: 'SHOP', name: '商城' },
        { id: 'app2', code: 'BI', name: '报表' },
      ],
      total: 2,
      page: 1,
      page_size: 100,
    } as never)
  })

  it('绑定列表：应用名映射/路径形态徽章（精确|前缀）/模式/强制签名 401 语义/版本', async () => {
    renderTab(FULL)
    expect(await screen.findByText('商城（SHOP）')).toBeInTheDocument()
    expect(screen.getByText('/api/v1/billing')).toBeInTheDocument()
    expect(screen.getByText('精确')).toBeInTheDocument()
    expect(screen.getByText('前缀')).toBeInTheDocument()
    expect(screen.getByText('实断（PROTECT）')).toBeInTheDocument()
    expect(screen.getByText('未签名 401')).toBeInTheDocument()
    expect(screen.getByText('观测（OBSERVE）')).toBeInTheDocument()
  })

  it('新建绑定：路径二选一校验（非 / 开头与含 query 拦截）+ 载荷 path_exact 逐键', async () => {
    renderTab(FULL)
    fireEvent.click(await screen.findByRole('button', { name: /新建绑定/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如：/api/v1/billing 或 /api/v1/billing/'), { target: { value: 'api/v1/x?y=1' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '创建绑定' }))
    expect(await within(dialog).findByText('路径须为 / 开头')).toBeInTheDocument()
    expect(machineIdentityApi.createBinding).not.toHaveBeenCalled()
    // 完整填写（默认 path_exact）
    fireEvent.mouseDown(within(dialog).getByText('选择应用'))
    await clickOption('商城（SHOP）')
    fireEvent.change(within(dialog).getByPlaceholderText('如：/api/v1/billing 或 /api/v1/billing/'), { target: { value: '/api/v1/billing' } })
    fireEvent.click(within(dialog).getByText('强制签名（proof_required）').closest('.ant-form-item')?.querySelector('button') as HTMLElement)
    fireEvent.click(within(dialog).getByRole('button', { name: '创建绑定' }))
    await waitFor(() =>
      expect(machineIdentityApi.createBinding).toHaveBeenCalledWith({
        application_id: 'app1',
        path_exact: '/api/v1/billing',
        path_prefix: '',
        mode: 'OBSERVE',
        proof_required: true,
      }),
    )
  })

  it('新建绑定：path_prefix 分支载荷；PROTECT 模式警示未签名 401 准入语义', async () => {
    renderTab(FULL)
    fireEvent.click(await screen.findByRole('button', { name: /新建绑定/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByText('路径前缀（path_prefix）'))
    fireEvent.mouseDown(within(dialog).getByText('选择应用'))
    await clickOption('报表（BI）')
    fireEvent.change(within(dialog).getByPlaceholderText('如：/api/v1/billing 或 /api/v1/billing/'), { target: { value: '/api/v1/reports/' } })
    // 选 PROTECT 展示准入语义警示
    fireEvent.mouseDown(within(dialog).getByText('观测（OBSERVE）'))
    await clickOption('实断（PROTECT）')
    expect(await within(dialog).findByText(/未签名的请求即拒绝 401（准入语义）/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: '创建绑定' }))
    await waitFor(() =>
      expect(machineIdentityApi.createBinding).toHaveBeenCalledWith({
        application_id: 'app2',
        path_exact: '',
        path_prefix: '/api/v1/reports/',
        mode: 'PROTECT',
        proof_required: false,
      }),
    )
  })

  it('编辑绑定：PUT 携带乐观锁 version；409 精确提示「版本冲突，请刷新后重试」', async () => {
    renderTab(FULL)
    const row = (await screen.findByText('/api/v1/billing')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/当前乐观锁版本 v2/)).toBeInTheDocument()
    vi.mocked(machineIdentityApi.updateBinding).mockRejectedValueOnce(new ApiError('binding version conflict（乐观锁不匹配）', 'RESOURCE_CONFLICT', 409))
    fireEvent.click(within(dialog).getByRole('button', { name: '保 存' }))
    expect(await within(dialog).findByText('版本冲突，请刷新后重试')).toBeInTheDocument()
    expect(machineIdentityApi.updateBinding).toHaveBeenCalledWith('b1', { mode: 'PROTECT', proof_required: true, version: 2 })
  })

  it('权限隐藏：无 manage 时新建/编辑/解绑全部隐藏（非禁用）', async () => {
    renderTab(['jwt_trust.read'])
    await screen.findByText('/api/v1/billing')
    expect(screen.queryByRole('button', { name: /新建绑定/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '解绑' })).not.toBeInTheDocument()
  })
})
