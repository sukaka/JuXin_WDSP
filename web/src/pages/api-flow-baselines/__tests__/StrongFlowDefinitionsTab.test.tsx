import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import StrongFlowDefinitionsTab from '../StrongFlowDefinitionsTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../../../api/strongFlow', () => ({
  strongFlowApi: {
    listDefinitions: vi.fn(),
    getDefinition: vi.fn(),
    createDefinition: vi.fn(),
    updateDefinition: vi.fn(),
    activateDefinition: vi.fn(),
    retireDefinition: vi.fn(),
  },
}))
vi.mock('../../../api/applications', () => ({
  applicationsApi: { list: vi.fn() },
}))
vi.mock('../../../api/apiAssets', () => ({
  apiEndpointsApi: { list: vi.fn() },
}))

import { strongFlowApi } from '../../../api/strongFlow'
import { applicationsApi } from '../../../api/applications'
import { apiEndpointsApi } from '../../../api/apiAssets'

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

const definitionDraft = {
  id: 'd1',
  application_id: 'app1',
  name: '下单支付流程',
  version: 3,
  status: 'DRAFT',
  binding_path_prefix: '/api/v1/orders',
  instance_key_param: 'query:order_id',
  mode: 'PROTECT',
  created_by_name: 'sec',
  created_at: '2026-10-01T00:00:00Z',
  activated_at: null,
}

const definitionActive = {
  ...definitionDraft,
  id: 'd2',
  name: '退款流程',
  version: 2,
  status: 'ACTIVE',
  mode: 'OBSERVE',
  activated_at: '2026-09-30T00:00:00Z',
}

const definitionDetail = {
  ...definitionDraft,
  steps: [
    {
      step_key: 'register',
      endpoint_key: 'POST /api/v1/orders/register',
      sequence: 1,
      success_rule: {
        status_codes: [200],
        body_jsonpath_equals: { path: '$.status', value: 'ok' },
      },
      timeout_seconds: 60,
      retry_semantics: 'IDEMPOTENT',
      parallel_group: '',
      lease_seconds: 60,
      allows_202: false,
    },
    {
      step_key: 'pay',
      endpoint_key: 'POST /api/v1/orders/{id}/pay',
      sequence: 2,
      success_rule: { status_codes: [200] },
      timeout_seconds: 30,
      retry_semantics: 'NOT_RETRYABLE',
      parallel_group: '',
      lease_seconds: 15,
      allows_202: true,
    },
  ],
}

function renderTab(permissions: string[]) {
  useAuthStore.setState({
    user: makeUser(permissions),
    csrfToken: null,
    initialized: true,
  })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <StrongFlowDefinitionsTab />
      </AntdApp>
    </QueryClientProvider>,
  )
}

const FULL = ['api_flow.read', 'api_flow.manage']

/** 端点下拉选择：历史下拉残留 DOM，取可见（非 hidden）下拉内的选项 */
async function pickEndpointOption(title: string) {
  const options = await screen.findAllByTitle(title)
  const visible = options.filter((el) => {
    const dd = el.closest('.ant-select-dropdown')
    return dd && !dd.className.includes('ant-select-dropdown-hidden')
  })
  fireEvent.click(
    (visible[visible.length - 1] ?? options[options.length - 1]) as HTMLElement,
  )
}

describe('StrongFlowDefinitionsTab（NG-FLOW-01/04 §1.9 定义管理）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(strongFlowApi.listDefinitions).mockResolvedValue({
      items: [definitionDraft, definitionActive],
      total: 2,
      page: 1,
      page_size: 20,
    })
    vi.mocked(strongFlowApi.getDefinition).mockResolvedValue(definitionDetail)
    vi.mocked(strongFlowApi.createDefinition).mockResolvedValue(
      definitionDetail,
    )
    vi.mocked(strongFlowApi.updateDefinition).mockResolvedValue(
      definitionDetail,
    )
    vi.mocked(strongFlowApi.activateDefinition).mockResolvedValue({
      ...definitionDraft,
      status: 'ACTIVE',
    })
    vi.mocked(strongFlowApi.retireDefinition).mockResolvedValue({
      id: 'd1',
      status: 'RETIRED',
    })
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [{ id: 'app1', code: 'SHOP', name: '商城' }],
      total: 1,
      page: 1,
      page_size: 100,
    } as never)
    vi.mocked(apiEndpointsApi.list).mockResolvedValue({
      items: [
        { id: 'e1', endpoint_key: 'POST /api/v1/orders/register' },
        { id: 'e2', endpoint_key: 'POST /api/v1/orders/{id}/pay' },
      ],
      total: 2,
      page: 1,
      page_size: 100,
    } as never)
  })

  it('列表渲染：名称/版本/状态/模式/绑定前缀/实例引用提取器', async () => {
    renderTab(FULL)
    expect(await screen.findByText('下单支付流程')).toBeInTheDocument()
    expect(screen.getByText('v3')).toBeInTheDocument()
    expect(screen.getByText('草稿')).toBeInTheDocument()
    expect(screen.getByText('已激活')).toBeInTheDocument()
    expect(screen.getByText('实断（PROTECT）')).toBeInTheDocument()
    expect(screen.getByText('观测（OBSERVE）')).toBeInTheDocument()
    expect(screen.getAllByText('/api/v1/orders')).toHaveLength(2)
    expect(screen.getAllByText('query:order_id')).toHaveLength(2)
  })

  it('新建表单必填校验：空表单提交展示字段级错误', async () => {
    renderTab(FULL)
    await screen.findByText('下单支付流程')
    fireEvent.click(screen.getByRole('button', { name: /新建强流程定义/ }))
    fireEvent.click(await screen.findByRole('button', { name: '保 存' }))
    expect(await screen.findByText('请选择所属应用')).toBeInTheDocument()
    expect(screen.getByText('流程名称必填')).toBeInTheDocument()
    expect(screen.getByText('绑定路径前缀必填')).toBeInTheDocument()
    expect(screen.getByText('实例引用提取器必填')).toBeInTheDocument()
    expect(strongFlowApi.createDefinition).not.toHaveBeenCalled()
  })

  it('步骤校验失败展示：step_key 重复被列表级校验拦截且不发 POST', async () => {
    renderTab(FULL)
    await screen.findByText('下单支付流程')
    fireEvent.click(screen.getByRole('button', { name: /新建强流程定义/ }))
    // 应用/名称/前缀/提取器
    const dialog = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(dialog).getByText('选择应用'))
    fireEvent.click(await screen.findByText('商城（SHOP）'))
    fireEvent.change(screen.getByPlaceholderText('如：下单支付流程'), {
      target: { value: 'dup-flow' },
    })
    fireEvent.change(screen.getByPlaceholderText('如：/api/v1/orders'), {
      target: { value: '/api/v1/orders' },
    })
    fireEvent.change(screen.getByPlaceholderText('如：query:order_id'), {
      target: { value: 'query:order_id' },
    })
    // 两个步骤 step_key 相同 + 端点 + 成功判定
    fireEvent.click(screen.getByRole('button', { name: /添加步骤/ }))
    const keyInputs = await screen.findAllByPlaceholderText('如：register')
    for (const input of keyInputs)
      fireEvent.change(input, { target: { value: 'dup' } })
    const endpointSelects = screen.getAllByText('选择 API 端点')
    fireEvent.mouseDown(endpointSelects[0])
    await pickEndpointOption('POST /api/v1/orders/register')
    fireEvent.mouseDown(endpointSelects[1])
    await pickEndpointOption('POST /api/v1/orders/{id}/pay')
    const codeInputs = screen.getAllByPlaceholderText('如：200,201')
    for (const input of codeInputs)
      fireEvent.change(input, { target: { value: '200' } })
    fireEvent.click(screen.getByRole('button', { name: '保 存' }))
    expect(
      await screen.findByText('step_key "dup" 重复（定义内唯一）'),
    ).toBeInTheDocument()
    expect(strongFlowApi.createDefinition).not.toHaveBeenCalled()
  })

  it('PROTECT 模式选择展示红色警示「违规请求将被 403」', async () => {
    renderTab(FULL)
    await screen.findByText('下单支付流程')
    fireEvent.click(screen.getByRole('button', { name: /新建强流程定义/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.mouseDown(within(dialog).getByText('观测（OBSERVE）'))
    const protectOption = (await screen.findAllByText('实断（PROTECT）')).find(
      (el) => el.closest('.ant-select-item-option-content'),
    ) as HTMLElement
    fireEvent.click(protectOption)
    expect(
      await screen.findByText('PROTECT 模式：违规请求将被 403'),
    ).toBeInTheDocument()
    expect(screen.getByText(/UNKNOWN 恒不阻断/)).toBeInTheDocument()
  })

  it('激活确认：PROTECT 定义展示红色后果警示，确认后调用 activate', async () => {
    renderTab(FULL)
    await screen.findByText('下单支付流程')
    fireEvent.click(screen.getByRole('button', { name: '激活' }))
    expect(
      await screen.findByText(
        /激活后该流程违规请求将被实断（FLOW_VIOLATION_DENIED）/,
      ),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确认激活' }))
    await waitFor(() =>
      expect(strongFlowApi.activateDefinition).toHaveBeenCalledWith('d1'),
    )
  })

  it('详情抽屉：步骤序列图含成功条件可读化与允许转换说明', async () => {
    renderTab(['api_flow.read'])
    await screen.findByText('下单支付流程')
    fireEvent.click(screen.getAllByRole('button', { name: '详情' })[0])
    expect(
      await screen.findByText('步骤序列（按 sequence）'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('成功条件：状态码 ∈ [200] 且 $.status == "ok"'),
    ).toBeInTheDocument()
    expect(screen.getByText('成功条件：状态码 ∈ [200]')).toBeInTheDocument()
    expect(screen.getByText(/允许转换：进行中（ACTIVE）→/)).toBeInTheDocument()
    expect(
      screen.getByText('超时 30s · 租约 15s · 不可重试'),
    ).toBeInTheDocument()
    expect(screen.getByText('允许 202 受理')).toBeInTheDocument()
  })

  it('权限裁剪：无 manage 时隐藏新建/编辑/激活/停用/复制为新草稿', async () => {
    renderTab(['api_flow.read'])
    await screen.findByText('下单支付流程')
    expect(
      screen.queryByRole('button', { name: /新建强流程定义/ }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: '编辑' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: '激活' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: '停用' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: '复制为新草稿' }),
    ).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '详情' })).toHaveLength(2)
  })
})
