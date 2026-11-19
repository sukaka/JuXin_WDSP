import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import StrongFlowInstancesTab from '../StrongFlowInstancesTab'
import { ApiError } from '../../../api/client'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../../../api/strongFlow', () => ({
  strongFlowApi: {
    listInstances: vi.fn(),
    getInstance: vi.fn(),
    resolveInstance: vi.fn(),
  },
}))
vi.mock('../../../api/applications', () => ({
  applicationsApi: { list: vi.fn() },
}))

import { strongFlowApi } from '../../../api/strongFlow'
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

const baseInstance = {
  id: 'i-1',
  application_id: 'app1',
  definition_id: 'd1',
  definition_name: '下单支付流程',
  definition_version: 3,
  instance_key: 'sfref:0123456789abcdef0123456789abcdef',
  tenant_ref: 'tenant:0a1b2c3d',
  principal_ref: 'principal:0a1b2c3d',
  version: 2,
  created_at: '2026-10-05T02:00:00Z',
  updated_at: '2026-10-05T02:10:00Z',
  terminated_at: null,
}

const fiveStatusInstances = [
  { ...baseInstance, id: 'i-1', status: 'ACTIVE' },
  {
    ...baseInstance,
    id: 'i-2',
    status: 'CONFIRMED',
    terminated_at: '2026-10-05T03:00:00Z',
  },
  { ...baseInstance, id: 'i-3', status: 'INDETERMINATE' },
  {
    ...baseInstance,
    id: 'i-4',
    status: 'CANCELLED',
    terminated_at: '2026-10-05T03:00:00Z',
  },
  {
    ...baseInstance,
    id: 'i-5',
    status: 'FAILED',
    terminated_at: '2026-10-05T03:00:00Z',
  },
]

const indeterminateDetail = {
  ...baseInstance,
  status: 'INDETERMINATE',
  status_semantics: 'UNKNOWN_NOT_CONFIRMED',
  status_message: '未知，不显示安全通过',
  steps: [
    {
      step_key: 'register',
      action: 'INSTANCE_NEW',
      result: 'OK',
      occurred_at: '2026-10-05T02:00:00Z',
      fencing_token: 1,
      reason_code: '',
      request_id: 'req-001-abcd',
    },
    {
      step_key: 'register',
      action: 'RESERVE',
      result: 'OK',
      occurred_at: '2026-10-05T02:00:01Z',
      fencing_token: 1,
      reason_code: '',
      request_id: 'req-001-abcd',
    },
    {
      step_key: 'register',
      action: 'COMMIT',
      result: 'OK',
      occurred_at: '2026-10-05T02:00:02Z',
      fencing_token: 1,
      reason_code: '',
      request_id: 'req-001-abcd',
    },
    {
      step_key: 'pay',
      action: 'RESERVE',
      result: 'OK',
      occurred_at: '2026-10-05T02:05:00Z',
      fencing_token: 2,
      reason_code: '',
      request_id: 'req-002-abcd',
    },
    {
      step_key: 'pay',
      action: 'INSTANCE_INDETERMINATE',
      result: 'UNKNOWN',
      occurred_at: '2026-10-05T02:05:10Z',
      fencing_token: 2,
      reason_code: 'UNKNOWN-001',
      request_id: 'req-002-abcd',
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
        <StrongFlowInstancesTab />
      </AntdApp>
    </QueryClientProvider>,
  )
}

const FULL = [
  'api_flow.read',
  'api_flow.manage',
  'api_authorization.evidence_read',
]

/** 打开 INDETERMINATE 实例详情抽屉 */
async function openIndeterminateDetail(permissions: string[] = FULL) {
  renderTab(permissions)
  await screen.findByText('未知待对账')
  const detailButtons = screen.getAllByRole('button', { name: '详情' })
  // i-3 为列表第三行（INDETERMINATE）
  fireEvent.click(detailButtons[2])
  await screen.findByText('步骤轨迹（5 条事件）')
}

describe('StrongFlowInstancesTab（NG-FLOW-02/03/04 §1.9 实例管理区块）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(strongFlowApi.listInstances).mockResolvedValue({
      items: fiveStatusInstances,
      total: 5,
      page: 1,
      page_size: 20,
    })
    vi.mocked(strongFlowApi.getInstance).mockResolvedValue(indeterminateDetail)
    vi.mocked(strongFlowApi.resolveInstance).mockResolvedValue({
      ...indeterminateDetail,
      status: 'CONFIRMED',
      status_semantics: 'SUCCEEDED',
      status_message: '已确认完成',
      version: 3,
      terminated_at: '2026-10-05T04:00:00Z',
    })
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [{ id: 'app1', code: 'SHOP', name: '商城' }],
      total: 1,
      page: 1,
      page_size: 100,
    } as never)
  })

  it('实例列表：五态徽章/定义版本/实例键截断/创建与终态时间', async () => {
    renderTab(FULL)
    expect(await screen.findByText('进行中')).toBeInTheDocument()
    expect(screen.getByText('已确认完成')).toBeInTheDocument()
    expect(screen.getByText('未知待对账')).toBeInTheDocument()
    expect(screen.getByText('已取消')).toBeInTheDocument()
    expect(screen.getByText('明确业务失败')).toBeInTheDocument()
    expect(screen.getAllByText('下单支付流程')).toHaveLength(5)
    expect(screen.getAllByText(/sfref:01234567…89abcdef/)).toHaveLength(5)
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2)
  })

  it('INDETERMINATE 详情：顶部警示条逐字「未知，不显示安全通过」+ 语义词表 + 步骤轨迹明细', async () => {
    await openIndeterminateDetail()
    // 警示条逐字（Alert message 位）
    const alertMessage = document.querySelector(
      '.ant-alert-warning .ant-alert-title',
    )
    expect(alertMessage?.textContent).toBe('未知，不显示安全通过')
    expect(screen.queryByText('UNKNOWN_NOT_CONFIRMED')).not.toBeInTheDocument()
    // 步骤轨迹：action/result/fencing/reason_code 明细（evidence_read 档）已中文化
    expect(screen.getAllByText('步骤预留').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('实例转未知待对账')).toBeInTheDocument()
    expect(
      screen.getByText(/防重入序号=2 · 证据不足或依赖不可用/),
    ).toBeInTheDocument()
    // 实例恢复记录：本例无管理对账事件
    expect(screen.getByText('暂无管理恢复记录。')).toBeInTheDocument()
  })

  it('恢复表单：reason 必填（空值禁用提交且不调 API）', async () => {
    await openIndeterminateDetail()
    const submit = screen.getByRole('button', { name: '提交恢复' })
    expect(submit).toBeDisabled()
    expect(screen.getByText('对账理由必填')).toBeInTheDocument()
    expect(strongFlowApi.resolveInstance).not.toHaveBeenCalled()
  })

  it('恢复提交：三 action 之一 + reason + expected_version 随行', async () => {
    await openIndeterminateDetail()
    fireEvent.click(screen.getByText('确认业务已执行'))
    fireEvent.change(screen.getByLabelText('对账理由'), {
      target: { value: '  源站日志确认支付已执行  ' },
    })
    fireEvent.click(screen.getByRole('button', { name: '提交恢复' }))
    await waitFor(() =>
      expect(strongFlowApi.resolveInstance).toHaveBeenCalledWith('i-1', {
        action: 'CONFIRM_SUCCEEDED',
        reason: '源站日志确认支付已执行',
        expected_version: 2,
      }),
    )
    await waitFor(() =>
      expect(
        vi.mocked(strongFlowApi.getInstance).mock.calls.length,
      ).toBeGreaterThanOrEqual(2),
    )
  })

  it('409 版本冲突：精确提示「版本冲突，请刷新后重试」', async () => {
    vi.mocked(strongFlowApi.resolveInstance).mockRejectedValueOnce(
      new ApiError(
        'strong flow instance version conflict（乐观锁不匹配：实例已被变更，请刷新后重试）',
        'RESOURCE_CONFLICT',
        409,
      ),
    )
    await openIndeterminateDetail()
    fireEvent.change(screen.getByLabelText('对账理由'), {
      target: { value: '对账' },
    })
    fireEvent.click(screen.getByRole('button', { name: '提交恢复' }))
    expect(
      await screen.findByText('版本冲突，请刷新后重试'),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '刷新实例' })).toBeInTheDocument()
  })

  it('409 终态：精确提示「实例已终态」', async () => {
    vi.mocked(strongFlowApi.resolveInstance).mockRejectedValueOnce(
      new ApiError(
        'instance already terminal（CONFIRMED/CANCELLED/FAILED 终态拒绝重复恢复）',
        'RESOURCE_CONFLICT',
        409,
      ),
    )
    await openIndeterminateDetail()
    fireEvent.change(screen.getByLabelText('对账理由'), {
      target: { value: '对账' },
    })
    fireEvent.click(screen.getByRole('button', { name: '提交恢复' }))
    expect(await screen.findByText('实例已终态')).toBeInTheDocument()
  })

  it('权限裁剪：无 manage 时恢复操作区隐藏（实例仍可读）', async () => {
    await openIndeterminateDetail(['api_flow.read'])
    expect(
      screen.queryByRole('button', { name: '提交恢复' }),
    ).not.toBeInTheDocument()
    expect(screen.queryByText('管理恢复（对账）')).not.toBeInTheDocument()
    expect(
      document.querySelector('.ant-alert-warning .ant-alert-title')
        ?.textContent,
    ).toBe('未知，不显示安全通过')
  })
})
