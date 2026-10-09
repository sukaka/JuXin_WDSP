import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ProtectWizard from '../ProtectWizard'
import { ApiError } from '../../../api/client'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../../../api/apiAuthz', () => ({
  apiAuthzApi: {
    listEnforcementReadiness: vi.fn(),
    evaluateEnforcementImpact: vi.fn(),
    signEnforcementConfirmation: vi.fn(),
  },
}))
vi.mock('../../../api/apiSecurity', () => ({
  apiObjectModelsApi: {
    list: vi.fn(),
    patch: vi.fn(),
  },
}))
vi.mock('../../../api/gatewayConfig', () => ({
  gatewayConfigApi: { publish: vi.fn() },
  publishTasksApi: { get: vi.fn() },
}))

import { apiAuthzApi } from '../../../api/apiAuthz'
import { apiObjectModelsApi } from '../../../api/apiSecurity'
import { gatewayConfigApi, publishTasksApi } from '../../../api/gatewayConfig'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
    display_name: '张磊',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

const modelRow = {
  id: 'm1',
  endpoint_id: 'e1',
  endpoint_key: 'GET /api/v1/tenants/{id}/items',
  application_name: '商城',
  application_domain: '',
  object_segment: 'path:3',
  identifier_type: 'numeric',
  example_hash: 'ab12cd',
  sample_count: 10,
  first_seen: '2026-09-01T00:00:00Z',
  last_seen: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
  publishable: true,
  required_relation: 'OWNER',
  owner_exclusive: true,
  on_lease_expired: 'strict',
  enforcement: 'OBSERVE',
  enforcement_owner: '',
  evidence_source: '',
  on_unknown: 'ALLOW_UNKNOWN',
}

const notPublishableRow = { ...modelRow, id: 'm2', endpoint_id: 'e2', endpoint_key: 'POST /api/v1/orders', object_segment: 'path:1', publishable: false, owner_exclusive: false }
const protectRow = { ...modelRow, id: 'm3', endpoint_id: 'e3', endpoint_key: 'GET /api/v1/invoices/{id}', object_segment: 'path:2', enforcement: 'PROTECT' }

const readinessItems = [
  { endpoint_id: 'e1', endpoint_key: modelRow.endpoint_key, object_segment: 'path:3', enforcement: 'OBSERVE', readiness: 'READY', reasons: [], checked_at: '2026-10-05T01:00:00Z' },
  { endpoint_id: 'e2', endpoint_key: 'POST /api/v1/orders', object_segment: 'path:1', enforcement: 'OBSERVE', readiness: 'NOT_PUBLISHABLE', reasons: ['publishable=false（发布资格未声明）'], checked_at: '2026-10-05T01:00:00Z' },
  { endpoint_id: 'e3', endpoint_key: 'GET /api/v1/invoices/{id}', object_segment: 'path:2', enforcement: 'PROTECT', readiness: 'PROTECT_ACTIVE', reasons: [], checked_at: '2026-10-05T01:00:00Z' },
]

const impactReady = {
  endpoint_id: 'e1',
  endpoint_key: modelRow.endpoint_key,
  object_segment: 'path:3',
  window_days: 7,
  evaluated_at: '2026-10-05T02:00:00Z',
  observe_violation_count: 12,
  unknown_total: 34,
  unknown_by_reason: [{ reason_code: 'AUTHZ-IDENTITY-001', count: 20 }],
  distinct_principal_count: 5,
  verified_violation_count: 0,
  readiness: 'READY',
  readiness_reasons: [],
  confirm_token: 'token-1',
  confirm_token_expires_at: new Date(Date.now() + 15 * 60_000).toISOString(),
}

const confirmation = {
  id: 'cf1',
  confirm_token: 'token-1',
  application_id: 'app1',
  endpoint_id: 'e1',
  object_segment: 'path:3',
  window_days: 7,
  impact_snapshot: {},
  confirm_text: '（确认文案 v1）',
  enforcement_owner: '张磊',
  evidence_source: 'MANUAL_CONFIRMED',
  on_unknown: 'ALLOW_UNKNOWN',
  confirmed_by: 'u1',
  confirmed_by_name: '张磊',
  created_at: '2026-10-05T02:00:00Z',
  token_expires_at: impactReady.confirm_token_expires_at,
  signed_at: '2026-10-05T02:05:00Z',
  consumed_at: null,
  consumed_audit_id: '',
}

function makeTask(id: string, status: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    task_type: 'PUBLISH' as const,
    status,
    requested_by: 'u1',
    requested_at: '2026-10-05T02:10:00Z',
    started_at: '2026-10-05T02:10:00Z',
    finished_at: null,
    target_version_id: null,
    current_step: status === 'SUCCESS' ? '完成' : '发布到网关',
    progress: status === 'SUCCESS' || status === 'FAILED' ? 100 : 40,
    result_summary: '',
    failure_code: '',
    failure_message: '',
    request_id: 'r1',
    ...extra,
  }
}

const ALL_PERMS = ['api_authorization.read', 'api_authorization.manage', 'gateway_configs.publish']

function renderWizard(props: Partial<Parameters<typeof ProtectWizard>[0]> = {}, permissions = ALL_PERMS) {
  useAuthStore.setState({ user: makeUser(permissions), csrfToken: null, initialized: true })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ProtectWizard open onClose={() => undefined} applicationId="app1" {...props} />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 从 preset 入口走完 影响评估→四要素→签署，到达第 5 步「提交与结果」 */
async function walkToSubmit() {
  await waitFor(() => expect(vi.mocked(apiAuthzApi.evaluateEnforcementImpact)).toHaveBeenCalledWith({ endpoint_id: 'e1', window_days: 7, object_segment: 'path:3' }))
  expect(await screen.findByText('切换后将被 403（近似）')).toBeInTheDocument()
  expect(screen.getByText('这些请求切换后将被实断')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '下一步' }))
  // 四要素
  const ownerInput = await screen.findByLabelText('业务负责人（enforcement_owner）')
  fireEvent.change(ownerInput, { target: { value: '张磊' } })
  fireEvent.click(screen.getByRole('button', { name: '下一步' }))
  // 确认单签署：冻结文案占位符已替换
  expect(await screen.findByText(/近 7 天观测违规 12 次、涉及主体 5 个；我（张磊）作为业务负责人确认承担实断影响。（确认文案 v1）/)).toBeInTheDocument()
  expect(screen.getByText(/当前为单人切换模式/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('checkbox', { name: '我已阅读并确认' }))
  fireEvent.click(screen.getByRole('button', { name: '提交签署' }))
  await waitFor(() =>
    expect(vi.mocked(apiAuthzApi.signEnforcementConfirmation)).toHaveBeenCalledWith('token-1', {
      enforcement_owner: '张磊',
      evidence_source: 'MANUAL_CONFIRMED',
      on_unknown: 'ALLOW_UNKNOWN',
    }),
  )
  expect(await screen.findByText(/已签署（signed_at 已落库）/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: '下一步：提交切换' }))
  expect(await screen.findByRole('button', { name: '确认提交切换' })).toBeInTheDocument()
}

describe('ProtectWizard（NG-AZ-04 §1.5 五步状态机）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [modelRow], total: 1, page: 1, page_size: 100 })
    vi.mocked(apiAuthzApi.listEnforcementReadiness).mockResolvedValue({ items: readinessItems })
    vi.mocked(apiAuthzApi.evaluateEnforcementImpact).mockResolvedValue(impactReady)
    vi.mocked(apiAuthzApi.signEnforcementConfirmation).mockResolvedValue(confirmation)
    vi.mocked(apiObjectModelsApi.patch).mockResolvedValue({ ...modelRow, enforcement: 'PROTECT' })
    let publishSeq = 0
    vi.mocked(gatewayConfigApi.publish).mockImplementation(() => {
      publishSeq += 1
      return Promise.resolve(makeTask(`task-${publishSeq}`, 'PUBLISHING'))
    })
    // 轮询即达 SUCCESS 终态（终态停轮询）；失败路径由各用例覆盖本 mock
    vi.mocked(publishTasksApi.get).mockImplementation((id: string) => Promise.resolve(makeTask(id, 'SUCCESS')))
  })

  it('preset 入口全流：评估→四要素→签署→PATCH 携带 confirm_token 与四要素→发布 SUCCESS 已生效', async () => {
    renderWizard({ preset: { endpoint_id: 'e1', object_segment: 'path:3' } })
    await walkToSubmit()
    fireEvent.click(screen.getByRole('button', { name: '确认提交切换' }))
    await waitFor(() =>
      expect(vi.mocked(apiObjectModelsApi.patch)).toHaveBeenCalledWith('m1', {
        enforcement: 'PROTECT',
        enforcement_owner: '张磊',
        evidence_source: 'MANUAL_CONFIRMED',
        on_unknown: 'ALLOW_UNKNOWN',
        confirm_token: 'token-1',
      }),
    )
    await waitFor(() => expect(vi.mocked(gatewayConfigApi.publish)).toHaveBeenCalled())
    expect(await screen.findByText(/已生效：端点已进入 PROTECT（实断）/)).toBeInTheDocument()
    expect(screen.getByText('授权决策列表')).toBeInTheDocument()
  })

  it('PATCH 400（token 过期）：回影响评估重新签发，表单保留', async () => {
    vi.mocked(apiObjectModelsApi.patch).mockRejectedValueOnce(new ApiError('confirm_token 已过期', 'INVALID_ARGUMENT', 400))
    renderWizard({ preset: { endpoint_id: 'e1', object_segment: 'path:3' } })
    await walkToSubmit()
    fireEvent.click(screen.getByRole('button', { name: '确认提交切换' }))
    await waitFor(() => expect(vi.mocked(apiObjectModelsApi.patch)).toHaveBeenCalled())
    // 回到第 2 步（影响评估）并自动重新评估签发新 token
    expect(await screen.findByText('评估端点：')).toBeInTheDocument()
    await waitFor(() => expect(vi.mocked(apiAuthzApi.evaluateEnforcementImpact)).toHaveBeenCalledTimes(2))
  })

  it('PATCH 400（四要素缺失）：回四要素步', async () => {
    vi.mocked(apiObjectModelsApi.patch).mockRejectedValueOnce(
      new ApiError('切换 PROTECT 必须同请求提供 enforcement_owner（业务负责人标识）', 'INVALID_ARGUMENT', 400),
    )
    renderWizard({ preset: { endpoint_id: 'e1', object_segment: 'path:3' } })
    await walkToSubmit()
    fireEvent.click(screen.getByRole('button', { name: '确认提交切换' }))
    await waitFor(() => expect(vi.mocked(apiObjectModelsApi.patch)).toHaveBeenCalled())
    expect(await screen.findByLabelText('业务负责人（enforcement_owner）')).toBeInTheDocument()
  })

  it('发布 FAILED（能力门 CAP_MISSING）：如实展示「配置与生效不一致」+ 缺口明细，快捷切回 OBSERVE 免 token', async () => {
    let publishSeq = 0
    const taskIndex: Record<string, ReturnType<typeof makeTask>> = {}
    vi.mocked(gatewayConfigApi.publish).mockImplementation(() => {
      publishSeq += 1
      const id = `task-${publishSeq}`
      taskIndex[id] = publishSeq === 1
        ? makeTask(id, 'FAILED', { failure_code: 'CAP_MISSING', failure_message: 'CAP_MISSING:detectors.authzdecide(required=az/3,actual=az/2)' })
        : makeTask(id, 'PUBLISHING')
      return Promise.resolve(taskIndex[id])
    })
    vi.mocked(publishTasksApi.get).mockImplementation((id: string) => {
      const t = taskIndex[id]
      if (!t) return Promise.resolve(makeTask(id, 'SUCCESS'))
      // 首个任务保持 FAILED 终态；切回后的新任务 SUCCESS
      return Promise.resolve(t.status === 'FAILED' ? t : makeTask(id, 'SUCCESS'))
    })
    renderWizard({ preset: { endpoint_id: 'e1', object_segment: 'path:3' } })
    await walkToSubmit()
    fireEvent.click(screen.getByRole('button', { name: '确认提交切换' }))
    // 「配置与生效不一致」+ CAP_MISSING 缺口明细完整展示，不自动回退
    expect(await screen.findByText('配置与生效不一致')).toBeInTheDocument()
    expect(screen.getByText(/detectors\.authzdecide\(required=az\/3,actual=az\/2\)/)).toBeInTheDocument()
    expect(screen.getByText(/能力门缺口（CAP_MISSING/)).toBeInTheDocument()
    // 快捷切回 OBSERVE：PATCH 不携带 confirm_token
    fireEvent.click(screen.getByRole('button', { name: '立即切回 OBSERVE' }))
    fireEvent.click(await screen.findByRole('button', { name: '立即切回' }))
    await waitFor(() => expect(vi.mocked(apiObjectModelsApi.patch)).toHaveBeenCalledWith('m1', { enforcement: 'OBSERVE' }))
    expect(await screen.findByText('已切回 OBSERVE')).toBeInTheDocument()
  })

  it('无 manage 权限：影响评估不签发 token，下一步禁用并如实提示', async () => {
    vi.mocked(apiAuthzApi.evaluateEnforcementImpact).mockResolvedValue({
      ...impactReady,
      confirm_token: undefined,
      confirm_token_expires_at: undefined,
    } as never)
    renderWizard({ preset: { endpoint_id: 'e1', object_segment: 'path:3' } }, ['api_authorization.read'])
    expect(await screen.findByText(/未签发签署令牌/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '下一步' })).toBeDisabled()
  })

  it('第 1 步选端点：NOT_PUBLISHABLE 与已 PROTECT 行禁用并注明缺项', async () => {
    vi.mocked(apiObjectModelsApi.list).mockResolvedValue({ items: [modelRow, notPublishableRow, protectRow], total: 3, page: 1, page_size: 100 })
    renderWizard()
    expect(await screen.findByText('POST /api/v1/orders')).toBeInTheDocument()
    expect(screen.getByText('资格不齐')).toBeInTheDocument()
    expect(screen.getByText('实断中（PROTECT）')).toBeInTheDocument()
    expect(screen.getByText(/publishable=false（发布资格未声明）/)).toBeInTheDocument()
    const radios = screen.getAllByRole('radio')
    // 行序：m1 READY（可选）/ m2 NOT_PUBLISHABLE（禁用）/ m3 PROTECT（禁用）
    expect(radios[0]).not.toBeDisabled()
    expect(radios[1]).toBeDisabled()
    expect(radios[2]).toBeDisabled()
    fireEvent.click(radios[0])
    expect(screen.getByRole('button', { name: '下一步' })).not.toBeDisabled()
  })
})
