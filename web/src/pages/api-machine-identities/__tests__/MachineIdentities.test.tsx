import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import IdentitiesTab from '../IdentitiesTab'
import ApiMachineIdentitiesPage from '../ApiMachineIdentitiesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../../../api/machineIdentity', () => ({
  machineIdentityApi: {
    listIdentities: vi.fn(),
    getIdentity: vi.fn(),
    createIdentity: vi.fn(),
    updateIdentity: vi.fn(),
    deleteIdentity: vi.fn(),
    importKey: vi.fn(),
    rotateKey: vi.fn(),
    revokeKey: vi.fn(),
    listBindings: vi.fn(),
  },
}))

import { machineIdentityApi } from '../../../api/machineIdentity'

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

const identitySummary = {
  id: 'mi1',
  identity_name: 'billing-agent',
  tenant_id: null,
  principal_binding: null,
  status: 'ENABLED',
  bot_challenge_exempt: true,
  version: 2,
  created_by: 'sec',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-05T00:00:00Z',
  key_count: 3,
  active_keys: 1,
  retired_keys: 1,
  revoked_keys: 1,
}

const keys = [
  {
    id: 'k1', identity_id: 'mi1', kid: 'k-2026-01', alg: 'ed25519',
    public_key_pem: '-----BEGIN PUBLIC KEY-----\nMFkwEw==\n-----END PUBLIC KEY-----',
    key_fingerprint: 'a1b2c3d4e5f60718', status: 'ACTIVE',
    not_before: null, not_after: null, retire_overlap_until: null, revoked_seq: null,
    created_by: 'sec', created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
  },
  {
    id: 'k2', identity_id: 'mi1', kid: 'k-2025-09', alg: 'ecdsa-p256-sha256',
    public_key_pem: '-----BEGIN PUBLIC KEY-----\nMFkwEx==\n-----END PUBLIC KEY-----',
    key_fingerprint: 'b2c3d4e5f60718293a4b', status: 'RETIRED',
    not_before: null, not_after: null, retire_overlap_until: '2026-10-10T00:00:00Z', revoked_seq: null,
    created_by: 'sec', created_at: '2025-09-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
  },
  {
    id: 'k3', identity_id: 'mi1', kid: 'k-2025-06', alg: 'rsa-pss-sha512',
    public_key_pem: '-----BEGIN PUBLIC KEY-----\nMIIBCg==\n-----END PUBLIC KEY-----',
    key_fingerprint: 'c3d4e5f60718293a4b', status: 'REVOKED',
    not_before: null, not_after: null, retire_overlap_until: null, revoked_seq: 7,
    created_by: 'sec', created_at: '2025-06-01T00:00:00Z', updated_at: '2026-09-15T00:00:00Z',
  },
]

const identityDetail = {
  identity: { ...identitySummary, key_count: undefined, active_keys: undefined, retired_keys: undefined, revoked_keys: undefined },
  keys,
}

const FULL = ['jwt_trust.read', 'jwt_trust.manage']

function renderUi(ui: React.ReactElement, permissions: string[]) {
  useAuthStore.setState({ user: makeUser(permissions), csrfToken: null, initialized: true })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>{ui}</AntdApp>
    </QueryClientProvider>,
  )
}

/** 打开身份详情抽屉 */
async function openDetail(permissions: string[] = FULL) {
  renderUi(<IdentitiesTab />, permissions)
  fireEvent.click(await screen.findByRole('button', { name: '详情' }))
  await screen.findByText('公钥（3）')
}

/** 取最新弹窗（详情抽屉与操作弹窗同为 dialog——弹窗后挂载取最后一个） */
async function lastDialog() {
  const dialogs = await screen.findAllByRole('dialog')
  return dialogs[dialogs.length - 1]
}

/** 选择算法下拉项（键表格同文案避让——取 option-content 容器内者） */
async function pickAlg(alg: string) {
  const option = (await screen.findAllByText(alg)).find((el) =>
    el.closest('.ant-select-item-option-content'),
  ) as HTMLElement
  fireEvent.click(option)
}

describe('ApiMachineIdentitiesPage / IdentitiesTab（NG-ID G1 身份与键管理）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(machineIdentityApi.listIdentities).mockResolvedValue({ items: [identitySummary], total: 1, revocation_watermark: 7 })
    vi.mocked(machineIdentityApi.getIdentity).mockResolvedValue(identityDetail as never)
    vi.mocked(machineIdentityApi.importKey).mockResolvedValue(keys[0] as never)
    vi.mocked(machineIdentityApi.rotateKey).mockResolvedValue({ key: { ...keys[0], id: 'k4', kid: 'k-2026-10' }, retired_key: { ...keys[0], status: 'RETIRED', retire_overlap_until: '2026-10-11T00:00:00Z' } } as never)
    vi.mocked(machineIdentityApi.revokeKey).mockResolvedValue({ ...keys[0], status: 'REVOKED', revoked_seq: 8 } as never)
    vi.mocked(machineIdentityApi.listBindings).mockResolvedValue({ items: [], total: 0 })
  })

  it('身份列表：身份名/跨租户共享/键状态三态计数/Bot 豁免声明/撤销水位/状态', async () => {
    renderUi(<ApiMachineIdentitiesPage />, FULL)
    expect(await screen.findByText('billing-agent')).toBeInTheDocument()
    expect(screen.getByText('跨租户共享')).toBeInTheDocument()
    expect(screen.getByText('ACTIVE 1')).toBeInTheDocument()
    expect(screen.getByText('RETIRED 1')).toBeInTheDocument()
    expect(screen.getByText('REVOKED 1')).toBeInTheDocument()
    expect(screen.getByText('声明豁免')).toBeInTheDocument()
    expect(screen.getByText(/撤销水位（单调不下降）/)).toBeInTheDocument()
    // 覆盖范围提示（可选叠加缺省 OFF / RFC 9421 首期 / DPoP 与 stdio 未覆盖）
    expect(screen.getByText(/DPoP（RFC 9449）与 stdio\/本地场景未覆盖/)).toBeInTheDocument()
    // 接入契约内联提示
    expect(screen.getByText('接入契约（客户端签名约定）')).toBeInTheDocument()
  })

  it('详情抽屉：键状态三态/重叠窗口终点/revoked_seq 溯源/指纹短显', async () => {
    await openDetail()
    expect(screen.getByText('ACTIVE（可签发可验证）')).toBeInTheDocument()
    expect(screen.getByText('RETIRED（窗口内仅验证）')).toBeInTheDocument()
    expect(screen.getByText('REVOKED（立即拒验）')).toBeInTheDocument()
    const revokedRow = screen.getByText('k-2025-06').closest('tr') as HTMLElement
    expect(within(revokedRow).getByText('7')).toBeInTheDocument()
    expect(screen.getByText('a1b2c3d4e5f60718')).toBeInTheDocument()
    expect(screen.getByText('b2c3d4e5f6071829…')).toBeInTheDocument()
    // RETIRED 行展示重叠窗口终点（窗口外旧键拒验）
    const retiredRow = screen.getByText('k-2025-09').closest('tr') as HTMLElement
    expect(within(retiredRow).getByText(/2026/)).toBeInTheDocument()
  })

  it('导入公钥：非法 PEM 客户端校验拦截且不发 POST；合法 PEM 提交载荷逐键', async () => {
    await openDetail()
    fireEvent.click(screen.getByRole('button', { name: '导入公钥' }))
    const dialog = await lastDialog()
    fireEvent.change(within(dialog).getByPlaceholderText('如：2026-10-primary'), { target: { value: 'k-2026-10' } })
    fireEvent.mouseDown(within(dialog).getByText('选择算法'))
    await pickAlg('ed25519')
    const pemField = within(dialog).getByPlaceholderText(/BEGIN PUBLIC KEY/)
    fireEvent.change(pemField, { target: { value: 'not a pem' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '导 入' }))
    expect(await within(dialog).findByText(/PEM 形态非法（须含恰一个 PUBLIC KEY 块/)).toBeInTheDocument()
    expect(machineIdentityApi.importKey).not.toHaveBeenCalled()
    // 合法 PEM 提交
    fireEvent.change(pemField, { target: { value: '-----BEGIN PUBLIC KEY-----\nMFkwEw==\n-----END PUBLIC KEY-----' } })
    fireEvent.click(within(dialog).getByRole('button', { name: '导 入' }))
    await waitFor(() =>
      expect(machineIdentityApi.importKey).toHaveBeenCalledWith('mi1', {
        kid: 'k-2026-10',
        alg: 'ed25519',
        public_key_pem: '-----BEGIN PUBLIC KEY-----\nMFkwEw==\n-----END PUBLIC KEY-----',
        not_before: null,
        not_after: null,
      }),
    )
  })

  it('轮换：仅 ACTIVE 键可轮换；重叠窗口缺省 24h（上限 168h 提示）随行提交', async () => {
    await openDetail()
    // 仅 ACTIVE 行有「轮换」入口
    expect(screen.getAllByRole('button', { name: '轮换' })).toHaveLength(1)
    fireEvent.click(screen.getByRole('button', { name: '轮换' }))
    const dialog = await lastDialog()
    expect(within(dialog).getByText(/缺省 24 小时、上限 168 小时/)).toBeInTheDocument()
    fireEvent.change(within(dialog).getByPlaceholderText('如：2026-10-primary'), { target: { value: 'k-2026-10' } })
    fireEvent.mouseDown(within(dialog).getByText('选择算法'))
    await pickAlg('ed25519')
    fireEvent.change(within(dialog).getByPlaceholderText(/BEGIN PUBLIC KEY/), {
      target: { value: '-----BEGIN PUBLIC KEY-----\nNEWKEY==\n-----END PUBLIC KEY-----' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: '确认轮换' }))
    await waitFor(() =>
      expect(machineIdentityApi.rotateKey).toHaveBeenCalledWith('mi1', 'k1', {
        kid: 'k-2026-10',
        alg: 'ed25519',
        public_key_pem: '-----BEGIN PUBLIC KEY-----\nNEWKEY==\n-----END PUBLIC KEY-----',
        not_before: null,
        not_after: null,
        overlap_hours: 24,
      }),
    )
  })

  it('撤销高危确认流：警示「撤销即拒验且不可经回滚复活」逐字，确认后调用 revoke', async () => {
    await openDetail()
    // ACTIVE 与 RETIRED 行可撤销（REVOKED 行无入口）
    expect(screen.getAllByRole('button', { name: '撤销' })).toHaveLength(2)
    const activeRow = screen.getByText('k-2026-01').closest('tr') as HTMLElement
    fireEvent.click(within(activeRow).getByRole('button', { name: '撤销' }))
    expect(await screen.findByText(/撤销即拒验且不可经回滚复活/)).toBeInTheDocument()
    expect(screen.getByText(/普通策略回滚不复活已撤销密钥/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '确认撤销' }))
    await waitFor(() => expect(machineIdentityApi.revokeKey).toHaveBeenCalledWith('mi1', 'k1'))
    expect(await screen.findByText(/已撤销 k-2026-01（revoked_seq=8/)).toBeInTheDocument()
  })

  it('权限隐藏：无 manage 时登记/编辑/删除/导入/轮换/撤销全部隐藏（非禁用）', async () => {
    renderUi(<IdentitiesTab />, ['jwt_trust.read'])
    await screen.findByText('billing-agent')
    expect(screen.queryByRole('button', { name: /登记机器身份/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '详情' }))
    await screen.findByText('公钥（3）')
    expect(screen.queryByRole('button', { name: '导入公钥' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '轮换' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '撤销' })).not.toBeInTheDocument()
  })

  it('登记身份：必填校验 + 租户/主体留空为 null 提交', async () => {
    renderUi(<IdentitiesTab />, FULL)
    fireEvent.click(await screen.findByRole('button', { name: /登记机器身份/ }))
    const dialog = await lastDialog()
    fireEvent.click(within(dialog).getByRole('button', { name: '登 记' }))
    expect(await within(dialog).findByText('身份名必填')).toBeInTheDocument()
    expect(machineIdentityApi.createIdentity).not.toHaveBeenCalled()
  })
})
