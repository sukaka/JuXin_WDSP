import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import PostureTab from '../PostureTab'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../../../api/applications', () => ({
  applicationsApi: { list: vi.fn() },
}))
vi.mock('../../../api/apiAuthz', () => ({
  apiAuthzApi: {
    listEnforcementReadiness: vi.fn(),
    listObjectRelations: vi.fn(),
    listAuthzConflicts: vi.fn(),
    listNodeAcks: vi.fn(),
    listAuthzAuthorities: vi.fn(),
    getAuthzAuthorityStatus: vi.fn(),
  },
}))

import { applicationsApi } from '../../../api/applications'
import { apiAuthzApi } from '../../../api/apiAuthz'

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

const readinessItems = [
  {
    endpoint_id: 'e1',
    endpoint_key: 'GET /api/v1/tenants/{id}/items',
    object_segment: 'path:3',
    enforcement: 'OBSERVE',
    readiness: 'READY',
    reasons: [],
    checked_at: '2026-10-05T01:00:00Z',
  },
  {
    endpoint_id: 'e2',
    endpoint_key: 'POST /api/v1/orders',
    object_segment: 'path:1',
    enforcement: 'OBSERVE',
    readiness: 'BLOCKED_BY_NODE',
    reasons: ['节点能力自报不足 az/3 或能力清单不可用（含 PROTECT 快照将被能力门 fail-closed 拒绝）'],
    checked_at: '2026-10-05T01:00:00Z',
  },
  {
    endpoint_id: 'e3',
    endpoint_key: 'GET /api/v1/invoices/{id}',
    object_segment: 'path:2',
    enforcement: 'PROTECT',
    readiness: 'PROTECT_ACTIVE',
    reasons: [],
    checked_at: '2026-10-05T01:00:00Z',
  },
]

const relationItems = [
  {
    id: 'rel-1',
    application_id: 'app1',
    object_type: 'order',
    object_ref: 'objref:0a1b',
    principal_id: 'principal:0a1b',
    tenant_id: null,
    relation: 'OWNER' as const,
    source: 'AUTHORITY_SYNC' as const,
    source_id: 'src1',
    status: 'CONFIRMED' as const,
    valid_from: '2026-09-01T00:00:00Z',
    valid_until: null,
    confirmed_by: 'sec',
    confirmed_at: '2026-09-01T00:00:00Z',
    reason: '权威批次同步',
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-10-04T08:00:00Z',
  },
]

const conflictItems = [
  {
    id: 'c1',
    application_id: 'app1',
    object_type: 'order',
    tenant_domain: 'tenant-a',
    object_ref: 'objref:conflict-1',
    principals: ['principal:p1', 'principal:p2'],
    status: 'OPEN',
    first_seen: '2026-10-03T00:00:00Z',
    updated_at: '2026-10-03T01:00:00Z',
  },
]

const nodeAckView = {
  items: [
    {
      node_name: 'gw-1',
      status: 'ACTIVE',
      authz_policy_version: 'ap-20261001',
      authz_watermark: { manual_seq: 7, sources: { src1: 42 } },
      authz_applied_at: '2026-10-05T00:59:00Z',
      last_ack_at: '2026-10-05T01:00:00Z',
      staleness_seconds: 60,
      lease_seconds: 300,
      ack_state: 'FRESH',
    },
    {
      node_name: 'gw-2',
      status: 'ACTIVE',
      authz_policy_version: '',
      authz_watermark: null,
      authz_applied_at: null,
      last_ack_at: '2026-10-05T01:00:05Z',
      staleness_seconds: null,
      lease_seconds: 300,
      ack_state: 'CLOCK_SKEW',
    },
  ],
  max_staleness_seconds: 60,
  management_watermark: { manual_seq: 7, sources: { src1: 42 } },
  generated_at: '2026-10-05T01:01:00Z',
}

const authoritySource = {
  id: 'src1',
  name: 'CRM 权威源',
  status: 'ACTIVE',
  scopes: { tenant_domains: ['tenant-a'], object_types: ['order'] },
  max_event_age_seconds: null,
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
  version: 1,
}

const authorityStatus = {
  source: authoritySource,
  watermark: { last_sequence: 42, last_event_id: 'evt-9', revocation_watermark: 5, gap_from: null, updated_at: '2026-10-04T08:00:00Z' },
  gap_status: 'OK',
  conflicts: [],
  batches: [
    {
      id: 'b1',
      source_id: 'src1',
      mode: 'DELTA',
      status: 'APPLIED',
      counts: { applied: 3, skipped_duplicate: 0, skipped_stale: 0, grants: 2, revokes: 1, conflicts: 0 },
      created_by: null,
      created_at: '2026-10-04T08:00:00Z',
    },
  ],
}

async function renderAndSelectApp(permissions: string[]) {
  useAuthStore.setState({ user: makeUser(permissions), csrfToken: null, initialized: true })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <PostureTab />
      </AntdApp>
    </QueryClientProvider>,
  )
  const applicationSelect = (await screen.findByText('选择应用后查看态势与实断资格')).closest('.ant-select') as HTMLElement
  fireEvent.mouseDown(within(applicationSelect).getByRole('combobox'))
  fireEvent.click(await screen.findByText('商城应用（SHOP）'))
}

describe('PostureTab（NG-AZ-04 §1.1 六要素态势 Tab）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [{ id: 'app1', code: 'SHOP', name: '商城应用' }],
      total: 1,
      page: 1,
      page_size: 100,
    } as never)
    vi.mocked(apiAuthzApi.listEnforcementReadiness).mockResolvedValue({ items: readinessItems })
    vi.mocked(apiAuthzApi.listObjectRelations).mockResolvedValue({ items: relationItems, total: 1, page: 1, page_size: 100 })
    vi.mocked(apiAuthzApi.listAuthzConflicts).mockResolvedValue({ items: conflictItems, total: 1, page: 1, page_size: 20 })
    vi.mocked(apiAuthzApi.listNodeAcks).mockResolvedValue(nodeAckView)
    vi.mocked(apiAuthzApi.listAuthzAuthorities).mockResolvedValue({ items: [authoritySource] })
    vi.mocked(apiAuthzApi.getAuthzAuthorityStatus).mockResolvedValue(authorityStatus)
  })

  it('六要素区块与 readiness 徽章渲染（manage 权限含切换入口，PROTECT 行无入口）', async () => {
    await renderAndSelectApp(['api_authorization.read', 'api_authorization.manage', 'applications.read'])
    // 端点实断资格表格：三态徽章
    expect(await screen.findByText('端点实断资格（readiness 服务端派生）')).toBeInTheDocument()
    expect(screen.getByText('可实断')).toBeInTheDocument()
    expect(screen.getByText('节点未就绪')).toBeInTheDocument()
    expect(screen.getByText('实断中（PROTECT）')).toBeInTheDocument()
    // readiness 徽章 tooltip 固定注明 UNKNOWN 永不阻断
    fireEvent.mouseEnter(screen.getByText('节点未就绪'))
    expect(await screen.findByText(/UNKNOWN 永不阻断/)).toBeInTheDocument()
    // 切换 PROTECT 入口：READY/BLOCKED 两行有，PROTECT 行无
    expect(screen.getAllByRole('button', { name: '切换 PROTECT' })).toHaveLength(2)
    // 来源与最后同步区块：权威来源 + 缺口状态 + 水位
    expect(screen.getByText('关系来源与最后同步')).toBeInTheDocument()
    expect(screen.getByText('CRM 权威源')).toBeInTheDocument()
    expect(screen.getByText('连续')).toBeInTheDocument()
    expect(screen.getByText(/水位 seq=42/)).toBeInTheDocument()
    expect(screen.getByText(/权威同步 1/)).toBeInTheDocument()
    // 冲突区块：对象类型/涉及主体数
    expect(screen.getByText('OPEN 冲突（1）')).toBeInTheDocument()
    expect(screen.getByText('order')).toBeInTheDocument()
    expect(screen.getByText('tenant-a')).toBeInTheDocument()
    // 节点 ACK 区块：FRESH 与时钟偏差如实呈现（含 null 字段占位）
    expect(screen.getByText('gw-1')).toBeInTheDocument()
    expect(screen.getByText('gw-2')).toBeInTheDocument()
    expect(screen.getByText('时钟偏差')).toBeInTheDocument()
    expect(screen.getByText(/管理面向量水位 manual_seq=7/)).toBeInTheDocument()
  })

  it('无 manage 权限：隐藏全部「切换 PROTECT」入口，态势数据仍可读', async () => {
    await renderAndSelectApp(['api_authorization.read', 'applications.read'])
    expect(await screen.findByText('可实断')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '切换 PROTECT' })).not.toBeInTheDocument()
  })

  it('无 applications.read 权限时不调用 applicationsApi.list', () => {
    useAuthStore.setState({ user: makeUser(['api_authorization.read']), csrfToken: null, initialized: true })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <PostureTab />
        </AntdApp>
      </QueryClientProvider>,
    )
    expect(applicationsApi.list).not.toHaveBeenCalled()
  })
})
