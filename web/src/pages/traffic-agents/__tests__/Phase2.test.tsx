import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import TrafficAgentsPage from '../TrafficAgentsPage'
import PolicyPanel from '../PolicyPanel'
import { HEALTH_REASON_META } from '../meta'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

/* Phase 2：健康分列渲染、策略版本历史与回滚操作（PHASE2 契约 §3/§4） */

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secops',
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

const SUMMARY = { total: 2, online: 1, offline: 0, degraded: 1, disabled: 0 }

const AGENTS = {
  items: [
    {
      agent_id: 'a3c98f51-0000-4000-8000-000000000001',
      hostname: 'web-prod-01',
      ip: '10.0.1.10',
      os: 'Rocky Linux 9',
      kernel: '5.14.0',
      arch: 'x86_64',
      version: '1.0.0',
      status: 'ONLINE',
      disabled: false,
      last_seen: new Date(Date.now() - 10_000).toISOString(),
      last_metrics: { cpu_percent: 95, memory_mb: 128.5 },
      config_version: 2,
      applied_config_version: 2,
      clock_offset_ms: 6000,
      health_score: 60,
      health_reasons: ['cpu_over_limit', 'clock_drift'],
      created_at: '2026-08-01T00:00:00Z',
    },
    {
      agent_id: 'a3c98f51-0000-4000-8000-000000000002',
      hostname: 'web-prod-02',
      ip: '10.0.1.11',
      os: 'Rocky Linux 9',
      kernel: '5.14.0',
      arch: 'x86_64',
      version: '1.0.0',
      status: 'DEGRADED',
      disabled: false,
      last_seen: new Date(Date.now() - 20_000).toISOString(),
      last_metrics: null,
      config_version: 1,
      applied_config_version: 1,
      clock_offset_ms: null,
      health_score: 90,
      health_reasons: ['status_degraded'],
      created_at: '2026-08-01T00:00:00Z',
    },
  ],
  total: 2,
}

const AGENT_DETAIL = {
  ...AGENTS.items[0],
  interfaces: [],
  policy_binding: null,
}

const EVENTS = { items: [], total: 0 }

const POLICY = {
  id: 'pol-1',
  name: 'production-web',
  version: 3,
  config: {
    name: 'production-web',
    capture: { interfaces: ['eth0'], direction: 'both', protocols: ['tcp'], ports: [80, 443] },
    output: { mode: 'FLOW' },
    limits: { outbound_mbps: 100 },
  },
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-20T00:00:00Z',
}

const POLICIES = { items: [POLICY], total: 1 }

const VERSIONS = {
  items: [
    { version: 3, config: POLICY.config, created_by: 'secops', created_at: '2026-08-20T00:00:00Z', current: true },
    { version: 2, config: POLICY.config, created_by: 'secops', created_at: '2026-08-10T00:00:00Z', current: false },
    { version: 1, config: POLICY.config, created_by: 'admin', created_at: '2026-08-01T00:00:00Z', current: false },
  ],
  total: 3,
}

function mockFetch() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    const empty = () => Promise.resolve(new Response(null, { status: 204 }))
    if (url.includes('/traffic/policies/pol-1/versions')) return ok(VERSIONS)
    if (url.includes('/traffic/policies/pol-1/rollback') && method === 'POST') {
      return ok({ ...POLICY, version: 4 })
    }
    if (url.includes('/traffic/policies')) return ok(POLICIES)
    if (url.includes('/traffic/agents/summary')) return ok(SUMMARY)
    if (/\/traffic\/agents\/[^/]+\/events/.test(url)) return ok(EVENTS)
    if (/\/traffic\/agents\/[^/]+$/.test(url.split('?')[0])) {
      if (method === 'DELETE') return empty()
      return ok(AGENT_DETAIL)
    }
    if (url.includes('/traffic/agents')) return ok(AGENTS)
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderWithProviders(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>{node}</AntdApp>
    </QueryClientProvider>,
  )
}

describe('Phase 2：健康分列与详情', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['traffic.agents.view', 'traffic.agents.manage']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表页渲染健康分列：分档 Badge 与扣分项 Tooltip', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<TrafficAgentsPage />)

    const row = (await screen.findByText('web-prod-01')).closest('tr')!
    // 健康分列：60 分 Badge（多位数渲染为 scroll-number 拆字，按 class 定位）
    const badge = row.querySelector('.ant-badge-count')!
    expect(badge.textContent).toBe('60')

    // Tooltip 展示主要扣分项（原因码 → 中文文案）
    fireEvent.mouseOver(badge.closest('.ant-badge')!)
    expect(await screen.findByText(/CPU 超过阈值/)).toBeInTheDocument()
    expect(screen.getByText(/时钟偏移超阈/)).toBeInTheDocument()

    // 第二行 90 分
    const row2 = screen.getByText('web-prod-02').closest('tr')!
    expect(row2.querySelector('.ant-badge-count')!.textContent).toBe('90')
  })

  it('详情抽屉展示健康分、扣分项明细与时钟偏移', { timeout: 20000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<TrafficAgentsPage />)
    await screen.findByText('web-prod-01')

    const row = screen.getByText('web-prod-01').closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))

    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('健康分')).toBeInTheDocument()
    expect(within(drawer).getByText(/CPU 超过阈值；时钟偏移超阈/)).toBeInTheDocument()
    expect(within(drawer).getByText('+6.0s（偏慢）')).toBeInTheDocument()
    expect(HEALTH_REASON_META.status_error).toBe('自报状态异常')
  })
})

describe('Phase 2：策略版本历史与回滚', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('版本历史：倒序列表、当前版本标记、回滚 Popconfirm 调 rollback 接口', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<PolicyPanel canManage={true} />)

    await screen.findByText('production-web')
    fireEvent.click(screen.getByRole('button', { name: /历\s*史/ }))

    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('版本历史：production-web')).toBeInTheDocument()
    // 倒序 v3 → v2 → v1，当前版本标记
    expect(await within(dialog).findByText('当前版本')).toBeInTheDocument()
    expect(within(dialog).getByText('生效中')).toBeInTheDocument()

    // 对 v2 执行回滚（Popconfirm 二次确认）
    const v2row = within(dialog).getByText('v2').closest('tr')!
    fireEvent.click(within(v2row).getByRole('button', { name: /回\s*滚/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认回滚' }))

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/traffic/policies/pol-1/rollback') &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call![1]?.body))).toEqual({ version: 2 })
    })
    expect(await screen.findByText('已回滚并生成新版本 v4')).toBeInTheDocument()
  })

  it('仅 view 权限：版本历史可读但无回滚操作', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<PolicyPanel canManage={false} />)

    await screen.findByText('production-web')
    fireEvent.click(screen.getByRole('button', { name: /历\s*史/ }))

    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('当前版本')).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: /回\s*滚/ })).not.toBeInTheDocument()
  })
})
