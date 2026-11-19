import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import TrafficAgentsPage from '../TrafficAgentsPage'
import CaptureOverridesPanel from '../CaptureOverridesPanel'
import PolicyPanel from '../PolicyPanel'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

/* Phase 4：智能采集前端（PHASE4 契约 §2/§3/§4）
 * —— 定向采集规则列表/新增/删除/过期灰显/权限显隐、背压降级帽 Tag、策略采样率输入 */

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

const AGENT_ID = 'a3c98f51-0000-4000-8000-000000000001'

const SUMMARY = { total: 1, online: 1, offline: 0, degraded: 0, disabled: 0 }

const AGENTS = {
  items: [
    {
      agent_id: AGENT_ID,
      hostname: 'web-prod-01',
      ip: '10.0.1.10',
      os: 'Rocky Linux 9',
      kernel: '5.14.0',
      arch: 'x86_64',
      version: '1.0.0',
      status: 'DEGRADED',
      disabled: false,
      last_seen: new Date(Date.now() - 10_000).toISOString(),
      last_metrics: null,
      config_version: 2,
      applied_config_version: 2,
      clock_offset_ms: null,
      health_score: 85,
      health_reasons: ['status_degraded'],
      created_at: '2026-08-01T00:00:00Z',
    },
  ],
  total: 1,
}

/** 详情：last_metrics 含 backpressure_cap/backpressure_events（Phase 4 §3 背压降级） */
const AGENT_DETAIL = {
  ...AGENTS.items[0],
  interfaces: [],
  policy_binding: null,
  last_metrics: { cpu_percent: 12, queue_depth: 7200, backpressure_cap: 'L1', backpressure_events: 2 },
}

const EVENTS = { items: [], total: 0 }

/** 定向采集规则：一条未过期（多字段 AND）+ 一条已过期 */
const OVERRIDES = {
  items: [
    {
      id: 'ov-1',
      agent_id: AGENT_ID,
      match: {
        dst_ip: '10.10.20.30',
        dst_port: 8443,
        host: 'api.example.com',
        uri_prefix: '/api/payment',
      },
      capture_level: 'L2',
      note: '支付链路排障',
      created_by: 'secops',
      created_at: '2026-08-20T00:00:00Z',
      expires_at: new Date(Date.now() + 25 * 60_000).toISOString(),
      active: true,
    },
    {
      id: 'ov-2',
      agent_id: AGENT_ID,
      match: { host: 'old.example.com' },
      capture_level: 'L3',
      note: '',
      created_by: 'admin',
      created_at: '2026-08-01T00:00:00Z',
      expires_at: new Date(Date.now() - 60_000).toISOString(),
      active: false,
    },
  ],
  total: 2,
}

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

function mockFetch() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    const ok = (data: unknown, status = 200) =>
      Promise.resolve(jsonResponse(status, { code: 'SUCCESS', message: 'ok', data }))
    const empty = () => Promise.resolve(new Response(null, { status: 204 }))
    if (/\/traffic\/agents\/[^/]+\/overrides/.test(url)) {
      if (method === 'POST') {
        const body = JSON.parse(String(init?.body)) as Record<string, unknown>
        return ok(
          {
            id: 'ov-new',
            agent_id: AGENT_ID,
            ...body,
            created_by: 'secops',
            created_at: '2026-09-02T00:00:00Z',
            expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
            active: true,
          },
          201,
        )
      }
      if (method === 'DELETE') return empty()
      return ok(OVERRIDES)
    }
    if (url.includes('/traffic/policies/pol-1') && method === 'PUT') return ok(POLICY)
    if (url.includes('/traffic/policies')) return ok(POLICIES)
    if (url.includes('/traffic/agents/summary')) return ok(SUMMARY)
    if (/\/traffic\/agents\/[^/]+\/http-events/.test(url)) return ok(EVENTS)
    if (/\/traffic\/agents\/[^/]+\/events/.test(url)) return ok(EVENTS)
    if (/\/traffic\/agents\/[^/]+$/.test(url.split('?')[0])) return ok(AGENT_DETAIL)
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

describe('Phase 4：定向采集规则面板', () => {
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

  it('规则列表渲染：匹配条件可读化 / 目标等级 / 剩余有效期 / 创建人 / 备注', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<CaptureOverridesPanel agentId={AGENT_ID} enabled canManage />)

    // 匹配条件可读化（多字段 AND 逐项展示）
    expect(await screen.findByText('目标 IP=10.10.20.30')).toBeInTheDocument()
    expect(screen.getByText('目标端口=8443')).toBeInTheDocument()
    expect(screen.getByText('域名=api.example.com')).toBeInTheDocument()
    expect(screen.getByText('URI 前缀=/api/payment')).toBeInTheDocument()
    expect(screen.getByText('域名=old.example.com')).toBeInTheDocument()
    // 目标等级 Tag / 创建人 / 备注
    expect(screen.getByText('L2')).toBeInTheDocument()
    expect(screen.getByText('L3')).toBeInTheDocument()
    expect(screen.getByText('secops')).toBeInTheDocument()
    expect(screen.getByText('支付链路排障')).toBeInTheDocument()
    // 未过期规则展示剩余有效期
    expect(screen.getByText(/剩余 \d+ 分钟/)).toBeInTheDocument()
  })

  it('过期规则灰显：标注「已过期」且不展示剩余倒计时', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<CaptureOverridesPanel agentId={AGENT_ID} enabled canManage />)
    await screen.findByText('域名=old.example.com')

    expect(screen.getByText('已过期')).toBeInTheDocument()
    // 倒计时仅一条（未过期规则）
    expect(screen.getAllByText(/剩余 \d+ 分钟/).length).toBe(1)
  })

  it('新增规则：提交体为 {match, capture_level, ttl_minutes, note}（默认 L2 / 30 分钟）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<CaptureOverridesPanel agentId={AGENT_ID} enabled canManage />)
    await screen.findByText('目标 IP=10.10.20.30')

    fireEvent.click(screen.getByRole('button', { name: '新增规则' }))
    const dialog = await screen.findByRole('dialog')
    expect(
      within(dialog).getByText(/仅提升不降低采集等级，命中流量即时生效/),
    ).toBeInTheDocument()

    fireEvent.change(dialog.querySelector('#dst_ip')!, { target: { value: '10.10.20.31' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /创\s*建/ }))

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) =>
          /\/traffic\/agents\/[^/]+\/overrides$/.test(String(c[0]).split('?')[0]) &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call![1]?.body))).toEqual({
        match: { dst_ip: '10.10.20.31' },
        capture_level: 'L2',
        ttl_minutes: 30,
        note: '',
      })
    })
    expect(await screen.findByText('规则已创建，命中流量将即时提升采集等级')).toBeInTheDocument()
  })

  it('新增规则：匹配条件全空时前端拦截不提交', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<CaptureOverridesPanel agentId={AGENT_ID} enabled canManage />)
    await screen.findByText('目标 IP=10.10.20.30')

    fireEvent.click(screen.getByRole('button', { name: '新增规则' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: /创\s*建/ }))

    expect(
      await screen.findByText('至少填写一个匹配条件（目标 IP / 目标端口 / 域名 / URI 前缀）'),
    ).toBeInTheDocument()
    expect(
      (fetch as Mock).mock.calls.some(
        (c) => (c[1] as RequestInit | undefined)?.method === 'POST',
      ),
    ).toBe(false)
  })

  it('新增规则：dst_ip 非 IP/CIDR 时前端校验拦截不提交', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<CaptureOverridesPanel agentId={AGENT_ID} enabled canManage />)
    await screen.findByText('目标 IP=10.10.20.30')

    fireEvent.click(screen.getByRole('button', { name: '新增规则' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(dialog.querySelector('#dst_ip')!, { target: { value: 'not-an-ip' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /创\s*建/ }))

    expect(await screen.findByText(/无效的IP地址/)).toBeInTheDocument()
    expect(
      (fetch as Mock).mock.calls.some(
        (c) => (c[1] as RequestInit | undefined)?.method === 'POST',
      ),
    ).toBe(false)
  })

  it('新增规则：uri_prefix 不以 / 开头时前端校验拦截不提交', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<CaptureOverridesPanel agentId={AGENT_ID} enabled canManage />)
    await screen.findByText('目标 IP=10.10.20.30')

    fireEvent.click(screen.getByRole('button', { name: '新增规则' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(dialog.querySelector('#uri_prefix')!, { target: { value: 'api/payment' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /创\s*建/ }))

    expect(await screen.findByText('URI 前缀须以 / 开头')).toBeInTheDocument()
    expect(
      (fetch as Mock).mock.calls.some(
        (c) => (c[1] as RequestInit | undefined)?.method === 'POST',
      ),
    ).toBe(false)
  })

  it('删除规则：Popconfirm 确认后调用 DELETE（裸 204 按成功处理）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<CaptureOverridesPanel agentId={AGENT_ID} enabled canManage />)
    await screen.findByText('目标 IP=10.10.20.30')

    const row = screen.getByText('目标 IP=10.10.20.30').closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: /删\s*除/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认删除' }))

    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some(
          (c) =>
            /\/traffic\/agents\/[^/]+\/overrides\/ov-1$/.test(String(c[0]).split('?')[0]) &&
            (c[1] as RequestInit | undefined)?.method === 'DELETE',
        ),
      ).toBe(true)
    })
    expect(await screen.findByText('规则已删除')).toBeInTheDocument()
  })

  it('仅 view 权限：隐藏新增/删除写操作', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<CaptureOverridesPanel agentId={AGENT_ID} enabled canManage={false} />)
    await screen.findByText('目标 IP=10.10.20.30')

    expect(screen.queryByRole('button', { name: '新增规则' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删\s*除/ })).not.toBeInTheDocument()
  })
})

describe('Phase 4：背压降级帽展示', () => {
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

  it('last_metrics 含 backpressure_cap 时基本信息展示降级帽 Tag', { timeout: 20000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<TrafficAgentsPage />)
    await screen.findByText('web-prod-01')

    const row = screen.getByText('web-prod-01').closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('Agent ID')

    expect(within(drawer).getByText('背压降级帽 L1')).toBeInTheDocument()
  })

  it('详情抽屉含「定向采集」Tab，点击后加载规则列表', { timeout: 20000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<TrafficAgentsPage />)
    await screen.findByText('web-prod-01')

    const row = screen.getByText('web-prod-01').closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))
    const drawer = await screen.findByRole('dialog')
    await within(drawer).findByText('Agent ID')

    fireEvent.click(within(drawer).getByRole('tab', { name: '定向采集' }))
    expect(await within(drawer).findByText('目标 IP=10.10.20.30')).toBeInTheDocument()
    expect(within(drawer).getByText('域名=old.example.com')).toBeInTheDocument()
  })
})

describe('Phase 4：策略采样率输入', () => {
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

  it('sampling.enabled 开启时出现 rate 输入，保存体含确定性采样配置', { timeout: 30000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<PolicyPanel canManage={true} />)
    await screen.findByText('production-web')

    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }))
    const dialog = await screen.findByRole('dialog')
    // 未开启时不渲染 rate 输入
    expect(dialog.querySelector('#sampling_rate')).toBeNull()

    fireEvent.click(within(dialog).getByRole('switch'))
    const rateInput = (await waitFor(() => {
      const el = dialog.querySelector('#sampling_rate')
      expect(el).toBeTruthy()
      return el!
    })) as HTMLElement
    // 确定性 flow 级采样提示
    expect(within(dialog).getByText(/SHA-256\(flow_id\)/)).toBeInTheDocument()
    fireEvent.change(rateInput, { target: { value: '0.1' } })

    fireEvent.click(within(dialog).getByRole('button', { name: /保\s*存/ }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/traffic/policies/pol-1') &&
          (c[1] as RequestInit | undefined)?.method === 'PUT',
      )
      expect(call).toBeTruthy()
      const body = JSON.parse(String(call![1]?.body)) as {
        config: { sampling: { enabled: boolean; rate: number } }
      }
      expect(body.config.sampling).toEqual({ enabled: true, rate: 0.1 })
    })
  })

  it('未开启采样时保存体归一为 {enabled:false, rate:1}', { timeout: 30000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<PolicyPanel canManage={true} />)
    await screen.findByText('production-web')

    fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: /保\s*存/ }))

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/traffic/policies/pol-1') &&
          (c[1] as RequestInit | undefined)?.method === 'PUT',
      )
      expect(call).toBeTruthy()
      const body = JSON.parse(String(call![1]?.body)) as {
        config: { sampling: { enabled: boolean; rate: number } }
      }
      expect(body.config.sampling).toEqual({ enabled: false, rate: 1 })
    })
  })
})
