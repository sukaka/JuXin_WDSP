import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import TrafficAgentsPage from '../TrafficAgentsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

const SUMMARY = { total: 4, online: 1, offline: 1, degraded: 1, disabled: 1 }

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
      last_metrics: {
        cpu_percent: 3.2,
        memory_mb: 128.5,
        capture_pps: 1200,
        capture_bps: 1_250_000,
        forward_pps: 1100,
        forward_bps: 1_000_000,
        drop_pps: 5,
        queue_depth: 12,
        buffer_bytes: 0,
      },
      config_version: 2,
      applied_config_version: 2,
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
      status: 'OFFLINE',
      disabled: false,
      last_seen: '2026-08-30T00:00:00Z',
      last_metrics: null,
      config_version: 0,
      applied_config_version: 0,
      created_at: '2026-08-01T00:00:00Z',
    },
    {
      agent_id: 'a3c98f51-0000-4000-8000-000000000003',
      hostname: 'web-prod-03',
      ip: '10.0.1.12',
      os: 'Rocky Linux 9',
      kernel: '5.14.0',
      arch: 'x86_64',
      version: '1.0.0',
      status: 'DEGRADED',
      disabled: false,
      last_seen: new Date(Date.now() - 20_000).toISOString(),
      last_metrics: null,
      config_version: 0,
      applied_config_version: 0,
      created_at: '2026-08-01T00:00:00Z',
    },
    {
      agent_id: 'a3c98f51-0000-4000-8000-000000000004',
      hostname: 'web-prod-04',
      ip: '10.0.1.13',
      os: 'Rocky Linux 9',
      kernel: '5.14.0',
      arch: 'x86_64',
      version: '1.0.0',
      status: 'DISABLED',
      disabled: true,
      last_seen: '2026-08-29T00:00:00Z',
      last_metrics: null,
      config_version: 0,
      applied_config_version: 0,
      created_at: '2026-08-01T00:00:00Z',
    },
  ],
  total: 4,
}

const AGENT_DETAIL = {
  ...AGENTS.items[0],
  interfaces: [
    { name: 'eth0', mac: 'aa:bb:cc:dd:ee:ff', ipv4: '10.0.1.10', ipv6: '', mtu: 1500, speed_mbps: 1000 },
  ],
  policy_binding: null,
}

const EVENTS = {
  items: [
    {
      event_type: 'request',
      flow_id: 'flow-1',
      timestamp: 1788256800,
      src_ip: '10.1.1.10',
      src_port: 51234,
      dst_ip: '10.1.2.20',
      dst_port: 8080,
      protocol: 'tcp',
      direction: 'ingress',
      bytes_in: 120,
      bytes_out: 2048,
      tls_visibility: 'PLAINTEXT',
      http_method: 'POST',
      http_host: 'api.example.com',
      http_uri: '/api/login',
      http_status: 0,
    },
    {
      event_type: 'flow_end',
      flow_id: 'flow-2',
      timestamp: 1788256900,
      src_ip: '10.1.1.11',
      src_port: 51235,
      dst_ip: '10.1.2.21',
      dst_port: 443,
      protocol: 'tcp',
      direction: 'egress',
      bytes_in: 0,
      bytes_out: 4096,
      tls_visibility: 'ENCRYPTED',
    },
  ],
  total: 2,
}

const POLICIES = {
  items: [
    {
      id: 'pol-1',
      name: 'production-web',
      version: 3,
      config: {
        capture: { interfaces: ['eth0'], direction: 'both', protocols: ['tcp'], ports: [80, 443] },
        output: { mode: 'FLOW' },
        limits: { outbound_mbps: 100 },
      },
      created_at: '2026-08-01T00:00:00Z',
      updated_at: '2026-08-20T00:00:00Z',
    },
  ],
  total: 1,
}

interface MockOptions {
  listStatus?: number
  pending?: boolean
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    if (opts.pending) return new Promise<Response>(() => {})
    const url = String(input)
    const method = init?.method ?? 'GET'
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    // 契约 §4 写操作返回裸 204（无信封），覆盖 client 空 body 2xx 成功分支
    const empty = () => Promise.resolve(new Response(null, { status: 204 }))
    if (url.includes('/traffic/agents/enrollment-tokens') && method === 'POST') {
      return Promise.resolve(
        jsonResponse(201, {
          code: 'SUCCESS',
          message: 'ok',
          data: { id: 'tok-1', token: 'wdt_secret_abc', expires_at: '2026-09-01T02:00:00Z' },
        }),
      )
    }
    if (url.includes('/traffic/agents/summary')) return ok(SUMMARY)
    if (/\/traffic\/agents\/[^/]+\/events/.test(url)) return ok(EVENTS)
    if (/\/traffic\/agents\/[^/]+\/policy/.test(url)) {
      return method === 'DELETE' ? empty() : empty()
    }
    if (/\/traffic\/agents\/[^/]+\/(disable|enable)/.test(url)) return empty()
    if (/\/traffic\/agents\/[^/]+$/.test(url.split('?')[0])) {
      if (method === 'DELETE') return empty()
      return ok(AGENT_DETAIL)
    }
    if (url.includes('/traffic/agents')) {
      const status = opts.listStatus ?? 200
      if (status !== 200) {
        return Promise.resolve(
          jsonResponse(status, {
            code: status === 403 ? 'FORBIDDEN' : 'INTERNAL',
            message: status === 403 ? '无权限' : '服务器错误',
            data: null,
          }),
        )
      }
      return ok(AGENTS)
    }
    if (url.includes('/traffic/policies')) return ok(POLICIES)
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <TrafficAgentsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 点击 antd 下拉选项（portal 渲染，按 title 属性定位） */
async function clickSelectOption(title: string) {
  await waitFor(() => {
    expect(document.querySelector(`.ant-select-item-option[title="${title}"]`)).toBeTruthy()
  })
  fireEvent.click(document.querySelector(`.ant-select-item-option[title="${title}"]`)!)
}

describe('TrafficAgentsPage', () => {
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

  it('正常渲染：汇总卡片、状态 Badge、实时速率列、相对心跳时间', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()

    const row = (await screen.findByText('web-prod-01')).closest('tr')!
    expect(row.textContent).toContain('10.0.1.10')
    expect(row.textContent).toContain('Rocky Linux 9')
    expect(row.textContent).toContain('1.0.0')
    // Agent ID 截断展示
    expect(row.textContent).toContain('a3c98f51…')
    // 采集 1_250_000 B/s = 10.00 Mbps；发送 1_000_000 B/s = 8.00 Mbps
    expect(row.textContent).toContain('10.00')
    expect(row.textContent).toContain('8.00')
    expect(row.textContent).toContain('1200')
    // 最后心跳相对时间（10 秒前）
    expect(row.textContent).toContain('秒前')

    // 状态 Badge 四态（汇总卡片含同名文案，用 getAllByText）
    expect(screen.getAllByText('在线').length).toBeGreaterThan(0)
    expect(screen.getAllByText('离线').length).toBeGreaterThan(0)
    expect(screen.getAllByText('降级').length).toBeGreaterThan(0)
    expect(screen.getByText('已禁用')).toBeInTheDocument()

    // 汇总卡片（总数 4，在线/离线/降级/禁用各 1）
    expect(screen.getByText('Agent 总数')).toBeInTheDocument()
    const totalCard = screen.getByText('Agent 总数').closest('.ant-statistic')!
    expect(totalCard.textContent).toContain('4')
    // 列头中文化（操作系统 / 丢包/秒）
    expect(screen.getAllByText('操作系统').length).toBeGreaterThan(0)
    expect(screen.getAllByText('丢包/秒').length).toBeGreaterThan(0)
    expect(screen.queryByText('OS')).not.toBeInTheDocument()
    expect(screen.queryByText('Drop/s')).not.toBeInTheDocument()
  })

  it('无权限（403）展示暂无权限提示', async () => {
    vi.stubGlobal('fetch', mockFetch({ listStatus: 403 }))
    renderPage()
    expect(await screen.findByText('暂无权限查看')).toBeInTheDocument()
  })

  it('创建注册令牌：提交后令牌原文仅展示一次，关闭后不可见', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('web-prod-01')

    fireEvent.click(screen.getByRole('button', { name: '创建注册令牌' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如 prod-web'), {
      target: { value: 'prod-web' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^创\s*建$/ }))

    expect(await screen.findByText('令牌原文仅显示一次')).toBeInTheDocument()
    expect(screen.getByText('wdt_secret_abc')).toBeInTheDocument()

    const createCall = (fetch as Mock).mock.calls.find((c) =>
      String(c[0]).includes('/traffic/agents/enrollment-tokens'),
    )
    expect(createCall).toBeTruthy()
    expect(JSON.parse(String(createCall![1]?.body))).toEqual({ label: 'prod-web', ttl_minutes: 60 })

    fireEvent.click(screen.getByRole('button', { name: /完\s*成/ }))
    await waitFor(() => expect(screen.queryByText('wdt_secret_abc')).not.toBeInTheDocument())
  })

  it('禁用 Agent：Popconfirm 二次确认后调用 disable 接口', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('web-prod-01')

    const row = screen.getByText('web-prod-01').closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: /禁\s*用/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认禁用' }))

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find((c) =>
        String(c[0]).includes(`/traffic/agents/${AGENTS.items[0].agent_id}/disable`),
      )
      expect(call).toBeTruthy()
      expect((call![1] as RequestInit).method).toBe('POST')
    })
    expect(await screen.findByText(/Agent 已禁用/)).toBeInTheDocument()
  })

  it('删除 Agent：Popconfirm 二次确认后调用 DELETE 接口', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('web-prod-02')

    const row = screen.getByText('web-prod-02').closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: /删\s*除/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认删除' }))

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).split('?')[0].endsWith(`/traffic/agents/${AGENTS.items[1].agent_id}`) &&
          (c[1] as RequestInit | undefined)?.method === 'DELETE',
      )
      expect(call).toBeTruthy()
    })
    expect(await screen.findByText('Agent 已删除')).toBeInTheDocument()
  })

  it('详情抽屉：基本信息/网卡/流量事件（含 TLS 可见性），绑定策略调用 bind 接口', { timeout: 20000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('web-prod-01')

    const row = screen.getByText('web-prod-01').closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))

    const drawer = await screen.findByRole('dialog')
    // 基本信息
    expect(await within(drawer).findByText('未绑定策略，Agent 使用内置默认采集集')).toBeInTheDocument()
    // 网卡 Tab
    fireEvent.click(within(drawer).getByRole('tab', { name: '网卡' }))
    expect(await within(drawer).findByText('aa:bb:cc:dd:ee:ff')).toBeInTheDocument()
    // 流量事件 Tab：五元组、TLS 可见性
    fireEvent.click(within(drawer).getByRole('tab', { name: '流量事件' }))
    expect(await within(drawer).findByText(/10\.1\.1\.10:51234 → 10\.1\.2\.20:8080\/tcp/)).toBeInTheDocument()
    expect(within(drawer).getByText('明文')).toBeInTheDocument()
    expect(within(drawer).getByText('加密')).toBeInTheDocument()

    // 绑定策略
    fireEvent.click(within(drawer).getByRole('tab', { name: '基本信息' }))
    fireEvent.mouseDown(within(drawer).getByRole('combobox'))
    await clickSelectOption('production-web（v3）')
    fireEvent.click(within(drawer).getByRole('button', { name: /绑\s*定/ }))

    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes(`/traffic/agents/${AGENTS.items[0].agent_id}/policy`) &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(call).toBeTruthy()
      expect(JSON.parse(String(call![1]?.body))).toEqual({ policy_id: 'pol-1' })
    })
    expect(await screen.findByText('策略已绑定')).toBeInTheDocument()
  })

  it('采集策略 Tab：列表渲染，编辑保存带 name+config', { timeout: 30000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('web-prod-01')

    fireEvent.click(screen.getByRole('tab', { name: '采集策略' }))
    expect(await screen.findByText('production-web')).toBeInTheDocument()
    expect(screen.getByText('v3')).toBeInTheDocument()
    // 采集配置列展示中文方向与输出模式，不裸露 both / FLOW
    expect(
      screen.getByText(/等级 L0 \/ eth0 \/ 双向 \/ 端口 80,443 \/ 流元数据 \/ 限速 100 Mbps/),
    ).toBeInTheDocument()

    // 编辑：保存时提交 name + config（表单字段覆盖 JSON 对应键）
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
        name: string
        config: { capture: { interfaces: string[]; ports: number[] }; output: { mode: string } }
      }
      expect(body.name).toBe('production-web')
      expect(body.config.capture.interfaces).toEqual(['eth0'])
      expect(body.config.capture.ports).toEqual([80, 443])
      expect(body.config.output.mode).toBe('FLOW')
    })
    expect(await screen.findByText('策略已保存')).toBeInTheDocument()
  })

  it('采集策略删除：Popconfirm 确认后调用 DELETE（裸 204 按成功处理）', { timeout: 30000 }, async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('web-prod-01')

    fireEvent.click(screen.getByRole('tab', { name: '采集策略' }))
    await screen.findByText('production-web')

    fireEvent.click(screen.getByRole('button', { name: /删\s*除/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认删除' }))
    await waitFor(() => {
      const call = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/traffic/policies/pol-1') &&
          (c[1] as RequestInit | undefined)?.method === 'DELETE',
      )
      expect(call).toBeTruthy()
    })
    expect(await screen.findByText('策略已删除')).toBeInTheDocument()
  })

  it('仅 view 权限：隐藏创建令牌与行内写操作', async () => {
    useAuthStore.setState({
      user: makeUser(['traffic.agents.view']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByText('web-prod-01')

    expect(screen.queryByRole('button', { name: '创建注册令牌' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /禁\s*用/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删\s*除/ })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /详\s*情/ }).length).toBeGreaterThan(0)
  })
})
