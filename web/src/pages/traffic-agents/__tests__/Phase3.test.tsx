import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import TrafficAgentsPage from '../TrafficAgentsPage'
import HttpEventsPanel from '../HttpEventsPanel'
import PolicyPanel from '../PolicyPanel'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

/* Phase 3：HTTP Sensor 前端（PHASE3 契约 §3/§4/§5/§9）
 * —— HTTP 事件 Tab 渲染与过滤、详情三分支（截断/skipped/响应 null）、策略采集等级与 masking 保存体、view 权限写操作隐藏 */

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
      status: 'ONLINE',
      disabled: false,
      last_seen: new Date(Date.now() - 10_000).toISOString(),
      last_metrics: null,
      config_version: 1,
      applied_config_version: 1,
      clock_offset_ms: null,
      health_score: 100,
      health_reasons: [],
      created_at: '2026-08-01T00:00:00Z',
    },
  ],
  total: 1,
}

const AGENT_DETAIL = {
  ...AGENTS.items[0],
  interfaces: [],
  policy_binding: null,
}

const EVENTS = { items: [], total: 0 }

/** 契约 §3 记录结构：response 含 body_truncated（截断分支） */
const HTTP_EVENT_TRUNCATED = {
  id: 101,
  flow_id: 'flow-http-1',
  request_ts: 1788256800.123,
  response_ts: 1788256800.456,
  latency_ms: 333,
  src_ip: '10.1.1.10',
  src_port: 51234,
  dst_ip: '10.1.2.20',
  dst_port: 8080,
  direction: 'ingress',
  tls_visibility: 'PLAINTEXT',
  k8s: {
    cluster: 'prod-cluster',
    namespace: 'payments',
    pod: 'api-7d9f6c8b5d-x',
    workload: 'api',
    service: 'api-service',
    side: 'dst',
  },
  request: {
    method: 'POST',
    scheme: 'http',
    host: 'api.example.com',
    uri: '/api/login',
    headers: { 'content-type': 'application/json', authorization: '********' },
    body: '{"user":"alice","password":"********"}',
    body_truncated: false,
    original_body_size: 42,
    body_skipped_reason: '',
  },
  response: {
    status: 200,
    headers: { 'content-type': 'application/json' },
    body: '{"token":"********"}',
    body_truncated: true,
    original_body_size: 300000,
    body_skipped_reason: '',
  },
}

/** body_skipped_reason=content_type（skipped 分支，§4 内容类型白名单） */
const HTTP_EVENT_SKIPPED = {
  id: 102,
  flow_id: 'flow-http-2',
  request_ts: 1788256900,
  response_ts: 1788256900.05,
  latency_ms: 50,
  src_ip: '10.1.1.11',
  src_port: 51235,
  dst_ip: '10.1.2.21',
  dst_port: 80,
  direction: 'egress',
  tls_visibility: 'PLAINTEXT',
  request: {
    method: 'POST',
    scheme: 'http',
    host: 'static.example.com',
    uri: '/upload',
    headers: { 'content-type': 'multipart/form-data; boundary=----x' },
    body: null,
    body_truncated: false,
    original_body_size: 10240,
    body_skipped_reason: 'content_type',
  },
  response: {
    status: 404,
    headers: {},
    body: null,
    body_truncated: false,
    original_body_size: 0,
    body_skipped_reason: '',
  },
}

/** response 为 null（响应未捕获/超时分支，§3） */
const HTTP_EVENT_NO_RESPONSE = {
  id: 103,
  flow_id: 'flow-http-3',
  request_ts: 1788257000,
  response_ts: null,
  latency_ms: null,
  src_ip: '10.1.1.12',
  src_port: 51236,
  dst_ip: '10.1.2.22',
  dst_port: 8080,
  direction: 'ingress',
  tls_visibility: 'PLAINTEXT',
  request: {
    method: 'GET',
    scheme: 'http',
    host: 'api.example.com',
    uri: '/api/slow',
    headers: {},
    body: null,
    body_truncated: false,
    original_body_size: 0,
    body_skipped_reason: '',
  },
  response: null,
}

const HTTP_EVENTS = {
  items: [HTTP_EVENT_TRUNCATED, HTTP_EVENT_SKIPPED, HTTP_EVENT_NO_RESPONSE],
  total: 3,
}

const POLICY = {
  id: 'pol-1',
  name: 'production-web',
  version: 3,
  config: {
    name: 'production-web',
    capture: {
      interfaces: ['eth0'],
      direction: 'both',
      protocols: ['tcp'],
      ports: [80, 443],
    },
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
    const ok = (data: unknown) =>
      Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }),
      )
    // Phase 3 §6：单条全量端点（须在列表端点之前匹配）
    const detailMatch = /\/traffic\/agents\/[^/]+\/http-events\/(\d+)/.exec(
      url.split('?')[0],
    )
    if (detailMatch) {
      const id = Number(detailMatch[1])
      return ok(HTTP_EVENTS.items.find((e) => e.id === id) ?? null)
    }
    if (/\/traffic\/agents\/[^/]+\/http-events/.test(url))
      return ok(HTTP_EVENTS)
    if (url.includes('/traffic/policies/pol-1') && method === 'PUT')
      return ok(POLICY)
    if (url.includes('/traffic/policies')) return ok(POLICIES)
    if (url.includes('/traffic/agents/summary')) return ok(SUMMARY)
    if (/\/traffic\/agents\/[^/]+\/events/.test(url)) return ok(EVENTS)
    if (/\/traffic\/agents\/[^/]+$/.test(url.split('?')[0]))
      return ok(AGENT_DETAIL)
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

/** 点击 antd 下拉选项（portal 渲染；jsdom 的 querySelector 对含部分全角字符的 title 属性选择器匹配不稳定，改用 JS 比对 title；
 * 已关闭的下拉 DOM 仍挂载（ant-select-dropdown-hidden），需排除避免点到陈旧选项） */
async function clickSelectOption(title: string) {
  const find = () =>
    Array.from(document.querySelectorAll('.ant-select-item-option')).find(
      (el) => {
        const dropdown = el.closest('.ant-select-dropdown')
        if (dropdown && dropdown.className.includes('hidden')) return false
        return el.getAttribute('title') === title || el.textContent === title
      },
    )
  await waitFor(() => {
    expect(find()).toBeTruthy()
  })
  fireEvent.click(find()!)
}

/** http-events 列表端点（不含单条详情端点）的请求 URL 列表 */
function httpEventListUrls(): string[] {
  return (fetch as Mock).mock.calls
    .map((c) => String(c[0]))
    .filter((u) => /\/http-events\?/.test(u))
}

describe('Phase 3：HTTP 事件 Tab', () => {
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

  it(
    '详情抽屉新增 HTTP 事件 Tab：列表渲染（请求/状态/时延/截断标记/无响应）',
    { timeout: 20000 },
    async () => {
      vi.stubGlobal('fetch', mockFetch())
      renderWithProviders(<TrafficAgentsPage />)
      await screen.findByText('web-prod-01')

      const row = screen.getByText('web-prod-01').closest('tr')!
      fireEvent.click(within(row).getByRole('button', { name: /详\s*情/ }))
      const drawer = await screen.findByRole('dialog')
      // 等待详情加载完成（Tabs 在 detail 就绪后才渲染）
      await within(drawer).findByText('Agent ID')

      fireEvent.click(within(drawer).getByRole('tab', { name: 'HTTP 事件' }))
      expect(
        await within(drawer).findByText('POST api.example.com/api/login'),
      ).toBeInTheDocument()
      expect(
        within(drawer).getByText('POST static.example.com/upload'),
      ).toBeInTheDocument()
      expect(
        within(drawer).getByText('GET api.example.com/api/slow'),
      ).toBeInTheDocument()
      // 时延与截断标记；response=null 行状态灰显"无响应"
      expect(within(drawer).getByText('333 ms')).toBeInTheDocument()
      expect(within(drawer).getByText('响应截断')).toBeInTheDocument()
      expect(within(drawer).getByText('无响应')).toBeInTheDocument()
    },
  )

  it('过滤：host/method 作为查询参数发起分页请求', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<HttpEventsPanel agentId={AGENT_ID} enabled />)
    await screen.findByText('POST api.example.com/api/login')

    // host 过滤（Input.Search 回车触发 onSearch）
    const hostInput = screen.getByPlaceholderText('按 Host 过滤')
    fireEvent.change(hostInput, { target: { value: 'api.example.com' } })
    fireEvent.keyDown(hostInput, { key: 'Enter', keyCode: 13 })
    await waitFor(() => {
      expect(
        httpEventListUrls().some((u) => u.includes('host=api.example.com')),
      ).toBe(true)
    })

    // method 过滤
    const methodSelect = screen
      .getByText('按 Method 过滤')
      .closest('.ant-select')!
    fireEvent.mouseDown(methodSelect.querySelector('[role="combobox"]')!)
    await clickSelectOption('POST')
    await waitFor(() => {
      expect(
        httpEventListUrls().some(
          (u) =>
            u.includes('host=api.example.com') && u.includes('method=POST'),
        ),
      ).toBe(true)
    })
    // 分页参数始终携带
    const urls = httpEventListUrls()
    const last = urls[urls.length - 1]
    expect(last).toContain('page=1')
    expect(last).toContain('page_size=20')
  })

  it('详情：截断分支（Alert 明示 + 原始大小 + 脱敏值原样展示 + JSON 美化）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<HttpEventsPanel agentId={AGENT_ID} enabled />)
    fireEvent.click(await screen.findByText('POST api.example.com/api/login'))

    const dialog = await screen.findByRole('dialog')
    expect(
      await within(dialog).findByText('HTTP 事件详情（#101）'),
    ).toBeInTheDocument()
    // 五元组/方向/TLS 可见性
    expect(
      within(dialog).getByText(/10\.1\.1\.10:51234 → 10\.1\.2\.20:8080/),
    ).toBeInTheDocument()
    expect(within(dialog).getByText('入站')).toBeInTheDocument()
    expect(within(dialog).getByText('明文')).toBeInTheDocument()
    const workload = within(dialog).getByText('payments/api-7d9f6c8b5d-x')
    expect(workload).toBeInTheDocument()
    fireEvent.mouseOver(workload)
    expect(
      await screen.findByText(/集群: prod-cluster；工作负载: api/),
    ).toBeInTheDocument()
    // 响应 Body 截断 Alert + 原始大小
    expect(within(dialog).getByText('Body 已截断')).toBeInTheDocument()
    expect(within(dialog).getByText(/原始大小/)).toBeInTheDocument()
    // 脱敏值即最终值（界面不标"明文"、不暗示可还原）；请求/响应两处脱敏说明
    expect(within(dialog).getAllByText('********').length).toBeGreaterThan(0)
    expect(
      within(dialog).getAllByText(
        '数据已在 Agent 侧脱敏（离主机前完成），此处展示为最终值',
      ).length,
    ).toBe(2)
    expect(
      within(dialog).queryByText(/明文密码|可还原|还原/),
    ).not.toBeInTheDocument()
    // JSON 美化（缩进后的 key 独立成行）
    expect(within(dialog).getByText(/"user": "alice"/)).toBeInTheDocument()
    // 单条全量端点被调用
    expect(
      (fetch as Mock).mock.calls.some((c) =>
        /\/traffic\/agents\/[^/]+\/http-events\/101$/.test(
          String(c[0]).split('?')[0],
        ),
      ),
    ).toBe(true)
  })

  it('详情：skipped 分支（content_type 未采集 Alert + 原始大小照记）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<HttpEventsPanel agentId={AGENT_ID} enabled />)
    fireEvent.click(await screen.findByText('POST static.example.com/upload'))

    const dialog = await screen.findByRole('dialog')
    expect(
      await within(dialog).findByText('HTTP 事件详情（#102）'),
    ).toBeInTheDocument()
    expect(
      within(dialog).getByText(
        /Body 未采集（content_type）：内容类型不在采集白名单/,
      ),
    ).toBeInTheDocument()
    expect(within(dialog).getByText(/原始大小/)).toBeInTheDocument()
    // 响应状态 4xx 橙色 Tag 文案仍在
    expect(within(dialog).getAllByText('404').length).toBeGreaterThan(0)
  })

  it('详情：response 为 null 分支（响应未捕获明示，不渲染响应 headers/body 区）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<HttpEventsPanel agentId={AGENT_ID} enabled />)
    fireEvent.click(await screen.findByText('GET api.example.com/api/slow'))

    const dialog = await screen.findByRole('dialog')
    expect(
      await within(dialog).findByText('HTTP 事件详情（#103）'),
    ).toBeInTheDocument()
    expect(
      within(dialog).getByText('响应未捕获（超时或连接中断），无响应数据'),
    ).toBeInTheDocument()
    expect(within(dialog).queryByText('响应 Body')).not.toBeInTheDocument()
    // 状态灰显"无响应"，时延/响应时间为占位符
    expect(within(dialog).getAllByText('无响应').length).toBeGreaterThan(0)
    expect(within(dialog).getAllByText('-').length).toBeGreaterThan(0)
  })
})

describe('Phase 3：策略采集等级与 masking', () => {
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

  it(
    '编辑保存：capture_level 与 masking.headers/params 覆盖 JSON 对应键',
    { timeout: 30000 },
    async () => {
      vi.stubGlobal('fetch', mockFetch())
      renderWithProviders(<PolicyPanel canManage={true} />)
      await screen.findByText('production-web')

      fireEvent.click(screen.getByRole('button', { name: /编\s*辑/ }))
      const dialog = await screen.findByRole('dialog')

      // 采集等级 L0 → L2
      const levelSelect = within(dialog)
        .getByText(/L0：仅元数据/)
        .closest('.ant-select')!
      fireEvent.mouseDown(levelSelect.querySelector('[role="combobox"]')!)
      await clickSelectOption('L2：L1 + Body（受大小与内容类型限制）')

      // Header 脱敏方式 MASK → HASH
      const headerMode = within(dialog)
        .getAllByText('MASK（替换为 ********）')[0]
        .closest('.ant-select')!
      fireEvent.mouseDown(headerMode.querySelector('[role="combobox"]')!)
      await clickSelectOption('HASH（sha256 前 16 位）')

      // 参数脱敏方式 MASK → DROP（此时仅剩一个 MASK 选中项）
      const paramMode = within(dialog)
        .getAllByText('MASK（替换为 ********）')[0]
        .closest('.ant-select')!
      fireEvent.mouseDown(paramMode.querySelector('[role="combobox"]')!)
      await clickSelectOption('DROP（整行/参数删除）')

      fireEvent.click(within(dialog).getByRole('button', { name: /保\s*存/ }))
      await waitFor(() => {
        const call = (fetch as Mock).mock.calls.find(
          (c) =>
            String(c[0]).includes('/traffic/policies/pol-1') &&
            (c[1] as RequestInit | undefined)?.method === 'PUT',
        )
        expect(call).toBeTruthy()
        const body = JSON.parse(String(call![1]?.body)) as {
          config: {
            capture_level: string
            masking: {
              headers: { mode: string; names: string[] }
              params: { mode: string; names: string[] }
            }
            output: { mode: string }
          }
        }
        expect(body.config.capture_level).toBe('L2')
        expect(body.config.masking).toEqual({
          headers: {
            mode: 'HASH',
            names: [
              'authorization',
              'cookie',
              'set-cookie',
              'x-api-key',
              'proxy-authorization',
            ],
          },
          params: {
            mode: 'DROP',
            names: [
              'password',
              'passwd',
              'pwd',
              'token',
              'access_token',
              'refresh_token',
              'secret',
              'api_key',
              'apikey',
            ],
          },
        })
        // 既有表单字段不受影响
        expect(body.config.output.mode).toBe('FLOW')
      })
      expect(await screen.findByText('策略已保存')).toBeInTheDocument()
    },
  )

  it('仅 view 权限：隐藏创建/编辑/删除写操作，历史可读', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<PolicyPanel canManage={false} />)
    await screen.findByText('production-web')

    expect(
      screen.queryByRole('button', { name: '创建策略' }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /编\s*辑/ }),
    ).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /删\s*除/ }),
    ).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /历\s*史/ })).toBeInTheDocument()
  })
})
