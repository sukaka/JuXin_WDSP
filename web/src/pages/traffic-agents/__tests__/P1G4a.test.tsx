import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import HttpEventsPanel from '../HttpEventsPanel'
import HttpAssetSourcesPanel from '../HttpAssetSourcesPanel'
import AgentDetailDrawer from '../AgentDetailDrawer'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

/* P1-03 G4a（任务书 §4.3，验收 AGT-025/026）：HTTP 事件 v2 管理端展示——
 * 来源/协议/关联/数据质量/去重/缓存补传/资产关联独立状态；v2 headers 数组形态还原；
 * 旧 Agent 显示「需升级」；恶意文本纯文本渲染（无 XSS）；筛选分页上下文保留 */

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

/** 恶意文本标记（XSS 用例）：必须以纯文本渲染，不得作为 HTML 执行 */
const XSS = '<img src=x onerror=alert(1)>'

/** v2 事件（含全部 v2 字段；采集→入库延迟 45s 触发"疑似缓存补传"） */
const HTTP_EVENT_V2 = {
  id: 201,
  flow_id: 'f-v2-1',
  request_ts: 1788256800.123,
  response_ts: null,
  latency_ms: null,
  src_ip: '127.0.0.1',
  src_port: 0,
  dst_ip: '127.0.0.1',
  dst_port: 9000,
  direction: 'ingress',
  tls_visibility: 'DECRYPTED',
  schema_version: 2,
  event_id: 'agent1-mirror-nginx-a-1788256800123-7',
  source_type: 'NGINX_MIRROR',
  source_instance: XSS,
  source_epoch: 3,
  source_capabilities_version: 'nginx-mirror/1',
  observed_http_version: '2',
  original_http_version: '1.1',
  association_state: 'REQUEST_ONLY',
  association_reason: 'SOURCE_REQUEST_ONLY',
  capture_stream_id: 'conn-9/stream-3',
  application_binding_id: null,
  binding_version: null,
  collection_ts: 1788256800.1,
  ingestion_ts: 1788256845.2,
  grpc: {
    service: 'pkg.UserService',
    method: 'GetUser',
    grpc_status: null,
    stream_state: 'OPEN',
  },
  request: {
    method: 'POST',
    scheme: 'https',
    host: 'api.example.com',
    uri: '/pkg.UserService/GetUser',
    headers: {
      'content-type': ['application/grpc'],
      'set-cookie': ['a=1', 'b=2'],
      'x-note': [XSS],
    },
    trailers: { 'x-trace': ['t1'] },
    body: '{"q":"1"}',
    body_truncated: true,
    original_body_size: 4096,
    body_skipped_reason: '',
    body_quality: {
      captured_bytes: 128,
      original_total_size: 4096,
      truncated: true,
      skipped_reason: '',
    },
  },
  response: null,
}

/** v1 事件（无 v2 字段——旧采集来源/协议/关联显示为「-」） */
const HTTP_EVENT_V1 = {
  id: 202,
  flow_id: 'f-v1-1',
  request_ts: 1788256900,
  response_ts: 1788256900.05,
  latency_ms: 50,
  src_ip: '10.1.1.11',
  src_port: 51235,
  dst_ip: '10.1.2.21',
  dst_port: 80,
  direction: 'egress',
  tls_visibility: 'PLAINTEXT',
  schema_version: 1,
  event_id: null,
  source_type: 'PASSIVE_HTTP1',
  source_instance: '',
  source_epoch: 0,
  source_capabilities_version: '',
  observed_http_version: 'UNKNOWN',
  original_http_version: null,
  association_state: null,
  association_reason: '',
  capture_stream_id: null,
  application_binding_id: null,
  binding_version: null,
  collection_ts: null,
  ingestion_ts: null,
  grpc: null,
  request: {
    method: 'GET',
    scheme: 'http',
    host: 'legacy.example.com',
    uri: '/old',
    headers: { authorization: '********' },
    trailers: null,
    body: '',
    body_truncated: false,
    original_body_size: 0,
    body_skipped_reason: '',
    body_quality: null,
  },
  response: {
    status: 200,
    headers: {},
    trailers: null,
    body: '',
    body_truncated: false,
    original_body_size: 0,
    body_skipped_reason: '',
    body_quality: null,
  },
}

const ASSET_SOURCES = {
  items: [
    {
      id: 1,
      agent_id: AGENT_ID,
      endpoint_id: 'b3c98f51-0000-4000-8000-0000000000aa',
      host: 'api.example.com',
      method: 'POST',
      path_template: '/pkg.UserService/GetUser',
      source_type: 'NGINX_MIRROR',
      source_instance: 'nginx-a',
      source_epoch: 3,
      application_binding_id: null,
      binding_version: null,
      association_state: 'UNASSIGNED',
      last_error: '',
      first_seen_at: '2026-09-01T00:00:00Z',
      last_seen_at: '2026-09-08T00:00:00Z',
    },
    {
      id: 2,
      agent_id: AGENT_ID,
      endpoint_id: null,
      host: 'api.example.com',
      method: 'GET',
      path_template: '/quota',
      source_type: 'PASSIVE_HTTP1',
      source_instance: 'sensor-0',
      source_epoch: 0,
      application_binding_id: null,
      binding_version: null,
      association_state: 'QUOTA_REJECTED',
      last_error: 'license quota exceeded',
      first_seen_at: '2026-09-01T00:00:00Z',
      last_seen_at: '2026-09-08T01:00:00Z',
    },
  ],
  total: 2,
}

function makeAgentDetail(schemas: number[]) {
  return {
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
    config_version: 5,
    applied_config_version: 3,
    clock_offset_ms: null,
    health_score: 100,
    health_reasons: [],
    created_at: '2026-08-01T00:00:00Z',
    interfaces: [],
    policy_binding: {
      policy_id: 'pol-1',
      name: 'production-web',
      version: 4,
    },
    http_event_schemas: schemas,
  }
}

function mockFetch(agentDetail: unknown = makeAgentDetail([1, 2])) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const path = url.split('?')[0]
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    const detailMatch = /\/traffic\/agents\/[^/]+\/http-events\/(\d+)/.exec(path)
    if (detailMatch) {
      const id = Number(detailMatch[1])
      const found = [HTTP_EVENT_V2, HTTP_EVENT_V1].find((e) => e.id === id)
      return ok(found ?? null)
    }
    if (/\/traffic\/agents\/[^/]+\/http-asset-sources/.test(path))
      return ok(ASSET_SOURCES)
    if (/\/traffic\/agents\/[^/]+\/http-events/.test(path))
      return ok({ items: [HTTP_EVENT_V2, HTTP_EVENT_V1], total: 2 })
    if (/\/traffic\/agents\/[^/]+\/events/.test(path)) return ok({ items: [], total: 0 })
    if (/\/traffic\/agents\/[^/]+\/overrides/.test(path)) return ok({ items: [], total: 0 })
    if (/\/traffic\/agents\/[^/]+$/.test(path)) return ok(agentDetail)
    if (url.includes('/traffic/policies')) return ok({ items: [], total: 0 })
    if (url.includes('/traffic/agents')) return ok({ items: [], total: 0 })
    void init
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

function httpEventListUrls(): string[] {
  return (fetch as Mock).mock.calls
    .map((c) => String(c[0]))
    .filter((u) => /\/http-events\?/.test(u))
}

describe('P1-03 G4a：HTTP 事件 v2 展示', () => {
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

  it('列表：v2 行来源/协议/关联独立状态；v1 行显示「-」不伪造', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(
      <HttpEventsPanel agentId={AGENT_ID} enabled httpEventSchemas={[1, 2]} />,
    )
    await screen.findByText('POST api.example.com/pkg.UserService/GetUser')
    // v2 行：来源 Nginx 镜像、协议 HTTP/2、关联 仅请求
    expect(screen.getByText('Nginx 镜像')).toBeInTheDocument()
    expect(screen.getByText('HTTP/2')).toBeInTheDocument()
    expect(screen.getByText('仅请求')).toBeInTheDocument()
    // v1 行：来源/协议/关联列为占位符（不谎称已观测）
    expect(screen.getByText('GET legacy.example.com/old')).toBeInTheDocument()
    // 无升级提示（能力集含 v2）
    expect(screen.queryByText(/仅支持 v1 事件/)).not.toBeInTheDocument()
  })

  it('旧 Agent（能力集仅 v1）：显示「需升级」提示，依据 http_event_schemas 字段', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(
      <HttpEventsPanel agentId={AGENT_ID} enabled httpEventSchemas={[1]} />,
    )
    await screen.findByText('POST api.example.com/pkg.UserService/GetUser')
    expect(screen.getByText('该 Agent 仅支持 v1 事件（需升级）')).toBeInTheDocument()
  })

  it('详情：v2 来源/质量/去重/补传/gRPC 分区与数组形态 headers（含 XSS 纯文本）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(
      <HttpEventsPanel agentId={AGENT_ID} enabled httpEventSchemas={[1, 2]} />,
    )
    fireEvent.click(
      await screen.findByText('POST api.example.com/pkg.UserService/GetUser'),
    )
    const dialog = await screen.findByRole('dialog')
    expect(
      await within(dialog).findByText('HTTP 事件详情（#201）'),
    ).toBeInTheDocument()
    // 来源与数据质量分区
    expect(within(dialog).getByText('来源与数据质量（v2 协议）')).toBeInTheDocument()
    expect(within(dialog).getByText('流 ID')).toBeInTheDocument()
    expect(within(dialog).getByText(/\/ 代次 3/)).toBeInTheDocument()
    expect(
      within(dialog).getByText('agent1-mirror-nginx-a-1788256800123-7'),
    ).toBeInTheDocument()
    expect(within(dialog).getByText('幂等去重生效')).toBeInTheDocument()
    expect(within(dialog).getByText('HTTP/2 / HTTP/1.1')).toBeInTheDocument()
    expect(within(dialog).getByText('conn-9/stream-3')).toBeInTheDocument()
    expect(within(dialog).getByText('未绑定（资产关联待确认）')).toBeInTheDocument()
    // 采集→入库延迟 45s > 阈值 → 疑似缓存补传
    expect(within(dialog).getByText('疑似缓存补传')).toBeInTheDocument()
    // TLS 已解密（v2 枚举）
    expect(within(dialog).getByText('已解密')).toBeInTheDocument()
    // 数组形态 headers：重复 set-cookie 两行保序
    expect(within(dialog).getByText('a=1')).toBeInTheDocument()
    expect(within(dialog).getByText('b=2')).toBeInTheDocument()
    // trailers 还原
    expect(within(dialog).getByText('请求尾部头')).toBeInTheDocument()
    expect(within(dialog).getByText('t1')).toBeInTheDocument()
    // body_quality：实际捕获/原始总大小
    expect(within(dialog).getByText(/实际捕获 128 B \/ 原始总大小 4\.00 KB \/ 已截断/)).toBeInTheDocument()
    // gRPC 元数据：grpc_status null 不伪造 0
    expect(within(dialog).getByText('gRPC 元数据')).toBeInTheDocument()
    expect(within(dialog).getByText('pkg.UserService')).toBeInTheDocument()
    expect(within(dialog).getByText('未知（流未结束/不可见）')).toBeInTheDocument()
    // 恶意文本作为纯文本渲染（textContent 可见，不产生 img 元素）
    const texts = within(dialog).getAllByText(XSS)
    expect(texts.length).toBeGreaterThan(0)
    expect(dialog.querySelector('img')).toBeNull()
  })

  it('详情：v1 行不渲染 v2 分区与 trailers（来源无此概念不伪造）', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(
      <HttpEventsPanel agentId={AGENT_ID} enabled httpEventSchemas={[1, 2]} />,
    )
    fireEvent.click(await screen.findByText('GET legacy.example.com/old'))
    const dialog = await screen.findByRole('dialog')
    expect(
      await within(dialog).findByText('HTTP 事件详情（#202）'),
    ).toBeInTheDocument()
    expect(within(dialog).queryByText('来源与数据质量（v2 协议）')).not.toBeInTheDocument()
    expect(within(dialog).queryByText('请求尾部头')).not.toBeInTheDocument()
    expect(within(dialog).queryByText(/数据质量：/)).not.toBeInTheDocument()
    // v1 headers string map 照常展示
    expect(within(dialog).getByText('********')).toBeInTheDocument()
  })

  it('AGT-025：打开/关闭详情后筛选与分页上下文保留', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(
      <HttpEventsPanel agentId={AGENT_ID} enabled httpEventSchemas={[1, 2]} />,
    )
    await screen.findByText('POST api.example.com/pkg.UserService/GetUser')
    const hostInput = screen.getByPlaceholderText('按域名过滤')
    fireEvent.change(hostInput, { target: { value: 'api.example.com' } })
    fireEvent.keyDown(hostInput, { key: 'Enter', keyCode: 13 })
    await waitFor(() => {
      expect(httpEventListUrls().some((u) => u.includes('host=api.example.com'))).toBe(true)
    })
    // 打开详情再关闭，筛选条件仍在（组件状态不重置）
    fireEvent.click(await screen.findByText('POST api.example.com/pkg.UserService/GetUser'))
    const dialog = await screen.findByRole('dialog')
    await within(dialog).findByText('HTTP 事件详情（#201）')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })
    expect((hostInput as HTMLInputElement).value).toBe('api.example.com')
    const urls = httpEventListUrls()
    expect(urls[urls.length - 1]).toContain('host=api.example.com')
    expect(urls[urls.length - 1]).toContain('page=1')
  })
})

describe('P1-03 G4a：Agent 详情能力集与版本分离', () => {
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

  it('能力集 [1,2]：协议 v1/v2 标签，无「需升级」；目标/实载版本分离显示待同步', async () => {
    vi.stubGlobal('fetch', mockFetch(makeAgentDetail([1, 2])))
    renderWithProviders(
      <AgentDetailDrawer agentId={AGENT_ID} open onClose={() => {}} canManage />,
    )
    await screen.findByText('HTTP 事件能力')
    expect(screen.getByText('协议 v1')).toBeInTheDocument()
    expect(screen.getByText('协议 v2')).toBeInTheDocument()
    expect(screen.getByText('操作系统')).toBeInTheDocument()
    expect(screen.queryByText('schema v1')).not.toBeInTheDocument()
    expect(screen.queryByText('需升级')).not.toBeInTheDocument()
    // 保存/目标版本/实际加载分离：config_version=5、applied=3 → 待同步
    expect(screen.getByText('服务端目标版本')).toBeInTheDocument()
    expect(screen.getByText('Agent 已加载版本')).toBeInTheDocument()
    expect(screen.getByText('待同步')).toBeInTheDocument()
    expect(screen.getByText(/已保存策略版本 v4/)).toBeInTheDocument()
  })

  it('能力集 [1]（旧 Agent）：显示「需升级」标签', async () => {
    vi.stubGlobal('fetch', mockFetch(makeAgentDetail([1])))
    renderWithProviders(
      <AgentDetailDrawer agentId={AGENT_ID} open onClose={() => {}} canManage />,
    )
    await screen.findByText('HTTP 事件能力')
    expect(screen.getByText('需升级')).toBeInTheDocument()
    expect(screen.queryByText('协议 v2')).not.toBeInTheDocument()
  })
})

describe('P1-03 G4a：资产来源面板', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['traffic.agents.view']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('关联状态独立展示（未绑定/配额拒绝），state 过滤发起请求', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderWithProviders(<HttpAssetSourcesPanel agentId={AGENT_ID} enabled />)
    await screen.findByText('api.example.com POST /pkg.UserService/GetUser')
    expect(screen.getByText('未绑定')).toBeInTheDocument()
    expect(screen.getByText('配额拒绝')).toBeInTheDocument()
    // 失败原因经 Tooltip 展示（hover 后可见）
    fireEvent.mouseOver(screen.getByText('原因'))
    expect(await screen.findByText('license quota exceeded')).toBeInTheDocument()
    // 状态过滤（下拉选项经 portal 渲染，按 title/textContent 比对）
    const select = screen.getByText('按关联状态过滤').closest('.ant-select')!
    fireEvent.mouseDown(select.querySelector('[role="combobox"]')!)
    await waitFor(() => {
      expect(
        Array.from(document.querySelectorAll('.ant-select-item-option')).some(
          (el) => el.textContent === '配额拒绝' && !el.closest('.ant-select-dropdown')?.className.includes('hidden'),
        ),
      ).toBe(true)
    })
    const option = Array.from(
      document.querySelectorAll('.ant-select-item-option'),
    ).find(
      (el) => el.textContent === '配额拒绝' && !el.closest('.ant-select-dropdown')?.className.includes('hidden'),
    )!
    fireEvent.click(option)
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some((c) =>
          String(c[0]).includes('http-asset-sources') &&
          String(c[0]).includes('state=QUOTA_REJECTED'),
        ),
      ).toBe(true)
    })
  })
})
