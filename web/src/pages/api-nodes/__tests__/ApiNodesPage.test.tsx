import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiNodesPage from '../ApiNodesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const nodeA = {
  id: 'n1',
  node_name: 'gw-node-a',
  first_seen_at: '2026-08-01T02:00:00Z',
  last_seen_at: '2026-08-19T10:00:00Z',
  last_policy_version: 'pv-2026-08-19-aaaa',
  last_model_version: 'mv-7',
  event_count: 15234,
  status: 'ACTIVE',
  admin_addr: '10.0.0.11:2019',
  sync_agent_addr: '',
  has_sync_secret: false,
  reported_version: '1.12.0',
  sync_enabled: true,
  last_sync_at: '2026-08-19T09:55:00Z',
  last_sync_result: 'SUCCESS',
  last_sync_error: '',
  last_sync_version_id: 'v-2026-08-19-1',
  version_consistent: true,
  created_at: '2026-08-01T02:00:00Z',
  updated_at: '2026-08-19T10:00:00Z',
}

const nodeB = {
  id: 'n2',
  node_name: 'gw-node-b',
  first_seen_at: '2026-08-02T02:00:00Z',
  last_seen_at: '2026-08-19T09:00:00Z',
  last_policy_version: 'pv-2026-08-18-bbbb',
  last_model_version: '',
  event_count: 8301,
  status: 'STALE',
  admin_addr: '10.0.0.12:2019',
  sync_agent_addr: 'https://10.0.0.12:18443',
  has_sync_secret: true,
  reported_version: '1.12.0',
  sync_enabled: true,
  last_sync_at: '2026-08-19T09:50:00Z',
  last_sync_result: 'FAILED',
  last_sync_error: 'dial tcp 10.0.0.12:2019: connect timeout',
  last_sync_version_id: 'v-2026-08-19-1',
  version_consistent: false,
  created_at: '2026-08-02T02:00:00Z',
  updated_at: '2026-08-19T09:00:00Z',
}

const nodeC = {
  id: 'n3',
  node_name: 'gw-node-c',
  first_seen_at: '2026-08-03T02:00:00Z',
  last_seen_at: '2026-08-18T01:00:00Z',
  last_policy_version: '',
  last_model_version: '',
  event_count: 120,
  status: 'SILENT',
  admin_addr: '',
  sync_agent_addr: '',
  has_sync_secret: false,
  reported_version: '',
  sync_enabled: false,
  last_sync_at: null,
  last_sync_result: '',
  last_sync_error: '',
  last_sync_version_id: null,
  version_consistent: null,
  created_at: '2026-08-03T02:00:00Z',
  updated_at: '2026-08-18T01:00:00Z',
}

const inconsistentReport = {
  consistent: false,
  evaluated_nodes: 2,
  dominant_version: 'pv-2026-08-19-aaaa',
  groups: [
    { policy_version: 'pv-2026-08-19-aaaa', node_count: 1, nodes: ['gw-node-a'] },
    { policy_version: 'pv-2026-08-18-bbbb', node_count: 1, nodes: ['gw-node-b'] },
  ],
  silent_nodes: ['gw-node-c'],
  generated_at: '2026-08-19T10:05:00Z',
}

const consistentReport = {
  consistent: true,
  evaluated_nodes: 2,
  dominant_version: 'pv-2026-08-19-aaaa',
  groups: [
    { policy_version: 'pv-2026-08-19-aaaa', node_count: 2, nodes: ['gw-node-a', 'gw-node-b'] },
  ],
  silent_nodes: [],
  generated_at: '2026-08-19T10:05:00Z',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiNodesPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiNodesPage', () => {
  /** 当前用例的一致性报告（beforeEach 置为不一致场景） */
  let report: typeof inconsistentReport
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    report = inconsistentReport
    fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const method = (init?.method ?? 'GET').toUpperCase()
      if (method === 'GET' && url.includes('/api-security/nodes/consistency')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: report }))
      }
      if (method === 'GET' && url.endsWith('/api-security/nodes')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              items: [nodeA, nodeB, nodeC],
              total: 3,
              consistent: report.consistent,
              evaluated_nodes: report.evaluated_nodes,
            },
          }),
        )
      }
      if (method === 'GET' && url.endsWith('/gateway-config/current')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              has_current: true,
              version: {
                id: 'ver-current-1',
                version_number: 'v20261124-01',
                configuration_hash: 'h1',
                business_snapshot: '{}',
                change_summary: '',
                publish_result: 'SUCCESS',
                is_current: true,
                created_at: '2026-11-24T11:00:00Z',
              },
            },
          }),
        )
      }
      if (method === 'POST' && url.endsWith('/api-security/nodes')) {
        return Promise.resolve(jsonResponse(201, { code: 'SUCCESS', message: 'ok', data: nodeB }))
      }
      if (method === 'PATCH' && url.includes('/api-security/nodes/')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: nodeB }))
      }
      if (method === 'POST' && url.endsWith('/api-security/nodes/n2/test')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              ok: true,
              channel: 'hasyncd',
              latency_ms: 18,
              version: '1.12.0',
              caddy_reachable: true,
              hostctl_ready: true,
              upgrade_ready: true,
            },
          }),
        )
      }
      if (method === 'POST' && url.endsWith('/config-versions/ver-current-1/retry-sync')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              version_id: 'ver-current-1',
              node_id: 'n2',
              attempted: 1,
              succeeded: 1,
              failed: 0,
              record_failures: 0,
            },
          }),
        )
      }
      if (method === 'DELETE' && url.endsWith('/api-security/nodes/n2')) {
        return Promise.resolve(
          jsonResponse(409, {
            code: 'RESOURCE_CONFLICT',
            message: '该节点仍归属主备高可用组，请先从主备组移除',
          }),
        )
      }
      return Promise.reject(new Error(`unexpected request: ${method} ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.setState({
      user: makeUser(['api_runtime.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('节点列表：状态标签/最近事件时间/版本截断/逐项一致性标记/协同字段', async () => {
    renderPage()
    await screen.findByText(/节点策略版本不一致/)
    // 节点列表为第二个表格（第一个是一致性分组对比表），按表消歧
    const tables = document.querySelectorAll('.ant-table')
    const listTable = tables[tables.length - 1] as HTMLElement

    const rowA = within(listTable).getByText('gw-node-a').closest('tr') as HTMLElement
    expect(within(rowA).getByText('活跃')).toBeInTheDocument()
    expect(within(rowA).getByText('pv-2026-08-19-aaaa')).toBeInTheDocument()
    expect(within(rowA).getByText('mv-7')).toBeInTheDocument()
    expect(within(rowA).getByText('15234')).toBeInTheDocument()
    expect(within(rowA).getByText('一致')).toBeInTheDocument()
    expect(within(rowA).getByText('1.12.0')).toBeInTheDocument()
    expect(rowA.textContent).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/)

    const rowB = within(listTable).getByText('gw-node-b').closest('tr') as HTMLElement
    expect(within(rowB).getByText('停滞')).toBeInTheDocument()
    expect(within(rowB).getByText('不一致')).toBeInTheDocument()
    expect(within(rowB).getByText('https://10.0.0.12:18443')).toBeInTheDocument()
    expect(within(rowB).getByText('已设密钥')).toBeInTheDocument()
    expect(within(rowB).getAllByText('-').length).toBeGreaterThanOrEqual(1)

    const rowC = within(listTable).getByText('gw-node-c').closest('tr') as HTMLElement
    expect(within(rowC).getByText('静默')).toBeInTheDocument()
    expect(within(rowC).queryByText('一致')).not.toBeInTheDocument()
  })

  it('节点列表：配置同步状态列（成功/失败/未参与）', async () => {
    renderPage()
    await screen.findByText(/节点策略版本不一致/)
    const tables = document.querySelectorAll('.ant-table')
    const listTable = tables[tables.length - 1] as HTMLElement

    const rowA = within(listTable).getByText('gw-node-a').closest('tr') as HTMLElement
    expect(within(rowA).getByText('成功')).toBeInTheDocument()

    const rowB = within(listTable).getByText('gw-node-b').closest('tr') as HTMLElement
    expect(within(rowB).getByText('失败')).toBeInTheDocument()

    // 未参与发布扇出（sync_enabled=false）如实展示，不谎报同步结果
    const rowC = within(listTable).getByText('gw-node-c').closest('tr') as HTMLElement
    expect(within(rowC).getByText('未参与')).toBeInTheDocument()
  })

  it('一致性横幅：不一致时红色告警 + 分组对比表 + 静默节点列出', async () => {
    renderPage()
    expect(await screen.findByText(/节点策略版本不一致/)).toBeInTheDocument()
    const table = document.querySelector('.ant-table') as HTMLElement
    expect(within(table).getByText('pv-2026-08-18-bbbb')).toBeInTheDocument()
    expect(screen.getByText(/静默节点（离线不参与判定）：gw-node-c/)).toBeInTheDocument()
  })

  it('一致性横幅：一致时成功提示（含参与判定节点数与多数派版本）', async () => {
    report = consistentReport
    renderPage()
    expect(
      await screen.findByText(/活跃节点策略版本一致（2 个参与判定，版本 pv-2026-08-19-aaaa）/),
    ).toBeInTheDocument()
    expect(screen.queryByText(/节点策略版本不一致/)).not.toBeInTheDocument()
  })

  it('只读权限用户隐藏新增按钮并禁用管理操作', async () => {
    renderPage()
    await screen.findByText('https://10.0.0.12:18443')
    expect(screen.queryByRole('button', { name: /新增节点/ })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '编辑-gw-node-b' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '连通测试-gw-node-b' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '重试同步-gw-node-b' })).toBeDisabled()
    expect(screen.getByRole('button', { name: '删除-gw-node-b' })).toBeDisabled()
  })

  it('新增节点：校验 HMAC 密钥为 ≥64 位十六进制并发送 POST /api/v1/api-security/nodes', async () => {
    useAuthStore.setState({
      user: makeUser(['api_runtime.read', 'api_policy.publish']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新增节点/ }))

    fireEvent.change(await screen.findByPlaceholderText('如 gw-standby-01'), {
      target: { value: 'gw-node-d' },
    })
    fireEvent.change(screen.getByPlaceholderText('如 https://10.0.0.12:18443'), {
      target: { value: 'https://10.0.0.14:18443' },
    })

    const secretInput = screen.getByPlaceholderText('64 位及以上十六进制密钥')
    fireEvent.change(secretInput, { target: { value: 'short-secret' } })
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))
    expect(
      await screen.findByText(/HMAC 密钥必须为至少 64 位十六进制字符/),
    ).toBeInTheDocument()

    const validSecret = 'a'.repeat(64)
    fireEvent.change(secretInput, { target: { value: validSecret } })
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([u, init]) =>
            String(u) === '/api/v1/api-security/nodes' &&
            (init as RequestInit)?.method === 'POST',
        ),
      ).toBe(true),
    )
    const createCall = fetchMock.mock.calls.find(
      ([u, init]) =>
        String(u) === '/api/v1/api-security/nodes' && (init as RequestInit)?.method === 'POST',
    )!
    expect(JSON.parse(String((createCall[1] as RequestInit).body))).toEqual({
      node_name: 'gw-node-d',
      sync_agent_addr: 'https://10.0.0.14:18443',
      sync_secret: validSecret,
      sync_enabled: true,
    })
  })

  it('编辑节点同步配置：留空保留原密钥，勾选清除密钥发送空串', async () => {
    useAuthStore.setState({
      user: makeUser(['api_runtime.read', 'ha.manage']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '编辑-gw-node-b' }))
    expect(await screen.findByPlaceholderText('已配置（留空不变更）')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.filter(
          ([u, init]) =>
            String(u) === '/api/v1/api-security/nodes/n2' &&
            (init as RequestInit)?.method === 'PATCH',
        ).length,
      ).toBe(1),
    )
    const firstPatch = fetchMock.mock.calls.find(
      ([u, init]) =>
        String(u) === '/api/v1/api-security/nodes/n2' &&
        (init as RequestInit)?.method === 'PATCH',
    )!
    expect(JSON.parse(String((firstPatch[1] as RequestInit).body)).sync_secret).toBeUndefined()

    // 勾选清除已有同步密钥 -> 发送 sync_secret: ''
    fireEvent.click(screen.getByRole('button', { name: '编辑-gw-node-b' }))
    fireEvent.click(await screen.findByLabelText('清除已有同步密钥'))
    fireEvent.click(screen.getByRole('button', { name: /^保\s*存$/ }))

    await waitFor(() =>
      expect(
        fetchMock.mock.calls.filter(
          ([u, init]) =>
            String(u) === '/api/v1/api-security/nodes/n2' &&
            (init as RequestInit)?.method === 'PATCH',
        ).length,
      ).toBe(2),
    )
    const patchCalls = fetchMock.mock.calls.filter(
      ([u, init]) =>
        String(u) === '/api/v1/api-security/nodes/n2' &&
        (init as RequestInit)?.method === 'PATCH',
    )
    expect(JSON.parse(String((patchCalls[1][1] as RequestInit).body)).sync_secret).toBe('')
  })

  it('行内同步开关、连通测试、定向重试同步与删除冲突提示', async () => {
    useAuthStore.setState({
      user: makeUser(['api_runtime.read', 'api_policy.publish', 'gateway_configs.publish']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()

    // 切换 gw-node-c 同步开关
    const sw = await screen.findByRole('switch', { name: '同步开关-gw-node-c' })
    fireEvent.click(sw)
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([u, init]) =>
            String(u) === '/api/v1/api-security/nodes/n3' &&
            (init as RequestInit)?.method === 'PATCH' &&
            JSON.parse(String((init as RequestInit).body)).sync_enabled === true,
        ),
      ).toBe(true),
    )

    // 连通测试 gw-node-b
    fireEvent.click(screen.getByRole('button', { name: '连通测试-gw-node-b' }))
    expect(await screen.findByText('节点连通性检测通过')).toBeInTheDocument()
    expect(screen.getByText('hasyncd 协同代理')).toBeInTheDocument()
    expect(screen.getByText('18 ms')).toBeInTheDocument()
    expect(screen.getByText('可达')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^关\s*闭$/ }))

    // 重试同步 gw-node-b -> POST /api/v1/config-versions/ver-current-1/retry-sync
    fireEvent.click(screen.getByRole('button', { name: '重试同步-gw-node-b' }))
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some(
          ([u, init]) =>
            String(u) === '/api/v1/config-versions/ver-current-1/retry-sync' &&
            (init as RequestInit)?.method === 'POST' &&
            JSON.parse(String((init as RequestInit).body)).node_id === 'n2',
        ),
      ).toBe(true),
    )

    // 删除 gw-node-b -> 二次确认后展示 409 冲突提示
    fireEvent.click(screen.getByRole('button', { name: '删除-gw-node-b' }))
    expect((await screen.findAllByText('删除网关节点「gw-node-b」？')).length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: /^删\s*除$/ }))
    expect(
      await screen.findByText('该节点仍归属主备高可用组，请先从主备组移除'),
    ).toBeInTheDocument()
  })
})
