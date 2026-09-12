import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
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
  groups: [{ policy_version: 'pv-2026-08-19-aaaa', node_count: 2, nodes: ['gw-node-a', 'gw-node-b'] }],
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

  beforeEach(() => {
    report = inconsistentReport
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/nodes/consistency')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: report }))
        }
        if (url.includes('/api-security/nodes')) {
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
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('节点列表：状态标签/最近事件时间/版本截断/逐项一致性标记', async () => {
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
    expect(rowA.textContent).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/)

    const rowB = within(listTable).getByText('gw-node-b').closest('tr') as HTMLElement
    expect(within(rowB).getByText('停滞')).toBeInTheDocument()
    expect(within(rowB).getByText('不一致')).toBeInTheDocument()
    // 未上报模型版本渲染占位符
    expect(within(rowB).getByText('-')).toBeInTheDocument()

    const rowC = within(listTable).getByText('gw-node-c').closest('tr') as HTMLElement
    expect(within(rowC).getByText('静默')).toBeInTheDocument()
    // 未参与判定（version_consistent 为 null）渲染占位符
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
    // 分组对比表：版本 + 归属节点
    const table = document.querySelector('.ant-table') as HTMLElement
    expect(within(table).getByText('pv-2026-08-18-bbbb')).toBeInTheDocument()
    // 静默节点如实列出（不参与判定）
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
})
