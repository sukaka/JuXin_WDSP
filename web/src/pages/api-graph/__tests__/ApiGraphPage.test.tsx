import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApiGraphPage from '../ApiGraphPage'
import { buildEndpointDisplayLabel, prepareIdentityGraph } from '../graphUtils'
import type { ApiGraphEdge, ApiGraphNode } from '../../../api/apiSecurity'

vi.mock('../../../components/EChart', () => ({
  default: ({ ariaLabel }: { ariaLabel: string }) => (
    <div data-testid="echart-stub" aria-label={ariaLabel} />
  ),
}))

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const RPC_GRAPH_DATA = {
  start: '2026-11-24T01:00:00Z',
  end: '2026-11-24T02:00:00Z',
  nodes: [
    {
      id: 'order-svc',
      name: 'order-svc',
      node_type: 'SERVICE',
      protocols: ['GRPC'],
      inbound_calls: 0,
      outbound_calls: 120,
      inbound_edges: 0,
      outbound_edges: 1,
      error_count: 0,
      error_rate: 0,
      avg_ms: 0,
      operations_count: 0,
    },
    {
      id: 'inventory-svc',
      name: 'inventory-svc',
      node_type: 'SERVICE',
      protocols: ['GRPC'],
      inbound_calls: 120,
      outbound_calls: 0,
      inbound_edges: 1,
      outbound_edges: 0,
      error_count: 8,
      error_rate: 0.067,
      avg_ms: 14.5,
      operations_count: 1,
    },
  ],
  edges: [
    {
      id: 'order-svc->inventory-svc|GRPC',
      source: 'order-svc',
      target: 'inventory-svc',
      target_type: 'SERVICE',
      protocol: 'GRPC',
      call_category: 'RPC',
      evidence_type: 'OTEL_SPAN_PAIRED',
      paired: true,
      data_source: 'otel_traces',
      calls: 120,
      error_count: 8,
      error_rate: 0.067,
      avg_ms: 14.5,
      p95_ms: 32.0,
      operations: ['inventory.StockService/Reserve'],
      sample_trace_ids: ['11111111111111111111111111111111'],
      first_seen_at: '2026-11-24T01:10:00Z',
      last_seen_at: '2026-11-24T01:55:00Z',
    },
  ],
  summary: {
    total_nodes: 2,
    service_nodes: 2,
    external_nodes: 0,
    total_edges: 1,
    rpc_edges: 1,
    http_edges: 0,
    paired_edges: 1,
    error_edges: 1,
    total_calls: 120,
    total_errors: 8,
    truncated: false,
  },
  sources: [
    { source: 'otel_traces', label: 'OTel 分布式追踪', status: 'READY', edge_count: 1 },
    { source: 'agent_dataflow', label: '云 API Sensor 数据流', status: 'EMPTY', edge_count: 0 },
    { source: 'agent_grpc', label: '流量 Agent gRPC 观测', status: 'EMPTY', edge_count: 0 },
  ],
  note: '基于 OTel 分布式追踪双端 Span 配对汇聚生成',
}

const IDENTITY_GRAPH_DATA = {
  nodes: [
    {
      id: 'ep-1',
      endpoint_key: 'POST /api/v1/login',
      http_method: 'POST',
      normalized_path: '/api/v1/login',
      application_id: 'app-1',
      application_name: '门户应用',
      host: 'portal.example.com',
      protocol_type: 'REST',
      is_api: true,
      asset_status: 'CONFIRMED',
      hit_count: 200,
    },
    {
      id: 'ep-2',
      endpoint_key: 'GET /api/v1/orders',
      http_method: 'GET',
      normalized_path: '/api/v1/orders',
      application_id: 'app-1',
      application_name: '门户应用',
      host: 'portal.example.com',
      protocol_type: 'REST',
      is_api: true,
      asset_status: 'DISCOVERED',
      hit_count: 180,
    },
  ],
  edges: [
    {
      id: 'edge-1',
      caller_fingerprint: 'fp-alice-12345678',
      source_endpoint_id: 'ep-1',
      target_endpoint_id: 'ep-2',
      call_count: 15,
      identity_count: 1,
      last_seen_at: '2026-11-24T01:50:00Z',
    },
  ],
  summary: {
    total_nodes: 697,
    visible_nodes: 2,
    static_noise_nodes: 410,
    ignored_nodes: 12,
    isolated_nodes: 273,
    total_edges: 482,
    visible_edges: 1,
  },
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/api-graph']}>
          <ApiGraphPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApiGraphPage', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('默认优先展示后端微服务真实 RPC 调用图谱与数据源状态', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/service-rpc-graph')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: RPC_GRAPH_DATA }))
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderPage()

    expect(await screen.findByText('order-svc')).toBeInTheDocument()
    expect(screen.getByText('inventory-svc')).toBeInTheDocument()
    expect(screen.getByText('inventory.StockService/Reserve')).toBeInTheDocument()
    expect(screen.getByText('OTel 双端配对')).toBeInTheDocument()
    expect(screen.getByText('OTel 分布式追踪：已接入 (1 边)')).toBeInTheDocument()
    expect(screen.getByTestId('echart-stub')).toHaveAttribute('aria-label', '后端微服务真实 RPC 调用关系图')
  })

  it('无微服务 RPC 数据时诚实展示空态与接入引导', async () => {
    const emptyData = {
      ...RPC_GRAPH_DATA,
      nodes: [],
      edges: [],
      summary: { ...RPC_GRAPH_DATA.summary, total_nodes: 0, service_nodes: 0, total_edges: 0, rpc_edges: 0, paired_edges: 0, error_edges: 0, total_calls: 0 },
      sources: [
        { source: 'otel_traces', label: 'OTel 分布式追踪', status: 'NOT_CONFIGURED', edge_count: 0, message: '未配置 ClickHouse' },
      ],
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: emptyData }))),
    )

    renderPage()

    expect(await screen.findByText('当前时间窗内暂未采集到后端微服务 RPC / 服务间调用链路')).toBeInTheDocument()
    expect(screen.getByText('前往 APM 探针接入')).toBeInTheDocument()
    expect(screen.getByText('查看用户身份访问轨迹')).toBeInTheDocument()
  })

  it('切换到用户身份 10 分钟轨迹视图时默认带静态过滤与孤立点过滤参数并展示清理提示', async () => {
    const requestedUrls: string[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        requestedUrls.push(url)
        if (url.includes('/api-security/service-rpc-graph')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: RPC_GRAPH_DATA }))
        }
        if (url.includes('/applications')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [{ id: 'app-1', name: '门户应用' }], total: 1 } }))
        }
        if (url.includes('/api-security/graph')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: IDENTITY_GRAPH_DATA }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderPage()
    await screen.findByText('order-svc')

    fireEvent.click(screen.getByText('用户身份访问轨迹（10 分钟窗口）'))

    expect(await screen.findByText('POST /api/v1/login')).toBeInTheDocument()
    expect(screen.getByText('GET /api/v1/orders')).toBeInTheDocument()
    expect(screen.getByText('去清理 410 个存量静态噪声')).toBeInTheDocument()

    await waitFor(() => {
      const graphCall = requestedUrls.find((u) => u.includes('/api-security/graph'))
      expect(graphCall).toContain('exclude_static=true')
      expect(graphCall).toContain('exclude_ignored=true')
      expect(graphCall).toContain('only_connected=true')
    })
  })
})

describe('graphUtils', () => {
  it('同名 endpoint_key 附带应用/Host 消歧，且画布自动合并多身份同向边', () => {
    const nodes: ApiGraphNode[] = [
      { id: 'n1', endpoint_key: 'GET /customer', http_method: 'GET', normalized_path: '/customer', asset_status: 'DISCOVERED', application_name: '门户A', host: 'a.example.com' },
      { id: 'n2', endpoint_key: 'GET /customer', http_method: 'GET', normalized_path: '/customer', asset_status: 'DISCOVERED', application_name: '后台B', host: 'b.example.com' },
      { id: 'n3', endpoint_key: 'POST /api/orders', http_method: 'POST', normalized_path: '/api/orders', asset_status: 'CONFIRMED', application_name: '门户A', host: 'a.example.com' },
    ]
    const edges: ApiGraphEdge[] = [
      { id: 'e1', caller_fingerprint: 'u1', source_endpoint_id: 'n1', target_endpoint_id: 'n3', call_count: 5 },
      { id: 'e2', caller_fingerprint: 'u2', source_endpoint_id: 'n1', target_endpoint_id: 'n3', call_count: 7 },
    ]
    const prepared = prepareIdentityGraph(nodes, edges, 60)
    expect(prepared.duplicateKeySet.has('GET /customer')).toBe(true)
    expect(buildEndpointDisplayLabel(nodes[0], prepared.duplicateKeySet)).toBe('GET /customer [门户A · a.example.com]')
    expect(buildEndpointDisplayLabel(nodes[2], prepared.duplicateKeySet)).toBe('POST /api/orders')
    expect(prepared.aggregatedEdges).toHaveLength(1)
    expect(prepared.aggregatedEdges[0].totalCalls).toBe(12)
    expect(prepared.aggregatedEdges[0].callerCount).toBe(2)
  })
})
