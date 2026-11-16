import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import ApiDataFlowPage from '../ApiDataFlowPage'
import type { DataFlowEvidenceRecord, DataFlowGraph } from '../../../api/apiDataFlow'

vi.mock('../../../components/EChart', () => ({
  default: () => <div data-testid="echart-stub" />,
}))

const NOW = '2026-11-04T01:00:00Z'
const EDGE = {
  id: 'edge-1', source_id: 'service:orders', target_id: 'service:profile',
  source_name: 'orders', target_name: 'profile', protocol: 'HTTP', method: 'POST',
  path_template: '/profiles/{id}', apis: ['POST /profiles/{id}'], calls: 2, errors: 0, avg_latency_ms: 12,
  max_latency_ms: 20, data_types: ['PHONE', 'CN_ID', 'EMAIL'], fields: [
    { side: 'REQUEST', path: '$.customer.mobile', data_type: 'PHONE', value_hmac: 'hmac-sha256:abc', hmac_key_id: 'key-1', match: 'CORRELATED_FIELD' },
    { side: 'RESPONSE', path: '$.identity_no', data_type: 'CN_ID', value_hmac: 'hmac-sha256:def', hmac_key_id: 'key-1', match: 'OBSERVED' },
    { side: 'MESSAGE', path: '$.customer.email', data_type: 'EMAIL', value_hmac: 'hmac-sha256:ghi', hmac_key_id: 'key-1', match: 'OBSERVED' },
  ],
  evidence_type: 'OBSERVED_TRACE', confidence: 0.98,
  first_seen_at: NOW, last_seen_at: NOW, sample_trace_ids: ['a'.repeat(32)],
}
const GRAPH = {
  nodes: [
    { id: 'service:orders', name: 'orders', type: 'SERVICE', service_name: 'orders', group_name: 'prod / shop', addresses: ['10.20.0.10'], environment: 'prod', namespace: 'shop', cluster: 'cloud-a', calls: 2, api_count: 1, avg_latency_ms: 12, max_latency_ms: 20, error_rate: 0, health: 'HEALTHY', incoming_count: 0, outgoing_count: 1 },
    { id: 'service:profile', name: 'profile', type: 'SERVICE', calls: 2, api_count: 1, avg_latency_ms: 12, max_latency_ms: 20, error_rate: 0, health: 'HEALTHY', incoming_count: 1, outgoing_count: 0 },
  ],
  edges: [EDGE],
  truncated: false,
  quality: { observations: 3, trace_linked: 2, trace_coverage: 2 / 3, truncated: 0, data_source: 'clickhouse', partial: true, message: '部分观测没有 Trace 关联' },
}
const EVIDENCE: { items: DataFlowEvidenceRecord[]; total: number } = {
  items: [{
    agent_id: 'agent-1', event_id: 'ev-1', edge_id: 'edge-1', occurred_at: NOW,
    service_name: 'orders', trace_id: 'a'.repeat(32), span_id: 'b'.repeat(16),
    fields: [
      { side: 'REQUEST', path: '$.customer.mobile', data_type: 'PHONE', value_hmac: 'hmac-sha256:abc', hmac_key_id: 'key-1', match: 'CORRELATED_FIELD' },
      { side: 'MESSAGE', path: '$.customer.email', data_type: 'EMAIL', value_hmac: 'hmac-sha256:ghi', hmac_key_id: 'key-1', match: 'OBSERVED' },
    ],
    evidence_type: 'OBSERVED_TRACE', confidence: 0.98,
  }],
  total: 1,
}

const BOUNDARY_GRAPH: DataFlowGraph = {
  ...GRAPH,
  view: 'boundary',
  nodes: [
    { ...GRAPH.nodes[0], id: 'client:public', name: '外部调用方', type: 'CLIENT', network_zone: 'PUBLIC' },
    { ...GRAPH.nodes[1], network_zone: 'INTERNAL' },
  ],
  edges: [{
    ...EDGE,
    source_id: 'client:public',
    source_name: '外部调用方',
    source_zone: 'PUBLIC',
    target_zone: 'INTERNAL',
    boundary_type: 'PUBLIC_TO_INTERNAL',
    boundary_evidence: 'DIRECT_PEER',
  }],
}

const BOUNDARY_EVIDENCE: { items: DataFlowEvidenceRecord[]; total: number } = {
  items: [{
    ...EVIDENCE.items[0],
    service_name: '外部调用方',
    peer_address: '203.0.113.10',
    client_address: '203.0.113.10',
    client_address_source: 'DIRECT_PEER',
    server_address: '10.20.0.10',
    source_zone: 'PUBLIC',
    target_zone: 'INTERNAL',
    boundary_type: 'PUBLIC_TO_INTERNAL',
    boundary_evidence: 'DIRECT_PEER',
  }],
  total: 1,
}

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockFetch(graph: DataFlowGraph = GRAPH, evidence: { items: DataFlowEvidenceRecord[]; total: number } = EVIDENCE) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = String(input)
    if (url.includes('/api/v1/applications?')) return Promise.resolve(jsonResponse({ items: [{ id: 'app1', code: 'cloud-dataflow', name: 'Cloud Dataflow Test' }], page: 1, page_size: 100, total: 1 }))
    if (url.includes('/data-flow/graph')) return Promise.resolve(jsonResponse(graph))
    if (url.includes('/data-flow/nodes/')) return Promise.resolve(jsonResponse({ node: graph.nodes[0] ?? GRAPH.nodes[0], dependencies: graph.edges, called_by: [] }))
    if (url.includes('/data-flow/evidence')) return Promise.resolve(jsonResponse(evidence))
    return Promise.reject(new Error(`unexpected URL: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/api-data-flow']}>
          <ApiDataFlowPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('ApiDataFlowPage', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('渲染系统级图数据、质量提示和上下游详情', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    expect(await screen.findByTestId('echart-stub')).toBeInTheDocument()
    expect(screen.getByText(/展示独立业务系统之间的 API 调用/)).toBeInTheDocument()
    expect(screen.getByText('调用证据不完整')).toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: 'orders · 2 次' }))
    expect(await screen.findByText('orders · 系统详情')).toBeInTheDocument()
    expect(await screen.findByText('调用的下游（1）')).toBeInTheDocument()
    expect(screen.getAllByText('orders → profile（2 次）').length).toBeGreaterThan(0)
    expect(screen.getByText('POST /profiles/{id}')).toBeInTheDocument()
  })

  it('关系明细区分请求、响应与消息敏感数据，并可打开脱敏证据', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    await screen.findByTestId('echart-stub')
    fireEvent.click(screen.getByRole('radio', { name: '边明细' }))
    expect(await screen.findByRole('columnheader', { name: /请求敏感数据/ })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /响应敏感数据/ })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /消息敏感数据/ })).toBeInTheDocument()
    expect(screen.getAllByText('手机号').length).toBeGreaterThan(0)
    expect(screen.getAllByText('身份证号').length).toBeGreaterThan(0)
    expect(screen.getAllByText('邮箱').length).toBeGreaterThan(0)
    fireEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    expect(await screen.findByText('$.customer.mobile')).toBeInTheDocument()
    expect(screen.getByText('hmac-sha256:abc')).toBeInTheDocument()
    expect(screen.getByText(/消息：orders → profile/)).toBeInTheDocument()
    expect(screen.getAllByText(`Trace: ${'a'.repeat(32)}`).length).toBeGreaterThan(0)
  })

  it('纯 HTTP 主图无消息字段时不显示空消息列', async () => {
    const httpOnlyGraph = {
      ...GRAPH,
      edges: [{
        ...EDGE,
        data_types: ['PHONE', 'CN_ID'],
        fields: EDGE.fields.filter((field) => field.side !== 'MESSAGE'),
      }],
    }
    vi.stubGlobal('fetch', mockFetch(httpOnlyGraph))
    renderPage()
    await screen.findByTestId('echart-stub')
    fireEvent.click(screen.getByRole('radio', { name: '边明细' }))
    expect(await screen.findByRole('columnheader', { name: /请求敏感数据/ })).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: /响应敏感数据/ })).toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: /消息敏感数据/ })).toBeNull()
  })

  it('应用筛选进入真实查询参数，重置后清除', async () => {
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderPage()
    await screen.findByTestId('echart-stub')
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '应用' }))
    fireEvent.click(await screen.findByText('Cloud Dataflow Test (cloud-dataflow)'))
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/data-flow/graph?') && String(input).includes('application_id=app1'))).toBe(true))
    const filteredCalls = fetchMock.mock.calls.length
    fireEvent.click(screen.getByRole('button', { name: /重\s*置/ }))
    await waitFor(() => expect(fetchMock.mock.calls.slice(filteredCalls).some(([input]) => String(input).includes('/data-flow/graph?') && !String(input).includes('application_id='))).toBe(true))
  })

  it('采集信息页保留真实环境和主机地址，但不作为系统分组', async () => {
    vi.stubGlobal('fetch', mockFetch())
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: 'orders · 2 次' }))
    fireEvent.click(await screen.findByRole('tab', { name: '采集信息' }))
    expect(await screen.findByText('10.20.0.10')).toBeInTheDocument()
    expect(screen.queryByText('prod / shop')).toBeNull()
    expect(screen.getByText('cloud-a')).toBeInTheDocument()
  })

  it('选择内外网边界后实际查询 view=boundary', async () => {
    const fetchMock = mockFetch()
    vi.stubGlobal('fetch', fetchMock)
    renderPage()
    await screen.findByTestId('echart-stub')
    fireEvent.mouseDown(screen.getByRole('combobox', { name: '拓扑视图' }))
    fireEvent.click(await screen.findByText('内外网边界'))
    fireEvent.click(screen.getByRole('button', { name: /查\s*询/ }))
    await waitFor(() => expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/data-flow/graph?') && String(input).includes('view=boundary'))).toBe(true))
  })

  it('公网到内网详情展示方向、独立地址与证据，并保留脱敏字段和 Trace', async () => {
    vi.stubGlobal('fetch', mockFetch(BOUNDARY_GRAPH, BOUNDARY_EVIDENCE))
    renderPage()
    expect(await screen.findByRole('region', { name: '内外网边界调用图' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: '边明细' }))
    fireEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    const title = await screen.findByText('外部调用方 → profile', { selector: '.ant-drawer-title' })
    const drawer = title.closest('.data-flow-detail-drawer') as HTMLElement
    expect(drawer).not.toBeNull()
    expect(within(drawer).getByText('边界类型')).toBeInTheDocument()
    expect(within(drawer).getAllByText(/公网 → 内网/).length).toBeGreaterThan(0)
    expect(await within(drawer).findByText('client_address')).toBeInTheDocument()
    expect(within(drawer).getByText('peer_address')).toBeInTheDocument()
    expect(within(drawer).getByText('server_address')).toBeInTheDocument()
    expect(within(drawer).getByText('client_address_source')).toBeInTheDocument()
    expect(within(drawer).getAllByText('203.0.113.10')).toHaveLength(2)
    expect(within(drawer).getByText('10.20.0.10')).toBeInTheDocument()
    expect(within(drawer).getAllByText(/DIRECT_PEER/).length).toBeGreaterThan(0)
    expect(drawer).not.toHaveTextContent('边界未知')
    expect(within(drawer).getByText('hmac-sha256:abc')).toBeInTheDocument()
    expect(within(drawer).getByText(`Trace: ${'a'.repeat(32)}`)).toBeInTheDocument()
  })

  it('不可信来源只显示边界未知，不把 direct peer 补成公网客户端', async () => {
    const unknownGraph: DataFlowGraph = {
      ...BOUNDARY_GRAPH,
      nodes: [{ ...BOUNDARY_GRAPH.nodes[0], network_zone: 'UNKNOWN' }, BOUNDARY_GRAPH.nodes[1]],
      edges: [{ ...BOUNDARY_GRAPH.edges[0], source_zone: 'UNKNOWN', boundary_type: 'UNKNOWN', boundary_evidence: 'UNTRUSTED_CLIENT_SOURCE' }],
    }
    const unknownEvidence = {
      items: [{
        ...BOUNDARY_EVIDENCE.items[0],
        peer_address: '10.20.0.8',
        client_address: undefined,
        client_address_source: 'UNKNOWN' as const,
        source_zone: 'UNKNOWN' as const,
        boundary_type: 'UNKNOWN' as const,
        boundary_evidence: 'UNTRUSTED_CLIENT_SOURCE' as const,
      }],
      total: 1,
    }
    vi.stubGlobal('fetch', mockFetch(unknownGraph, unknownEvidence))
    renderPage()
    await screen.findByTestId('echart-stub')
    fireEvent.click(screen.getByRole('radio', { name: '边明细' }))
    fireEvent.click(await screen.findByRole('button', { name: '查看详情' }))
    const title = await screen.findByText('外部调用方 → profile', { selector: '.ant-drawer-title' })
    const drawer = title.closest('.data-flow-detail-drawer') as HTMLElement
    expect(drawer).not.toBeNull()
    expect(await within(drawer).findAllByText(/UNTRUSTED_CLIENT_SOURCE/)).not.toHaveLength(0)
    expect(drawer).toHaveTextContent('边界未知')
    expect(drawer).not.toHaveTextContent('公网 → 内网')
    expect(within(drawer).queryByText('client_address')).toBeNull()
    expect(within(drawer).getByText('peer_address')).toBeInTheDocument()
    expect(within(drawer).getByText('10.20.0.8')).toBeInTheDocument()
    expect(within(drawer).getByText('client_address_source')).toBeInTheDocument()
  })

  it('无证据时展示空态而非虚构节点', async () => {
    vi.stubGlobal('fetch', mockFetch({ ...GRAPH, nodes: [], edges: [], quality: { ...GRAPH.quality, observations: 0, trace_linked: 0, trace_coverage: 0, partial: false, message: '当前时间窗无观测数据' } }))
    renderPage()
    expect(await screen.findByText('当前时间窗无观测数据')).toBeInTheDocument()
    expect(screen.queryByTestId('echart-stub')).toBeNull()
  })
})
