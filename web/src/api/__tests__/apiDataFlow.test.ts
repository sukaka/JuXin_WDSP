import { afterEach, describe, expect, it, vi } from 'vitest'
import { apiDataFlowApi } from '../apiDataFlow'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

function stubFetch(body: unknown, status = 200) {
  const fn = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(() =>
    Promise.resolve(new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data: body }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

describe('apiDataFlowApi', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('graph 携带过滤条件并补空数组', async () => {
    const fetchMock = stubFetch({ quality: { observations: 0 } })
    const data = await apiDataFlowApi.graph({ start: '2026-11-04T00:00:00Z', end: '2026-11-04T01:00:00Z', method: 'POST', data_type: 'PHONE', max_edges: 20 })
    expect(data.nodes).toEqual([])
    expect(data.edges).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/api-security/data-flow/graph?')).toBe(true)
    expect(url).toContain('method=POST')
    expect(url).toContain('data_type=PHONE')
    expect(url).toContain('max_edges=20')
  })

  it('node 编码节点 ID 并补空上下游', async () => {
    const fetchMock = stubFetch({ node: { id: 'kafka/customer-events' } })
    const data = await apiDataFlowApi.node('kafka/customer-events', {})
    expect(data.dependencies).toEqual([])
    expect(data.called_by).toEqual([])
    expect(String(fetchMock.mock.calls[0][0])).toContain('/nodes/kafka%2Fcustomer-events')
  })

  it('evidence 使用查询参数传 edge_id 并补空数组', async () => {
    const fetchMock = stubFetch({ total: 0 })
    const data = await apiDataFlowApi.evidence('service:a->service:b|HTTP', { limit: 10 })
    expect(data.items).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain('/evidence?')
    expect(url).toContain('edge_id=service%3Aa-%3Eservice%3Ab%7CHTTP')
    expect(url).toContain('limit=10')
  })

  it('graph 查询内外网边界并保留区域与边界证据字段', async () => {
    const fetchMock = stubFetch({
      nodes: [{ id: 'client:198.51.100.10', network_zone: 'PUBLIC' }],
      edges: [{ id: 'boundary-edge', source_zone: 'PUBLIC', target_zone: 'INTERNAL', boundary_type: 'PUBLIC_TO_INTERNAL', boundary_evidence: 'DIRECT_PEER' }],
      quality: { observations: 1 },
    })
    const data = await apiDataFlowApi.graph({ view: 'boundary' })
    expect(String(fetchMock.mock.calls[0][0])).toContain('view=boundary')
    expect(data.nodes[0].network_zone).toBe('PUBLIC')
    expect(data.edges[0]).toMatchObject({ source_zone: 'PUBLIC', target_zone: 'INTERNAL', boundary_type: 'PUBLIC_TO_INTERNAL', boundary_evidence: 'DIRECT_PEER' })
  })

  it('旧证据仅含 peer_address 时按直连兼容，代理地址不会覆盖真实客户端', async () => {
    stubFetch({
      items: [
        { event_id: 'legacy', peer_address: '198.51.100.10', fields: [] },
        { event_id: 'proxy', peer_address: '10.20.0.8', client_address: '203.0.113.20', client_address_source: 'TRUSTED_PROXY', fields: [] },
      ],
      total: 2,
    })
    const data = await apiDataFlowApi.evidence('boundary-edge', {})
    expect(data.items[0]).toMatchObject({ peer_address: '198.51.100.10', client_address: '198.51.100.10', client_address_source: 'DIRECT_PEER' })
    expect(data.items[1]).toMatchObject({ peer_address: '10.20.0.8', client_address: '203.0.113.20', client_address_source: 'TRUSTED_PROXY' })
  })
})
