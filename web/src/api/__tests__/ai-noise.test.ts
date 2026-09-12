import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { aiNoiseApi } from '../ai'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function envelope(data: unknown) {
  return { code: 'SUCCESS', message: 'ok', data }
}

const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>()

describe('aiNoiseApi', () => {
  beforeEach(() => {
    fetchMock.mockClear()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('listClusters：拼接筛选与分页查询参数并返回 items/total', async () => {
    const cluster = { id: 'c1', status: 'ACTIVE' }
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, envelope({ items: [cluster], page: 2, page_size: 10, total: 21 })),
    )
    const res = await aiNoiseApi.listClusters({
      page: 2,
      page_size: 10,
      source: 'WAF',
      status: 'ACTIVE',
      verdict: 'LIKELY_FALSE_POSITIVE',
    })
    expect(res.items).toHaveLength(1)
    expect(res.total).toBe(21)
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain('/api/v1/ai/noise/clusters?')
    expect(url).toContain('page=2')
    expect(url).toContain('page_size=10')
    expect(url).toContain('source=WAF')
    expect(url).toContain('status=ACTIVE')
    expect(url).toContain('verdict=LIKELY_FALSE_POSITIVE')
  })

  it('listClusters：items 为 null 时回退为空数组', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, envelope({ items: null, page: 1, page_size: 20, total: 0 })),
    )
    const res = await aiNoiseApi.listClusters({ page: 1, page_size: 20 })
    expect(res.items).toEqual([])
  })

  it('getCluster：返回簇与代表事件', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        200,
        envelope({
          cluster: { id: 'c1' },
          events: [{ event_id: 'e1', source: 'WAF', is_representative: true, created_at: '2026-07-23T00:00:00Z' }],
        }),
      ),
    )
    const res = await aiNoiseApi.getCluster('c1')
    expect(res.cluster.id).toBe('c1')
    expect(res.events).toHaveLength(1)
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/ai/noise/clusters/c1')
  })

  it('suppressCluster / resolveCluster：POST 到对应流转端点', async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(jsonResponse(200, envelope({ id: 'c1', status: 'SUPPRESSED' }))),
    )
    await aiNoiseApi.suppressCluster('c1')
    await aiNoiseApi.resolveCluster('c1')
    const [suppressCall, resolveCall] = fetchMock.mock.calls
    expect(String(suppressCall[0])).toBe('/api/v1/ai/noise/clusters/c1/suppress')
    expect(suppressCall[1]?.method).toBe('POST')
    expect(String(resolveCall[0])).toBe('/api/v1/ai/noise/clusters/c1/resolve')
    expect(resolveCall[1]?.method).toBe('POST')
  })

  it('triggerSweep：POST /ai/noise/sweeps 并返回扫描统计', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        200,
        envelope({
          started_at: '2026-07-23T00:00:00Z',
          finished_at: '2026-07-23T00:00:01Z',
          scanned_events: 100,
          new_clusters: 2,
          updated_clusters: 5,
          llm_calls: 1,
          tokens_used: 500,
          recommendations: 0,
          status: 'SUCCESS',
        }),
      ),
    )
    const res = await aiNoiseApi.triggerSweep()
    expect(res.status).toBe('SUCCESS')
    expect(res.new_clusters).toBe(2)
    const call = fetchMock.mock.calls[0]
    expect(String(call[0])).toBe('/api/v1/ai/noise/sweeps')
    expect(call[1]?.method).toBe('POST')
  })

  it('putSettings：PUT 提交设置字段', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        200,
        envelope({
          enabled: true,
          interval_seconds: 300,
          sweep_window_minutes: 60,
          min_events_threshold: 5,
          llm_verdict_enabled: false,
        }),
      ),
    )
    await aiNoiseApi.putSettings({ enabled: true, interval_seconds: 300 })
    const call = fetchMock.mock.calls[0]
    expect(String(call[0])).toBe('/api/v1/ai/noise/settings')
    expect(call[1]?.method).toBe('PUT')
    expect(JSON.parse(String(call[1]?.body))).toEqual({ enabled: true, interval_seconds: 300 })
  })

  it('错误响应：抛出带后端 message 的 ApiError', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(400, { code: 'INVALID_ARGUMENT', message: '无效的 status' }),
    )
    await expect(aiNoiseApi.listClusters({ page: 1, page_size: 20, status: 'X' })).rejects.toThrow(
      '无效的 status',
    )
  })
})
