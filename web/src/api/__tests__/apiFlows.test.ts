import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFlowBaselinesApi, toUpsertInput, type ApiFlowBaseline } from '../apiFlows'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function stubFetch(body: unknown, status = 200) {
  const fn = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(() =>
    Promise.resolve(
      jsonResponse(status, { code: 'SUCCESS', message: 'ok', data: body }),
    ),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

const FLOW: ApiFlowBaseline = {
  id: 'f-1',
  flow_id: 'order-checkout',
  name: '下单结账',
  description: '',
  enabled: true,
  version: 3,
  steps: [
    {
      id: 's-1',
      step_id: 'create-order',
      endpoint_id: 'e-1',
      endpoint_key: 'POST /api/orders',
      sequence: 1,
      predecessors: [],
      terminal: false,
      state_from: '',
      state_to: 'CREATED',
      max_per_window: 0,
      rate_window_seconds: 0,
      cancels_flow: false,
    },
    {
      id: 's-2',
      step_id: 'pay-order',
      endpoint_id: 'e-2',
      endpoint_key: 'POST /api/orders/{id}/pay',
      sequence: 2,
      predecessors: ['create-order'],
      terminal: true,
      state_from: 'CREATED',
      state_to: 'PAID',
      max_per_window: 5,
      rate_window_seconds: 120,
      cancels_flow: true,
    },
  ],
  created_by: 'admin',
  created_at: '2026-09-10T00:00:00Z',
  updated_at: '2026-09-10T01:00:00Z',
}

describe('apiFlowBaselinesApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('list：GET /api-security/flow-baselines 携带 enabled 过滤，items 为空时归一化为空数组', async () => {
    const fetchMock = stubFetch({ items: null, total: 0 })
    const data = await apiFlowBaselinesApi.list({ enabled: true })
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/api-security/flow-baselines?enabled=true',
    )
    expect(data).toEqual({ items: [], total: 0 })
  })

  it('list：不带过滤时不拼 enabled 参数', async () => {
    const fetchMock = stubFetch({ items: [], total: 0 })
    await apiFlowBaselinesApi.list()
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/api-security/flow-baselines')
  })

  it('create：POST 携带整体载荷（不含 expected_version）', async () => {
    const fetchMock = stubFetch(FLOW, 201)
    const input = toUpsertInput(FLOW)
    await apiFlowBaselinesApi.create(input)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/api-security/flow-baselines')
    expect(init?.method).toBe('POST')
    const body = JSON.parse(String(init?.body))
    expect(body.flow_id).toBe('order-checkout')
    expect(body.steps).toHaveLength(2)
    expect(body.steps[0]).not.toHaveProperty('id')
    expect(body.steps[0]).not.toHaveProperty('endpoint_key')
    expect(body).not.toHaveProperty('expected_version')
    // 零值字段省略不发送（0/false 语义 = 不判定），非零字段随载荷提交
    expect(body.steps[0]).not.toHaveProperty('max_per_window')
    expect(body.steps[0]).not.toHaveProperty('rate_window_seconds')
    expect(body.steps[0]).not.toHaveProperty('cancels_flow')
    expect(body.steps[1].max_per_window).toBe(5)
    expect(body.steps[1].rate_window_seconds).toBe(120)
    expect(body.steps[1].cancels_flow).toBe(true)
  })

  it('update：PUT 携带 expected_version 乐观锁', async () => {
    const fetchMock = stubFetch(FLOW)
    await apiFlowBaselinesApi.update('f-1', toUpsertInput(FLOW), 3)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/api-security/flow-baselines/f-1')
    expect(init?.method).toBe('PUT')
    expect(JSON.parse(String(init?.body)).expected_version).toBe(3)
  })

  it('remove：DELETE /api-security/flow-baselines/{id}', async () => {
    const fetchMock = stubFetch({ status: 'deleted' })
    const r = await apiFlowBaselinesApi.remove('f-1')
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/api-security/flow-baselines/f-1')
    expect(fetchMock.mock.calls[0][1]?.method).toBe('DELETE')
    expect(r.status).toBe('deleted')
  })

  it('toUpsertInput：剥离仅出参字段（id/endpoint_key），保留乐观锁外全部字段', () => {
    const input = toUpsertInput(FLOW)
    expect(input.enabled).toBe(true)
    expect(input.steps[1]).toEqual({
      step_id: 'pay-order',
      endpoint_id: 'e-2',
      sequence: 2,
      predecessors: ['create-order'],
      terminal: true,
      state_from: 'CREATED',
      state_to: 'PAID',
      max_per_window: 5,
      rate_window_seconds: 120,
      cancels_flow: true,
    })
  })

  it('toUpsertInput：max_per_window/rate_window_seconds 为 0、cancels_flow 为 false 时省略不发送', () => {
    const input = toUpsertInput(FLOW)
    expect(input.steps[0]).toEqual({
      step_id: 'create-order',
      endpoint_id: 'e-1',
      sequence: 1,
      predecessors: [],
      terminal: false,
      state_from: '',
      state_to: 'CREATED',
    })
  })
})
