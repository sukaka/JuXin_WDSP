import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apmApi } from '../apm'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function stubFetch(body: unknown, status = 200) {
  const fn = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(() =>
    Promise.resolve(jsonResponse(status, { code: 'SUCCESS', message: 'ok', data: body })),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

const TIME = {
  start_time: '2026-08-30T00:00:00.000Z',
  end_time: '2026-08-30T01:00:00.000Z',
}

describe('apmApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('overview：GET /api/v1/apm/overview 携带时间窗并解包 data', async () => {
    const fetchMock = stubFetch({ data_source: 'agentless', requests_total: 42 })
    const data = await apmApi.overview(TIME)
    expect(data.requests_total).toBe(42)
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/overview?')).toBe(true)
    expect(url).toContain(`start_time=${encodeURIComponent(TIME.start_time)}`)
    expect(url).toContain(`end_time=${encodeURIComponent(TIME.end_time)}`)
    expect((fetchMock.mock.calls[0][1] as RequestInit | undefined)?.method ?? 'GET').toBe('GET')
  })

  it('services：keyword/page/page_size 作为查询参数；items 缺省补空数组', async () => {
    const fetchMock = stubFetch({ page: 2, page_size: 50, total: 0 })
    const data = await apmApi.services({ ...TIME, keyword: '商城', page: 2, page_size: 50 })
    expect(data.items).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/services?')).toBe(true)
    expect(url).toContain(`keyword=${encodeURIComponent('商城')}`)
    expect(url).toContain('page=2')
    expect(url).toContain('page_size=50')
  })

  it('service：路径拼接服务 ID 并携带时间窗', async () => {
    const fetchMock = stubFetch({ application_id: 'svc-1' })
    const data = await apmApi.service('svc-1', TIME)
    expect(data.application_id).toBe('svc-1')
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/services/svc-1?')).toBe(true)
    expect(url).toContain('start_time=')
  })

  it('endpoints：application_id/sort/分页参数拼接；list 缺省补空数组且透传 access_log_enabled', async () => {
    const fetchMock = stubFetch({ total: 3, page: 1, page_size: 20, access_log_enabled: false })
    const data = await apmApi.endpoints({
      ...TIME,
      application_id: 'svc-1',
      sort: 'error_rate',
      page: 1,
      page_size: 20,
    })
    expect(data.list).toEqual([])
    expect(data.access_log_enabled).toBe(false)
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/endpoints?')).toBe(true)
    expect(url).toContain('application_id=svc-1')
    expect(url).toContain('sort=error_rate')
    expect(url).toContain('page=1')
    expect(url).toContain('page_size=20')
  })

  it('endpoints：可选参数缺省不出现在查询串', async () => {
    const fetchMock = stubFetch({ list: [], total: 0, page: 1, page_size: 20, access_log_enabled: true })
    await apmApi.endpoints({ ...TIME, page: 1, page_size: 20 })
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).not.toContain('application_id')
    expect(url).not.toContain('sort=')
  })

  it('trace：GET /api/v1/apm/traces/{trace_id} 无查询参数', async () => {
    const traceId = 'a'.repeat(32)
    const fetchMock = stubFetch({ trace_id: traceId, access_logs: [], security_events: [] })
    const data = await apmApi.trace(traceId)
    expect(data.trace_id).toBe(traceId)
    expect(String(fetchMock.mock.calls[0][0])).toBe(`/api/v1/apm/traces/${traceId}`)
  })

  it('trace：携带可选时间窗上下文（P1-01 A3，start_time/end_time 同时提供）', async () => {
    const traceId = 'b'.repeat(32)
    const fetchMock = stubFetch({ trace_id: traceId, access_logs: [], security_events: [] })
    await apmApi.trace(traceId, {
      start_time: '2026-08-30T00:25:00.000Z',
      end_time: '2026-08-30T00:35:00.000Z',
    })
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith(`/api/v1/apm/traces/${traceId}?`)).toBe(true)
    expect(url).toContain('start_time=2026-08-30T00%3A25%3A00.000Z')
    expect(url).toContain('end_time=2026-08-30T00%3A35%3A00.000Z')
  })

  it('traceSearch：GET /api/v1/apm/trace-search 携带全部筛选参数；list 缺省补空数组', async () => {
    const fetchMock = stubFetch({ total: 0, page: 1, page_size: 20, data_source: 'agentless' })
    const data = await apmApi.traceSearch({
      ...TIME,
      service: 'shop',
      trace_id: 'a'.repeat(32),
      request_id: 'req-1',
      min_duration_ms: 500,
      error: true,
      page: 1,
      page_size: 20,
    })
    expect(data.list).toEqual([])
    expect(data.data_source).toBe('agentless')
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/trace-search?')).toBe(true)
    expect(url).toContain('service=shop')
    expect(url).toContain(`trace_id=${'a'.repeat(32)}`)
    expect(url).toContain('request_id=req-1')
    expect(url).toContain('min_duration_ms=500')
    expect(url).toContain('error=true')
    expect(url).toContain('page=1')
  })

  it('traceSearch：可选参数缺省不出现在查询串（error=false 等价于不传）', async () => {
    const fetchMock = stubFetch({ list: [], total: 0, page: 1, page_size: 20, data_source: 'otel' })
    await apmApi.traceSearch({ ...TIME, page: 1, page_size: 20 })
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).not.toContain('service=')
    expect(url).not.toContain('trace_id=')
    expect(url).not.toContain('request_id=')
    expect(url).not.toContain('min_duration_ms')
    expect(url).not.toContain('error=')
  })

  it('createEnrollmentToken：POST /api/v1/apm/agents/enrollment-tokens 携带入参', async () => {
    const fetchMock = stubFetch({ id: 'tok-1', token: 'secret-token', expires_at: '2026-08-30T02:00:00Z' })
    const body = {
      application_id: 'app-1',
      environment: 'prod',
      languages: ['Java', 'Go'],
      ttl_minutes: 60,
    }
    const data = await apmApi.createEnrollmentToken(body)
    expect(data.token).toBe('secret-token')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/agents/enrollment-tokens')
    expect((init as RequestInit).method).toBe('POST')
    expect(JSON.parse(String((init as RequestInit).body))).toEqual(body)
  })

  it('agents：GET /api/v1/apm/agents 携带 status/keyword/分页；items 缺省补空数组', async () => {
    const fetchMock = stubFetch({ page: 1, page_size: 20, total: 0 })
    const data = await apmApi.agents({ status: 'OFFLINE', keyword: 'shop', page: 1, page_size: 20 })
    expect(data.items).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/agents?')).toBe(true)
    expect(url).toContain('status=OFFLINE')
    expect(url).toContain(`keyword=${encodeURIComponent('shop')}`)
  })

  it('revokeAgent：POST /api/v1/apm/agents/{id}/revoke 无请求体', async () => {
    const fetchMock = stubFetch({ message: '已撤销' })
    await apmApi.revokeAgent('agent-1')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/agents/agent-1/revoke')
    expect((init as RequestInit).method).toBe('POST')
    expect((init as RequestInit).body).toBeUndefined()
  })

  it('getPolicy：GET /api/v1/apm/policies/{scope}（scope 做 URL 编码）', async () => {
    const fetchMock = stubFetch({ scope: 'order svc', version: 3, policy: {} })
    const data = await apmApi.getPolicy('order svc')
    expect(data.version).toBe(3)
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/apm/policies/order%20svc')
  })

  it('putPolicy：PUT /api/v1/apm/policies/{scope} 携带 policy 与 expected_version', async () => {
    const fetchMock = stubFetch({ scope: 'shop', version: 4, policy: { sampling: 10 } })
    await apmApi.putPolicy('shop', { policy: { sampling: 10 }, expected_version: 3 })
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/policies/shop')
    expect((init as RequestInit).method).toBe('PUT')
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({
      policy: { sampling: 10 },
      expected_version: 3,
    })
  })

  it('sql：GET /api/v1/apm/sql 携带 service/db_system/sort/分页；list 缺省补空数组', async () => {
    const fetchMock = stubFetch({ total: 0, page: 1, page_size: 20, data_source: 'otel', message: '' })
    const data = await apmApi.sql({
      ...TIME,
      service: 'shop',
      db_system: 'mysql',
      sort: 'p95_ms',
      page: 1,
      page_size: 20,
    })
    expect(data.list).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/sql?')).toBe(true)
    expect(url).toContain(`start_time=${encodeURIComponent(TIME.start_time)}`)
    expect(url).toContain('service=shop')
    expect(url).toContain('db_system=mysql')
    expect(url).toContain('sort=p95_ms')
    expect(url).toContain('page=1')
    expect(url).toContain('page_size=20')
  })

  it('sql：可选参数缺省不出现在查询串', async () => {
    const fetchMock = stubFetch({ list: [], total: 0, page: 1, page_size: 20, data_source: 'agentless' })
    await apmApi.sql({ ...TIME, page: 1, page_size: 20 })
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).not.toContain('service=')
    expect(url).not.toContain('db_system=')
    expect(url).not.toContain('sort=')
  })

  it('exceptions：GET /api/v1/apm/exceptions 携带 service/分页；list 缺省补空数组', async () => {
    const fetchMock = stubFetch({ total: 1, page: 2, page_size: 50, data_source: 'otel' })
    const data = await apmApi.exceptions({ ...TIME, service: 'shop', page: 2, page_size: 50 })
    expect(data.list).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/exceptions?')).toBe(true)
    expect(url).toContain('service=shop')
    expect(url).toContain('page=2')
    expect(url).toContain('page_size=50')
  })

  it('dependencies：GET /api/v1/apm/dependencies 携带时间窗与 service；edges 缺省补空数组且透传 note', async () => {
    const fetchMock = stubFetch({
      data_source: 'otel',
      note: '基于客户端 span 单视角派生',
    })
    const data = await apmApi.dependencies({ ...TIME, service: 'shop' })
    expect(data.edges).toEqual([])
    expect(data.note).toBe('基于客户端 span 单视角派生')
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/dependencies?')).toBe(true)
    expect(url).toContain('service=shop')
    expect(url).toContain('start_time=')
  })

  it('runtime：GET /api/v1/apm/runtime 携带 service/instance_id/时间窗；instances 缺省补空数组', async () => {
    const fetchMock = stubFetch({ data_source: 'otel', note: '' })
    const data = await apmApi.runtime({ ...TIME, service: 'shop', instance_id: 'inst-1' })
    expect(data.instances).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/runtime?')).toBe(true)
    expect(url).toContain('service=shop')
    expect(url).toContain('instance_id=inst-1')
    expect(url).toContain('end_time=')
  })

  it('slos：GET /api/v1/apm/slos 无查询参数；list 缺省补空数组', async () => {
    const fetchMock = stubFetch({ total: 0 })
    const data = await apmApi.slos()
    expect(data.list).toEqual([])
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/apm/slos')
  })

  it('slo：GET /api/v1/apm/slos/{id}（id 做 URL 编码）', async () => {
    const fetchMock = stubFetch({ id: 'slo 1', trend: [] })
    const data = await apmApi.slo('slo 1')
    expect(data.id).toBe('slo 1')
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/apm/slos/slo%201')
  })

  it('createSlo：POST /api/v1/apm/slos 携带入参', async () => {
    const fetchMock = stubFetch({ id: 'slo-1' })
    const body = { name: '商城可用性', service: 'shop', metric_type: 'availability' as const, target: 0.999, window: '30d' }
    await apmApi.createSlo(body)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/slos')
    expect((init as RequestInit).method).toBe('POST')
    expect(JSON.parse(String((init as RequestInit).body))).toEqual(body)
  })

  it('updateSlo：PUT /api/v1/apm/slos/{id} 携带入参', async () => {
    const fetchMock = stubFetch({ id: 'slo-1' })
    const body = { name: '商城 P95', service: 'shop', metric_type: 'latency_p95' as const, target: 500, window: '7d' }
    await apmApi.updateSlo('slo-1', body)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/slos/slo-1')
    expect((init as RequestInit).method).toBe('PUT')
    expect(JSON.parse(String((init as RequestInit).body))).toEqual(body)
  })

  it('deleteSlo：DELETE /api/v1/apm/slos/{id} 无请求体', async () => {
    const fetchMock = stubFetch({ message: '已删除' })
    await apmApi.deleteSlo('slo-1')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/slos/slo-1')
    expect((init as RequestInit).method).toBe('DELETE')
    expect((init as RequestInit).body).toBeUndefined()
  })

  it('diagnosticSessions：GET /api/v1/apm/diagnostic-sessions 携带 status/分页；list 缺省补空数组并透传 kill_switch_enabled', async () => {
    const fetchMock = stubFetch({ total: 0, page: 1, page_size: 20, kill_switch_enabled: true })
    const data = await apmApi.diagnosticSessions({ status: 'ACTIVE', page: 1, page_size: 20 })
    expect(data.list).toEqual([])
    expect(data.kill_switch_enabled).toBe(true)
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/apm/diagnostic-sessions?')).toBe(true)
    expect(url).toContain('status=ACTIVE')
    expect(url).toContain('page=1')
    expect(url).toContain('page_size=20')
  })

  it('diagnosticSession：GET /api/v1/apm/diagnostic-sessions/{id}（id 做 URL 编码）；audits 缺省补空数组', async () => {
    const fetchMock = stubFetch({ id: 'diag 1', status: 'ACTIVE' })
    const data = await apmApi.diagnosticSession('diag 1')
    expect(data.id).toBe('diag 1')
    expect(data.audits).toEqual([])
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/apm/diagnostic-sessions/diag%201')
  })

  it('dryRunDiagnosticSession：POST /api/v1/apm/diagnostic-sessions 强制 dry_run=true', async () => {
    const fetchMock = stubFetch({
      estimated_overhead: {
        cpu_hint: '约 +8% CPU',
        spans_per_s_hint: '约 1200 spans/s',
        data_volume_hint: '约 300 MB/小时',
        risk_notes: ['SQL 明细可能包含敏感数据'],
      },
    })
    const body = {
      scope: {
        application_id: 'app-1',
        service: 'shop',
        environment: 'production',
        instance_ids: ['inst-001'],
      },
      capabilities: ['sql_detail' as const],
      sampling_rate: 0.5,
      duration_minutes: 15,
    }
    const data = await apmApi.dryRunDiagnosticSession(body)
    expect(data.estimated_overhead.cpu_hint).toContain('CPU')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/diagnostic-sessions')
    expect((init as RequestInit).method).toBe('POST')
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ ...body, dry_run: true })
  })

  it('createDiagnosticSession：POST /api/v1/apm/diagnostic-sessions 强制 confirm=true', async () => {
    const fetchMock = stubFetch({ id: 'diag-1', status: 'ACTIVE' })
    const body = {
      scope: {
        application_id: 'app-1',
        service: 'shop',
        environment: 'production',
        instance_ids: ['inst-001'],
      },
      capabilities: ['sql_detail' as const, 'function_probe' as const],
      sampling_rate: 1,
      duration_minutes: 30,
    }
    const data = await apmApi.createDiagnosticSession(body)
    expect(data.id).toBe('diag-1')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/diagnostic-sessions')
    expect((init as RequestInit).method).toBe('POST')
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ ...body, confirm: true })
  })

  it('stopDiagnosticSession：POST /api/v1/apm/diagnostic-sessions/{id}/stop 无请求体', async () => {
    const fetchMock = stubFetch({ id: 'diag-1', status: 'STOPPED' })
    const data = await apmApi.stopDiagnosticSession('diag-1')
    expect(data.status).toBe('STOPPED')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/diagnostic-sessions/diag-1/stop')
    expect((init as RequestInit).method).toBe('POST')
    expect((init as RequestInit).body).toBeUndefined()
  })

  it('setDiagnosticKillSwitch：POST /api/v1/apm/diagnostics/kill-switch 携带 enable', async () => {
    const fetchMock = stubFetch({ kill_switch_enabled: true })
    const data = await apmApi.setDiagnosticKillSwitch(true)
    expect(data.kill_switch_enabled).toBe(true)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/apm/diagnostics/kill-switch')
    expect((init as RequestInit).method).toBe('POST')
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ enable: true })
  })
})
