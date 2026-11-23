import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { domainsApi, pathRoutesApi, upstreamsApi } from '../applications'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

const APP_ID = 'app-1'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function stubFetch(body: unknown, status = 200) {
  const fn = vi.fn<
    (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  >(() =>
    Promise.resolve(
      jsonResponse(status, { code: 'SUCCESS', message: 'ok', data: body }),
    ),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

describe('applications API client (M2b contracts)', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('B9-7: domainsApi.list 将后端 { items: null } 归一化为空数组', async () => {
    const fetchMock = stubFetch({ items: null })
    const res = await domainsApi.list(APP_ID)
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      `/api/v1/applications/${APP_ID}/domains`,
    )
    expect(res.items).toEqual([])
  })

  it('B9-7: upstreamsApi.list 将后端 { items: null } 归一化为空数组', async () => {
    const fetchMock = stubFetch({ items: null })
    const res = await upstreamsApi.list(APP_ID)
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      `/api/v1/applications/${APP_ID}/upstreams`,
    )
    expect(res.items).toEqual([])
  })

  it('B9-5: upstreamsApi.test POST /upstreams/test 不携带 allow_private', async () => {
    const fetchMock = stubFetch({
      dns_result: 'ok',
      resolved_addresses: ['93.184.216.34'],
      tcp_connected: true,
      tls_handshake: true,
      tls_verify_result: 'ok',
      http_status: 200,
      response_time_ms: 42,
      error_code: '',
      error_message: '',
    })
    const body = {
      scheme: 'https',
      host: 'origin.example.com',
      port: 443,
      health_check_path: '/health',
      tls_server_name: 'origin.example.com',
      tls_verify: true,
    }
    const res = await upstreamsApi.test(body)
    const call = fetchMock.mock.calls[0]
    expect(String(call[0])).toBe('/api/v1/upstreams/test')
    expect((call[1] as RequestInit).method).toBe('POST')
    const sent = JSON.parse(String((call[1] as RequestInit).body)) as Record<
      string,
      unknown
    >
    expect(sent).toEqual(body)
    expect('allow_private' in sent).toBe(false)
    expect(res.http_status).toBe(200)
  })

  it('B9-6 & B9-1: pathRoutesApi.create / update 返回 { route, message } 且 PATCH 携带 version', async () => {
    const route = {
      id: 'r1',
      application_id: APP_ID,
      path_prefix: '/api/v1',
      upstream_scheme: 'http' as const,
      upstream_host: '10.0.0.11',
      upstream_port: 8080,
      strip_prefix: true,
      priority: 50,
      status: 'ENABLED' as const,
      description: 'API',
      created_at: '2026-07-01T10:00:00Z',
      updated_at: '2026-07-01T10:00:00Z',
      version: 1,
    }
    const fetchMock = stubFetch({ route, message: '创建成功' })
    const createBody = {
      path_prefix: '/api/v1',
      upstream_scheme: 'http',
      upstream_host: '10.0.0.11',
      upstream_port: 8080,
      strip_prefix: true,
      priority: 50,
      status: 'ENABLED',
      description: 'API',
    }
    const created = await pathRoutesApi.create(APP_ID, createBody)
    expect(created).toEqual({ route, message: '创建成功' })
    expect((fetchMock.mock.calls[0][1] as RequestInit).method).toBe('POST')

    const updatedRoute = { ...route, status: 'DISABLED' as const, version: 2 }
    const updateMock = stubFetch({ route: updatedRoute, message: '更新成功' })
    const updateBody = { ...createBody, status: 'DISABLED', version: 1 }
    const updated = await pathRoutesApi.update(APP_ID, 'r1', updateBody)
    expect(updated).toEqual({ route: updatedRoute, message: '更新成功' })
    const call = updateMock.mock.calls[0]
    expect(String(call[0])).toBe(
      `/api/v1/applications/${APP_ID}/path-routes/r1`,
    )
    expect((call[1] as RequestInit).method).toBe('PATCH')
    expect(JSON.parse(String((call[1] as RequestInit).body))).toEqual(
      updateBody,
    )
  })
})
