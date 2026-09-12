import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { securityIdentitiesApi } from '../securityIdentities'
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

describe('securityIdentitiesApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('list：筛选与分页参数拼接到查询串，items 为 null 时归一化为空数组', async () => {
    const fetchMock = stubFetch({ items: null, page: 2, page_size: 10, total: 0 })
    const data = await securityIdentitiesApi.list({
      risk_level: 'HIGH',
      identity_type: 'BOT',
      keyword: 'scanner',
      ip: '1.2.3.4',
      from: '2026-08-01',
      to: '2026-08-31',
      page: 2,
      page_size: 10,
    })
    expect(data.items).toEqual([])
    expect(data.total).toBe(0)
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain('/api/v1/security/identities?')
    expect(url).toContain('risk_level=HIGH')
    expect(url).toContain('identity_type=BOT')
    expect(url).toContain('keyword=scanner')
    expect(url).toContain('ip=1.2.3.4')
    expect(url).toContain('from=2026-08-01')
    expect(url).toContain('to=2026-08-31')
    expect(url).toContain('page=2')
    expect(url).toContain('page_size=10')
  })

  it('get：详情内嵌数组为 null 时归一化为空数组', async () => {
    // 后端响应为 { identity, ip_history, credentials, recent_events } 包裹结构
    stubFetch({
      identity: {
        id: 'idn-1',
        identity_key: 'ip:1.2.3.4',
        identity_type: 'BOT',
        risk_score: 86,
        risk_level: 'HIGH',
      },
      ip_history: null,
      credentials: null,
      recent_events: null,
    })
    const data = await securityIdentitiesApi.get('idn-1')
    expect(data.ip_history).toEqual([])
    expect(data.credentials).toEqual([])
    expect(data.recent_events).toEqual([])
    expect(data.risk_score).toBe(86)
  })

  it('behavior：window/from/to 作为查询参数传递，items 归一化', async () => {
    const fetchMock = stubFetch({ items: null, page: 1, page_size: 500, total: 0 })
    const data = await securityIdentitiesApi.behavior('idn-1', {
      window: '5m',
      from: '2026-08-30',
      to: '2026-08-31',
      page: 1,
      page_size: 500,
    })
    expect(data.items).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain('/api/v1/security/identities/idn-1/behavior?')
    expect(url).toContain('window=5m')
    expect(url).toContain('from=2026-08-30')
    expect(url).toContain('to=2026-08-31')
  })

  it('events：signal 与分页参数拼接，空参不传', async () => {
    const fetchMock = stubFetch({ items: null, page: 1, page_size: 20, total: 0 })
    await securityIdentitiesApi.events('idn-1', {
      signal: 'URI_ENUMERATION',
      page: 1,
      page_size: 20,
    })
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain('/api/v1/security/identities/idn-1/events?')
    expect(url).toContain('signal=URI_ENUMERATION')
    expect(url).toContain('page=1')
    expect(url).not.toContain('from=')
    expect(url).not.toContain('to=')
  })
})
