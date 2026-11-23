import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { upgradesApi } from '../upgrades'
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

describe('upgradesApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('list：GET /api/v1/upgrades 返回 UpgradeJobItem（requested_at/package_id），items 为 null 时归一为空数组', async () => {
    const fetchMock = stubFetch({ items: null, total: 0, page: 1, page_size: 20 })
    const data = await upgradesApi.list({ status: 'SUCCESS', page: 1, page_size: 20 })
    expect(data.items).toEqual([])
    const url = String(fetchMock.mock.calls[0][0])
    expect(url.startsWith('/api/v1/upgrades?')).toBe(true)
    expect(url).toContain('status=SUCCESS')
    expect(url).toContain('page=1')
    expect(url).toContain('page_size=20')
  })

  it('listPackages：GET /api/v1/upgrade-packages items 为 null 时归一为空数组', async () => {
    const fetchMock = stubFetch({ items: null, total: 0, page: 1, page_size: 50 })
    const data = await upgradesApi.listPackages({ page: 1, page_size: 50 })
    expect(data.items).toEqual([])
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/upgrade-packages?page=1&page_size=50')
  })

  it('execute / get / rollback / cancelUpgrade：解包 data.job 并保留 requested_at 与 package_id', async () => {
    const job = {
      id: 'job-1',
      package_id: 'pkg-1',
      status: 'PENDING',
      requested_at: '2026-09-14T00:00:00Z',
      scheduled_at: null,
      started_at: null,
      finished_at: null,
    }
    const fetchMock = stubFetch({ job })
    const executed = await upgradesApi.execute('pkg-1')
    expect(executed.requested_at).toBe('2026-09-14T00:00:00Z')
    expect(executed.package_id).toBe('pkg-1')
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/upgrades')

    const got = await upgradesApi.get('job-1')
    expect(got.id).toBe('job-1')
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/upgrades/job-1')

    const rolled = await upgradesApi.rollback('job-1')
    expect(rolled.id).toBe('job-1')
    expect(String(fetchMock.mock.calls[2][0])).toBe('/api/v1/upgrades/job-1/rollback')

    const cancelled = await upgradesApi.cancelUpgrade('job-1')
    expect(cancelled.id).toBe('job-1')
    expect(String(fetchMock.mock.calls[3][0])).toBe('/api/v1/upgrades/job-1/cancel')
  })

  it('precheck：POST /api/v1/upgrades/precheck 将 precheck null 安全归一为 PASS 且 items=[]', async () => {
    stubFetch({ precheck: null, passed: true })
    const res = await upgradesApi.precheck('pkg-1')
    expect(res).toEqual({ package_id: 'pkg-1', overall_result: 'PASS', items: [] })
  })
})
