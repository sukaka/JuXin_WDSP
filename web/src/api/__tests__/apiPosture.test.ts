import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiPostureOverviewApi } from '../apiPosture'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

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

describe('apiPostureOverviewApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('overview：GET /api/v1/api-security/posture/overview 并解包 data', async () => {
    const fetchMock = stubFetch({ traffic_24h: 5, protected_24h: 3 })
    const data = await apiPostureOverviewApi.overview()
    expect(data.traffic_24h).toBe(5)
    expect(data.protected_24h).toBe(3)
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toBe('/api/v1/api-security/posture/overview')
    expect(
      (fetchMock.mock.calls[0][1] as RequestInit | undefined)?.method ?? 'GET',
    ).toBe('GET')
  })

  it('trends：days 作为查询参数传递', async () => {
    const fetchMock = stubFetch({ days: 14, points: [] })
    const data = await apiPostureOverviewApi.trends(14)
    expect(data.days).toBe(14)
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toBe('/api/v1/api-security/posture/trends?days=14')
  })
})
