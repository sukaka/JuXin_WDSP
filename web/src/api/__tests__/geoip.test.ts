import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { geoipApi } from '../geoip'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('geoipApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('lookup 发送 GET /geoip/lookup?ip=... 并正确编码参数', async () => {
    const fetchMock = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >(() =>
      Promise.resolve(
        jsonResponse({
          code: 'SUCCESS',
          message: 'ok',
          data: {
            geo: {
              ip: '202.96.128.86',
              scope: 'PUBLIC',
              country_code: 'CN',
              country: '中国',
              province: '广东',
              city: '广州',
              isp: '中国电信',
              label: '中国 广东 广州 中国电信',
              source: 'ip2region',
            },
            geo_enabled: true,
            sources: ['ip2region'],
          },
        }),
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    const res = await geoipApi.lookup('202.96.128.86')
    expect(res.geo.ip).toBe('202.96.128.86')
    expect(res.geo.source).toBe('ip2region')
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/geoip/lookup?ip=202.96.128.86',
    )
  })

  it('lookupBatch 空或仅空白数组时直接返回空结果而不调用 fetch', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    const res = await geoipApi.lookupBatch(['', '   '])
    expect(res).toEqual({ items: {}, geo_enabled: true, sources: [] })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('lookupBatch 发送单次序列化 JSON 对象 { ips }（禁止双重 JSON.stringify）', async () => {
    const fetchMock = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >(() =>
      Promise.resolve(
        jsonResponse({
          code: 'SUCCESS',
          message: 'ok',
          data: {
            items: {
              '8.8.8.8': {
                ip: '8.8.8.8',
                scope: 'PUBLIC',
                country_code: 'US',
                country: '美国',
                label: '美国',
                source: 'mmdb',
              },
            },
            geo_enabled: true,
            sources: ['ip2region', 'mmdb'],
          },
        }),
      ),
    )
    vi.stubGlobal('fetch', fetchMock)

    const res = await geoipApi.lookupBatch([' 8.8.8.8 ', '8.8.8.8', '', '1.1.1.1'])
    expect(res.items['8.8.8.8'].country).toBe('美国')
    expect(fetchMock).toHaveBeenCalledTimes(1)

    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/geoip/lookup')
    expect(init?.method).toBe('POST')
    expect(typeof init?.body).toBe('string')
    const parsed: unknown = JSON.parse(String(init?.body))
    expect(typeof parsed).toBe('object')
    expect(parsed).toEqual({ ips: ['8.8.8.8', '1.1.1.1'] })
  })

  it('lookupBatch 超过 200 个 IP 时按 200 分片并发送合法 JSON 对象请求体', async () => {
    const ips = Array.from({ length: 205 }, (_, i) => `198.51.100.${i + 1}`)
    const fetchMock = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >((_input, init) => {
      const parsed = JSON.parse(String(init?.body)) as { ips: string[] }
      const items = Object.fromEntries(
        parsed.ips.map((ip) => [
          ip,
          { ip, scope: 'PUBLIC', label: `geo-${ip}`, source: 'ip2region' },
        ]),
      )
      return Promise.resolve(
        jsonResponse({
          code: 'SUCCESS',
          message: 'ok',
          data: { items, geo_enabled: true, sources: ['ip2region'] },
        }),
      )
    })
    vi.stubGlobal('fetch', fetchMock)

    const res = await geoipApi.lookupBatch(ips)
    expect(fetchMock).toHaveBeenCalledTimes(2)

    const body1: unknown = JSON.parse(String(fetchMock.mock.calls[0][1]?.body))
    const body2: unknown = JSON.parse(String(fetchMock.mock.calls[1][1]?.body))
    expect(typeof body1).toBe('object')
    expect(typeof body2).toBe('object')
    expect((body1 as { ips: string[] }).ips).toHaveLength(200)
    expect((body2 as { ips: string[] }).ips).toHaveLength(5)
    expect(Object.keys(res.items)).toHaveLength(205)
    expect(res.geo_enabled).toBe(true)
    expect(res.sources).toEqual(['ip2region'])
  })
})
