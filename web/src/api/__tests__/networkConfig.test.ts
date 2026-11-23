import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { networkConfigApi } from '../networkConfig'
import { setCsrfToken, setSessionExpiredHandler } from '../client'
import type { NetworkConfigData, NetworkDesiredConfig } from '../../types'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function stubFetch(data: unknown) {
  const fn = vi.fn<
    (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  >(() =>
    Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data })),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

const SAMPLE_DESIRED: NetworkDesiredConfig = {
  bridges: [{ name: 'br0', ports: ['eth1', 'eth2'] }],
  ip_forward: true,
  routes: [{ dst: '10.10.0.0/16', via: '172.30.10.2' }],
}

const SAMPLE_DATA: NetworkConfigData = {
  desired: SAMPLE_DESIRED,
  status: null,
}

describe('networkConfigApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('get 携带可选 node_name 查询参数并返回 NetworkConfigData', async () => {
    const fetchMock = stubFetch(SAMPLE_DATA)
    const res1 = await networkConfigApi.get('node-1')
    expect(res1).toEqual(SAMPLE_DATA)
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/gateway/network-config?node_name=node-1',
    )

    await networkConfigApi.get()
    expect(String(fetchMock.mock.calls[1][0])).toBe(
      '/api/v1/gateway/network-config',
    )
  })

  it('save(body, nodeName) 通过 JSON 请求体发送 node_name 且不拼接查询参数，返回 NetworkConfigData', async () => {
    const fetchMock = stubFetch(SAMPLE_DATA)
    const result = await networkConfigApi.save(SAMPLE_DESIRED, ' node-2 ')

    expect(result).toEqual(SAMPLE_DATA)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/gateway/network-config')
    expect(String(url)).not.toContain('node_name=')
    expect(init?.method).toBe('PUT')
    expect(JSON.parse(String(init?.body))).toEqual({
      ...SAMPLE_DESIRED,
      node_name: 'node-2',
    })
  })

  it.each([undefined, '', '   '])(
    'save 当 nodeName=%j 为空或仅空白时省略 body.node_name 且不带查询参数',
    async (nodeName) => {
      const fetchMock = stubFetch(SAMPLE_DATA)
      await networkConfigApi.save(SAMPLE_DESIRED, nodeName)

      const [url, init] = fetchMock.mock.calls[0]
      expect(String(url)).toBe('/api/v1/gateway/network-config')
      expect(init?.method).toBe('PUT')
      const parsed = JSON.parse(String(init?.body)) as Record<string, unknown>
      expect(parsed).toEqual(SAMPLE_DESIRED)
      expect('node_name' in parsed).toBe(false)
    },
  )
})
