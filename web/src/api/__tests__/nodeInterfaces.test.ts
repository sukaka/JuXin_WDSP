import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nodeInterfacesApi } from '../nodeInterfaces'
import { setCsrfToken, setSessionExpiredHandler } from '../client'
import type { NodeInterfaceOrderPayload, NodeInterfacesData } from '../../types'

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

const SAMPLE_NODES: NodeInterfacesData = {
  nodes: [
    {
      node_name: 'node-1',
      interfaces: [
        {
          ifname: 'eth0',
          mac: '00:11:22:33:44:01',
          media_type: 'TP',
          operstate: 'up',
          sort_order: 1,
          role: 'MANAGEMENT',
          present: true,
        },
      ],
    },
  ],
}

describe('nodeInterfacesApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('list 支持可选 node_name 查询参数并返回 NodeInterfacesData', async () => {
    const fetchMock = stubFetch(SAMPLE_NODES)
    const res1 = await nodeInterfacesApi.list()
    expect(res1).toEqual(SAMPLE_NODES)
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/gateway/interfaces')

    await nodeInterfacesApi.list('node-1')
    expect(String(fetchMock.mock.calls[1][0])).toBe(
      '/api/v1/gateway/interfaces?node_name=node-1',
    )
  })

  it('saveOrder 提交排序请求体并返回更新后的 NodeInterfacesData', async () => {
    const fetchMock = stubFetch(SAMPLE_NODES)
    const payload: NodeInterfaceOrderPayload = {
      node_name: 'node-1',
      items: [{ ifname: 'eth0', sort_order: 1, role: 'MANAGEMENT' }],
    }

    const res = await nodeInterfacesApi.saveOrder(payload)
    expect(res).toEqual(SAMPLE_NODES)

    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/gateway/interfaces/order')
    expect(init?.method).toBe('PUT')
    expect(JSON.parse(String(init?.body))).toEqual(payload)
  })
})
