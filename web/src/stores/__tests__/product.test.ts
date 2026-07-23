import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useProductStore } from '../product'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('product store', () => {
  beforeEach(() => {
    useProductStore.setState({
      edition: 'waf',
      apiDynamicProtection: false,
      initialized: false,
    })
    vi.unstubAllGlobals()
  })

  it('WDSP 且能力开启时暴露接口防护', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { edition: 'wdsp', api_dynamic_protection: true },
          }),
        ),
      ),
    )

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({
      edition: 'wdsp',
      apiDynamicProtection: true,
      initialized: true,
    })
  })

  it('WAF 即使返回能力开关也按关闭处理', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { edition: 'waf', api_dynamic_protection: true },
          }),
        ),
      ),
    )

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({
      edition: 'waf',
      apiDynamicProtection: false,
      initialized: true,
    })
  })

  it('探测失败时安全降级为 WAF 并隐藏接口防护', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('network error'))))

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({
      edition: 'waf',
      apiDynamicProtection: false,
      initialized: true,
    })
  })
})
