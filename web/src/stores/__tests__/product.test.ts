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
      webWafEnabled: true,
      apmEnabled: false,
      productName: '九章WEB应用智能防护系统',
      initialized: false,
    })
    vi.unstubAllGlobals()
  })

  it('WDSP 且能力开启时暴露 API 防护', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { edition: 'wdsp', api_dynamic_protection: true, web_waf_enabled: true },
          }),
        ),
      ),
    )

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({
      edition: 'wdsp',
      apiDynamicProtection: true,
      webWafEnabled: true,
      initialized: true,
    })
  })

  it('API edition 暴露 API 防护并关闭 Web WAF', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              edition: 'api',
              api_dynamic_protection: true,
              web_waf_enabled: false,
              product_name: '九章API安全系统',
            },
          }),
        ),
      ),
    )

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({
      edition: 'api',
      apiDynamicProtection: true,
      webWafEnabled: false,
      productName: '九章API安全系统',
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
            data: { edition: 'waf', api_dynamic_protection: true, web_waf_enabled: true },
          }),
        ),
      ),
    )

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({
      edition: 'waf',
      apiDynamicProtection: false,
      webWafEnabled: true,
      initialized: true,
    })
  })

  it('探测失败时安全降级为 WAF 并隐藏 API 防护', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('network error'))))

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({
      edition: 'waf',
      apiDynamicProtection: false,
      webWafEnabled: true,
      apmEnabled: false,
      initialized: true,
    })
  })

  it('apm_enabled=true 时开启 APM 能力（共享底座，不做 edition 门控）', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { edition: 'waf', api_dynamic_protection: false, web_waf_enabled: true, apm_enabled: true },
          }),
        ),
      ),
    )

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({
      edition: 'waf',
      apmEnabled: true,
      initialized: true,
    })
  })

  it('apm_enabled 缺省或非 true 按关闭处理（fail-safe）', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { edition: 'waf', api_dynamic_protection: false, web_waf_enabled: true },
          }),
        ),
      ),
    )

    await useProductStore.getState().load()

    expect(useProductStore.getState()).toMatchObject({ apmEnabled: false, initialized: true })
  })
})
