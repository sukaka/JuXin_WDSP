import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiMaskingRulesApi, type ApiMaskingAlgorithm } from '../apiData'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

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

describe('apiMaskingRulesApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it.each([
    ['ENCRYPT', { key_id: 'key-prod_01' }],
    ['MAP', { map_id: 'map-prod_01' }],
  ])('create 原样提交 %s 算法参数', async (algorithm, paramsJson) => {
    const fetchMock = stubFetch({})
    await apiMaskingRulesApi.create({
      name: '规则',
      algorithm: algorithm as ApiMaskingAlgorithm,
      params_json: paramsJson,
    })

    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/api-security/masking-rules')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toMatchObject({
      algorithm,
      params_json: paramsJson,
    })
  })

  it('decrypt 提交 ciphertext 并返回服务端 plaintext', async () => {
    const fetchMock = stubFetch({ plaintext: '恢复后的明文' })
    const result = await apiMaskingRulesApi.decrypt('ciphertext_123==')

    expect(result).toEqual({ plaintext: '恢复后的明文' })
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/api-security/masking-rules/decrypt')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      ciphertext: 'ciphertext_123==',
    })
  })
})
