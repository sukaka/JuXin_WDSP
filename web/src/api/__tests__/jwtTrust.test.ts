import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  jwtTrustApi,
  jwksHasPrivateMaterial,
  validateStaticJwks,
} from '../jwtTrust'
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

const VALID_PUBLIC_JWKS = JSON.stringify({
  keys: [
    {
      kty: 'RSA',
      kid: 'rsa-1',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbA',
      e: 'AQAB',
    },
    {
      kty: 'EC',
      kid: 'ec-1',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1rHMzV7Ue4Jj6n5s4m3y2k',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    },
  ],
})

describe('jwtTrustApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('get：GET /applications/{id}/jwt-trust-policy 并解包 policy/summary，null 列表归一化为空数组', async () => {
    const fetchMock = stubFetch({
      policy: {
        id: 'p1',
        application_id: APP_ID,
        mode: 'OFF',
        version: 0,
        selectors: null,
        issuers: null,
        updated_by: '',
        created_at: '',
        updated_at: '',
      },
      summary: {
        state: 'NOT_CONFIGURED',
        draft_version: 0,
        published_version: 0,
      },
    })
    const data = await jwtTrustApi.get(APP_ID)
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      `/api/v1/applications/${APP_ID}/jwt-trust-policy`,
    )
    expect(
      (fetchMock.mock.calls[0][1] as RequestInit | undefined)?.method ?? 'GET',
    ).toBe('GET')
    expect(data.policy.mode).toBe('OFF')
    expect(data.policy.selectors).toEqual([])
    expect(data.policy.issuers).toEqual([])
    expect(data.summary.state).toBe('NOT_CONFIGURED')
  })

  it('update：PUT 全量草稿并携带 expected_version 与 reason，返回归一化策略', async () => {
    const fetchMock = stubFetch({
      policy: {
        id: 'p1',
        application_id: APP_ID,
        mode: 'OBSERVE',
        version: 1,
        selectors: [
          { methods: ['GET'], path_prefix: '/api', token_required: false },
        ],
        issuers: [
          {
            issuer: 'https://idp.example.com/',
            audiences: null,
            algorithms: null,
            key_source: { type: 'STATIC_JWKS' },
            clock_skew_seconds: 30,
          },
        ],
        updated_by: 'secops',
        created_at: '2026-09-06T00:00:00Z',
        updated_at: '2026-09-06T00:00:00Z',
      },
    })
    const body = {
      mode: 'OBSERVE' as const,
      expected_version: 0,
      selectors: [
        { methods: ['GET'], path_prefix: '/api', token_required: false },
      ],
      issuers: [
        {
          issuer: 'https://idp.example.com/',
          audiences: ['shop-api'],
          algorithms: ['RS256'],
          key_source: { type: 'STATIC_JWKS' as const, jwks: VALID_PUBLIC_JWKS },
          clock_skew_seconds: 30,
        },
      ],
      reason: '接入身份发行方',
    }
    const saved = await jwtTrustApi.update(APP_ID, body)
    const call = fetchMock.mock.calls[0]
    expect(String(call[0])).toBe(
      `/api/v1/applications/${APP_ID}/jwt-trust-policy`,
    )
    expect((call[1] as RequestInit).method).toBe('PUT')
    expect(JSON.parse(String((call[1] as RequestInit).body))).toEqual(body)
    expect(saved.version).toBe(1)
    expect(saved.issuers[0].audiences).toEqual([])
  })

  it('preflight：POST 候选策略并返回 checks/publishable，checks 为 null 时归一化为空数组', async () => {
    const fetchMock = stubFetch({
      policy: {
        id: 'p1',
        application_id: APP_ID,
        mode: 'OBSERVE',
        version: 1,
        selectors: [],
        issuers: [],
        updated_by: '',
        created_at: '',
        updated_at: '',
      },
      checks: null,
      publishable: true,
    })
    const result = await jwtTrustApi.preflight(APP_ID, { mode: 'OBSERVE' })
    const call = fetchMock.mock.calls[0]
    expect(String(call[0])).toBe(
      `/api/v1/applications/${APP_ID}/jwt-trust-policy/preflight`,
    )
    expect((call[1] as RequestInit).method).toBe('POST')
    expect(JSON.parse(String((call[1] as RequestInit).body))).toEqual({
      mode: 'OBSERVE',
    })
    expect(result.publishable).toBe(true)
    expect(result.checks).toEqual([])
  })

  it('409 冲突原样抛出（由页面提示刷新后重试）', async () => {
    const fn = vi.fn(() =>
      Promise.resolve(
        jsonResponse(409, {
          code: 'RESOURCE_CONFLICT',
          message: '策略已被其他人修改，请刷新后重试',
          data: null,
        }),
      ),
    )
    vi.stubGlobal('fetch', fn)
    await expect(
      jwtTrustApi.update(APP_ID, {
        mode: 'OFF',
        expected_version: 1,
        selectors: [],
        issuers: [],
        reason: 'x',
      }),
    ).rejects.toMatchObject({ status: 409, code: 'RESOURCE_CONFLICT' })
  })
})

describe('validateStaticJwks / jwksHasPrivateMaterial', () => {
  it('合法公钥 JWKS（RSA + EC P-256）通过', () => {
    expect(validateStaticJwks(VALID_PUBLIC_JWKS)).toBeNull()
    expect(jwksHasPrivateMaterial(VALID_PUBLIC_JWKS)).toBe(false)
  })

  it('含 RSA 私钥参数（d/p/q 等）立即拒绝', () => {
    const jwks = JSON.stringify({
      keys: [{ kty: 'RSA', kid: 'k1', n: 'abc', e: 'AQAB', d: 'secret' }],
    })
    expect(jwksHasPrivateMaterial(jwks)).toBe(true)
    expect(validateStaticJwks(jwks)).toContain('私钥参数')
    const jwksP = JSON.stringify({
      keys: [{ kty: 'RSA', kid: 'k1', n: 'abc', e: 'AQAB', p: 'secret' }],
    })
    expect(jwksHasPrivateMaterial(jwksP)).toBe(true)
  })

  it('对称密钥（kty=oct）立即拒绝', () => {
    const jwks = JSON.stringify({
      keys: [{ kty: 'oct', kid: 'k1', k: 'c2VjcmV0' }],
    })
    expect(jwksHasPrivateMaterial(jwks)).toBe(true)
    expect(validateStaticJwks(jwks)).toContain('kty=oct')
  })

  it('非法 JSON / 缺 keys / 空 keys 拒绝；非法 JSON 不误报私钥材料', () => {
    expect(validateStaticJwks('not-json')).toContain('合法 JSON')
    expect(jwksHasPrivateMaterial('not-json')).toBe(false)
    expect(validateStaticJwks('{}')).toContain('keys')
    expect(validateStaticJwks('{"keys":[]}')).toContain('keys')
    expect(validateStaticJwks('')).toContain('请粘贴')
  })

  it('kid 为空或重复拒绝；非 P-256 曲线拒绝；不支持的 kty 拒绝', () => {
    expect(
      validateStaticJwks(
        JSON.stringify({ keys: [{ kty: 'RSA', kid: '', n: 'a', e: 'AQAB' }] }),
      ),
    ).toContain('kid')
    const dup = JSON.stringify({
      keys: [
        { kty: 'RSA', kid: 'k1', n: 'a', e: 'AQAB' },
        { kty: 'RSA', kid: 'k1', n: 'b', e: 'AQAB' },
      ],
    })
    expect(validateStaticJwks(dup)).toContain('kid 重复')
    expect(
      validateStaticJwks(
        JSON.stringify({
          keys: [{ kty: 'EC', kid: 'k1', crv: 'P-384', x: 'a', y: 'b' }],
        }),
      ),
    ).toContain('P-256')
    expect(
      validateStaticJwks(JSON.stringify({ keys: [{ kty: 'OKP', kid: 'k1' }] })),
    ).toContain('RSA 或 EC')
  })
})
