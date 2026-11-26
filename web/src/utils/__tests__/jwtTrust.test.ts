import { describe, expect, it } from 'vitest'
import {
  JWT_TOKEN_BINDING_MODE_META,
  isDPoPBindingMode,
  isMTLSBindingMode,
  mapJwtTrustFieldErrorPath,
} from '../jwtTrust'

describe('mapJwtTrustFieldErrorPath', () => {
  it('映射顶级字段 mode 与 reason', () => {
    expect(mapJwtTrustFieldErrorPath('mode')).toEqual(['mode'])
    expect(mapJwtTrustFieldErrorPath('reason')).toEqual(['reason'])
  })

  it('映射 selectors 字段路径', () => {
    expect(mapJwtTrustFieldErrorPath('selectors[0]')).toEqual(['selectors', 0])
    expect(mapJwtTrustFieldErrorPath('selectors[0].path_exact')).toEqual([
      'selectors',
      0,
      'path',
    ])
    expect(mapJwtTrustFieldErrorPath('selectors[1].path_prefix')).toEqual([
      'selectors',
      1,
      'path',
    ])
    expect(mapJwtTrustFieldErrorPath('selectors[2].methods')).toEqual([
      'selectors',
      2,
      'methods',
    ])
    expect(mapJwtTrustFieldErrorPath('selectors[2].token_required')).toEqual([
      'selectors',
      2,
      'token_required',
    ])
  })

  it('映射 issuers 子字段路径（含 role_claims / tenant_claim / key_source）', () => {
    expect(mapJwtTrustFieldErrorPath('issuers[0]')).toEqual(['issuers', 0])
    expect(mapJwtTrustFieldErrorPath('issuers[0].issuer')).toEqual([
      'issuers',
      0,
      'issuer',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].audiences')).toEqual([
      'issuers',
      0,
      'audiences',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].algorithms')).toEqual([
      'issuers',
      0,
      'algorithms',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].clock_skew_seconds')).toEqual([
      'issuers',
      0,
      'clock_skew_seconds',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[1].tenant_claim')).toEqual([
      'issuers',
      1,
      'tenant_claim',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].role_claims')).toEqual([
      'issuers',
      0,
      'role_claims',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].key_source.jwks')).toEqual([
      'issuers',
      0,
      'jwks',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].key_source.url')).toEqual([
      'issuers',
      0,
      'url',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].key_source.type')).toEqual([
      'issuers',
      0,
      'key_source_type',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].token_binding')).toEqual([
      'issuers',
      0,
      'token_binding_mode',
    ])
    expect(mapJwtTrustFieldErrorPath('issuers[0].token_binding.mode')).toEqual([
      'issuers',
      0,
      'token_binding_mode',
    ])
    expect(
      mapJwtTrustFieldErrorPath('issuers[0].token_binding.require_nonce'),
    ).toEqual(['issuers', 0, 'dpop_require_nonce'])
    expect(
      mapJwtTrustFieldErrorPath(
        'issuers[0].token_binding.max_proof_age_seconds',
      ),
    ).toEqual(['issuers', 0, 'dpop_max_proof_age_seconds'])
    expect(
      mapJwtTrustFieldErrorPath('issuers[0].token_binding.nonce_ttl_seconds'),
    ).toEqual(['issuers', 0, 'dpop_nonce_ttl_seconds'])
    expect(
      mapJwtTrustFieldErrorPath('issuers[0].token_binding.allowed_dpop_algs'),
    ).toEqual(['issuers', 0, 'dpop_allowed_algs'])
  })

  it('令牌持有证明绑定模式枚举与辅助判断完整', () => {
    expect(Object.keys(JWT_TOKEN_BINDING_MODE_META)).toEqual([
      'NONE',
      'DPOP_OPTIONAL',
      'DPOP_REQUIRED',
      'MTLS_REQUIRED',
      'DPOP_OR_MTLS',
    ])
    expect(isDPoPBindingMode('NONE')).toBe(false)
    expect(isDPoPBindingMode('MTLS_REQUIRED')).toBe(false)
    expect(isDPoPBindingMode('DPOP_OPTIONAL')).toBe(true)
    expect(isDPoPBindingMode('DPOP_REQUIRED')).toBe(true)
    expect(isDPoPBindingMode('DPOP_OR_MTLS')).toBe(true)
    expect(isMTLSBindingMode('MTLS_REQUIRED')).toBe(true)
    expect(isMTLSBindingMode('DPOP_OR_MTLS')).toBe(true)
    expect(isMTLSBindingMode('DPOP_REQUIRED')).toBe(false)
  })

  it('未知字段路径返回 null', () => {
    expect(mapJwtTrustFieldErrorPath('unknown_field')).toBeNull()
    expect(mapJwtTrustFieldErrorPath('selectors[0].unknown')).toBeNull()
    expect(mapJwtTrustFieldErrorPath('issuers[0].unknown')).toBeNull()
  })
})
