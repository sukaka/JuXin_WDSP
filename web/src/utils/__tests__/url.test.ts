import { describe, expect, it } from 'vitest'
import { isSafeHttpUrl } from '../url'

describe('isSafeHttpUrl', () => {
  it('允许 http 与 https URL', () => {
    expect(isSafeHttpUrl('https://nvd.nist.gov/vuln/detail/CVE-2026-0001')).toBe(true)
    expect(isSafeHttpUrl('http://example.com/advisory')).toBe(true)
    expect(isSafeHttpUrl('  https://example.com/path?a=1  ')).toBe(true)
  })

  it('拦截 javascript: / data: / vbscript: 及非法 URL', () => {
    expect(isSafeHttpUrl('javascript:alert(1)')).toBe(false)
    expect(isSafeHttpUrl('  JaVaScRiPt:alert(document.cookie)  ')).toBe(false)
    expect(isSafeHttpUrl('data:text/html,<script>alert(1)</script>')).toBe(false)
    expect(isSafeHttpUrl('vbscript:msgbox(1)')).toBe(false)
    expect(isSafeHttpUrl('/relative/path')).toBe(false)
    expect(isSafeHttpUrl('')).toBe(false)
    expect(isSafeHttpUrl(null)).toBe(false)
    expect(isSafeHttpUrl(undefined)).toBe(false)
  })
})
