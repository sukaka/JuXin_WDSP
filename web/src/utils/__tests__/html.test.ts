import { describe, expect, it } from 'vitest'
import { escapeHtml, safeCssColor } from '../html'

describe('html utils', () => {
  it('转义所有 HTML 关键特殊字符，防止存储型 XSS', () => {
    expect(escapeHtml(`<img src=x onerror="alert('xss')">&`)).toBe(
      '&lt;img src=x onerror=&quot;alert(&#39;xss&#39;)&quot;&gt;&amp;',
    )
    expect(escapeHtml(null)).toBe('')
    expect(escapeHtml(undefined)).toBe('')
    expect(escapeHtml(42)).toBe('42')
  })

  it('safeCssColor 仅放行安全十六进制/rgb/rgba 颜色，拦截属性注入', () => {
    expect(safeCssColor('#ff4d4f')).toBe('#ff4d4f')
    expect(safeCssColor('rgba(0, 229, 255, 0.4)')).toBe('rgba(0, 229, 255, 0.4)')
    expect(safeCssColor('red" onmouseover="alert(1)')).toBe('#00e5ff')
    expect(safeCssColor('expression(alert(1))')).toBe('#00e5ff')
    expect(safeCssColor(undefined, '#123456')).toBe('#123456')
  })
})
