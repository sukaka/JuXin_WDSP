import { describe, expect, it } from 'vitest'
import { escapeHtml, formatDuration } from '../format'

describe('formatDuration 起止时长格式化', () => {
  it('缺任一端或非法值返回占位符', () => {
    expect(formatDuration(undefined, '2026-08-31T10:00:00Z')).toBe('-')
    expect(formatDuration('2026-08-31T10:00:00Z', null)).toBe('-')
    expect(formatDuration('not-a-date', '2026-08-31T10:00:00Z')).toBe('-')
    // 结束早于开始
    expect(formatDuration('2026-08-31T11:00:00Z', '2026-08-31T10:00:00Z')).toBe('-')
  })

  it('60 秒内按秒展示', () => {
    expect(formatDuration('2026-08-31T10:00:00Z', '2026-08-31T10:00:45Z')).toBe('45秒')
  })

  it('60 分钟内按分钟展示', () => {
    expect(formatDuration('2026-08-31T10:00:00Z', '2026-08-31T10:43:00Z')).toBe('43分钟')
  })

  it('24 小时内按小时+余分钟展示，整小时省略分钟', () => {
    expect(formatDuration('2026-08-31T10:00:00Z', '2026-08-31T11:23:00Z')).toBe('1小时23分')
    expect(formatDuration('2026-08-31T10:00:00Z', '2026-08-31T13:00:00Z')).toBe('3小时')
  })

  it('超过 24 小时按天+余小时展示，整天省略小时', () => {
    expect(formatDuration('2026-08-30T10:00:00Z', '2026-08-31T13:00:00Z')).toBe('1天3小时')
    expect(formatDuration('2026-08-29T10:00:00Z', '2026-08-31T10:00:00Z')).toBe('2天')
  })
})

describe('escapeHtml HTML 转义', () => {
  it('转义全部 HTML 特殊字符', () => {
    expect(escapeHtml(`<img src=x onerror="alert('1')">&`)).toBe(
      '&lt;img src=x onerror=&quot;alert(&#39;1&#39;)&quot;&gt;&amp;',
    )
  })

  it('无特殊字符时原样返回', () => {
    expect(escapeHtml('GET /api/v1/users?page=1')).toBe('GET /api/v1/users?page=1')
    expect(escapeHtml('')).toBe('')
  })
})
