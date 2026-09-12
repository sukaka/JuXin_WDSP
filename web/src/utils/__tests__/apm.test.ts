/* ==================== utils/apm 时间窗与展示工具测试 ==================== */

import dayjs from 'dayjs'
import { describe, expect, it } from 'vitest'
import {
  APM_APPLICATION_ID_PATTERN,
  APM_INGEST_WAIT_BUDGET_MS,
  APM_SEARCH_WINDOW_HOURS,
  buildEventApmTraceHref,
  capApmPlainText,
  formatLagMs,
  formatMs,
  formatPercent,
  isApmIngestionPending,
  isCustomRangeOverCap,
  nextApmIngestRetryDelay,
  parseApmUrlTimeWindow,
  resolveApmTimeRange,
  sanitizeApmReturnPath,
} from '../apm'

describe('resolveApmTimeRange', () => {
  it('快捷档位映射为对应时长（RFC3339）', () => {
    for (const [range, hours] of [
      ['1h', 1],
      ['24h', 24],
      ['7d', 24 * 7],
      ['30d', 24 * 30],
    ] as const) {
      const { start_time, end_time } = resolveApmTimeRange(range)
      const span = dayjs(end_time).diff(dayjs(start_time), 'hour')
      expect(span).toBe(hours)
    }
  })

  it('未知档位缺省按最近 1 小时', () => {
    const { start_time, end_time } = resolveApmTimeRange('bogus')
    expect(dayjs(end_time).diff(dayjs(start_time), 'hour')).toBe(1)
  })

  it('自定义区间优先于快捷档位', () => {
    const s = dayjs('2026-09-01T10:00:00Z')
    const e = dayjs('2026-09-01T12:00:00Z')
    const { start_time, end_time } = resolveApmTimeRange('custom', [s, e])
    expect(start_time).toBe(s.toISOString())
    expect(end_time).toBe(e.toISOString())
  })

  it('自定义未选全时回落到快捷档位', () => {
    const { start_time, end_time } = resolveApmTimeRange('custom', [dayjs(), null])
    expect(dayjs(end_time).diff(dayjs(start_time), 'hour')).toBe(1)
  })
})

describe('isCustomRangeOverCap（检索类接口 24h 限窗前置校验）', () => {
  it('窗口上限恒为 24 小时（与 server parseSearchWindow 口径一致）', () => {
    expect(APM_SEARCH_WINDOW_HOURS).toBe(24)
  })

  it('超过上限判定为超窗', () => {
    const s = dayjs('2026-09-01T00:00:00Z')
    expect(isCustomRangeOverCap([s, s.add(25, 'hour')], 24)).toBe(true)
  })

  it('等于/小于上限不拦截', () => {
    const s = dayjs('2026-09-01T00:00:00Z')
    expect(isCustomRangeOverCap([s, s.add(24, 'hour')], 24)).toBe(false)
    expect(isCustomRangeOverCap([s, s.add(1, 'hour')], 24)).toBe(false)
  })

  it('未选全或空值不拦截（待选全后校验）', () => {
    expect(isCustomRangeOverCap(null, 24)).toBe(false)
    expect(isCustomRangeOverCap([dayjs(), null], 24)).toBe(false)
    expect(isCustomRangeOverCap([null, dayjs()], 24)).toBe(false)
  })
})

describe('formatMs / formatPercent', () => {
  it('空值与非法值返回占位符', () => {
    expect(formatMs(null)).toBe('-')
    expect(formatMs(undefined)).toBe('-')
    expect(formatMs(Number.NaN)).toBe('-')
    expect(formatPercent(null)).toBe('-')
  })

  it('正常值格式化', () => {
    expect(formatMs(12.3)).toBe('12.3 ms')
    expect(formatPercent(0.1234)).toBe('12.34%')
  })
})


/* ==================== P1-01 A3：availability / correlation 判定与跳转工具 ==================== */

describe('isApmIngestionPending（等待入库判定）', () => {
  it('correlation.state=PENDING 时触发', () => {
    expect(isApmIngestionPending({ correlation: { state: 'PENDING' } })).toBe(true)
  })

  it('reason_codes 含 INGESTION_DELAY_CONFIRMED 时触发', () => {
    expect(
      isApmIngestionPending({ availability: { reason_codes: ['INGESTION_DELAY_CONFIRMED'] } }),
    ).toBe(true)
  })

  it('NO_MATCH/UNKNOWN/缺字段不触发（仅有依据的信号才触发自动等待）', () => {
    expect(isApmIngestionPending({ correlation: { state: 'NOT_FOUND' } })).toBe(false)
    expect(isApmIngestionPending({ correlation: { state: 'UNKNOWN' } })).toBe(false)
    expect(isApmIngestionPending({ availability: { reason_codes: ['NO_MATCH'] } })).toBe(false)
    expect(isApmIngestionPending({})).toBe(false)
    expect(isApmIngestionPending({ correlation: null, availability: null })).toBe(false)
  })
})

describe('nextApmIngestRetryDelay（30 秒有界等待）', () => {
  it('预算内按固定间隔重试', () => {
    expect(nextApmIngestRetryDelay(0)).toBe(5_000)
    expect(nextApmIngestRetryDelay(10_000)).toBe(5_000)
  })

  it('最后一次重试夹紧到预算边界', () => {
    expect(nextApmIngestRetryDelay(APM_INGEST_WAIT_BUDGET_MS - 1_000)).toBe(1_000)
  })

  it('预算用尽返回 null（停止自动重试，不无限轮询）', () => {
    expect(nextApmIngestRetryDelay(APM_INGEST_WAIT_BUDGET_MS)).toBeNull()
    expect(nextApmIngestRetryDelay(APM_INGEST_WAIT_BUDGET_MS + 5_000)).toBeNull()
  })

  it('非法输入按 0 处理', () => {
    expect(nextApmIngestRetryDelay(Number.NaN)).toBe(5_000)
    expect(nextApmIngestRetryDelay(-1)).toBe(5_000)
  })
})

describe('formatLagMs', () => {
  it('空值/非法值/负值显示未知', () => {
    expect(formatLagMs(null)).toBe('未知')
    expect(formatLagMs(undefined)).toBe('未知')
    expect(formatLagMs(-5)).toBe('未知')
  })

  it('毫秒/秒/分钟分级展示', () => {
    expect(formatLagMs(800)).toBe('800 毫秒')
    expect(formatLagMs(12_000)).toBe('约 12 秒')
    expect(formatLagMs(125_000)).toBe('约 2 分 5 秒')
  })
})

describe('sanitizeApmReturnPath（返回链接站内白名单）', () => {
  it('白名单内路由放行并给出中文标签', () => {
    expect(sanitizeApmReturnPath('/security-events')).toEqual({
      path: '/security-events',
      label: '返回安全事件',
    })
  })

  it('白名单路由携带查询串仍放行', () => {
    const r = sanitizeApmReturnPath('/security-events?domain=shop.example.com')
    expect(r?.path).toBe('/security-events?domain=shop.example.com')
  })

  it('外部 URL / 协议相对 / javascript: 一律拒绝（防开放重定向）', () => {
    expect(sanitizeApmReturnPath('https://evil.example.com/x')).toBeNull()
    expect(sanitizeApmReturnPath('//evil.example.com')).toBeNull()
    expect(sanitizeApmReturnPath('javascript:alert(1)')).toBeNull()
    expect(sanitizeApmReturnPath('/%2f%2fevil.example.com')).toBeNull()
  })

  it('站内但非白名单路由拒绝', () => {
    expect(sanitizeApmReturnPath('/users')).toBeNull()
    expect(sanitizeApmReturnPath('')).toBeNull()
    expect(sanitizeApmReturnPath(null)).toBeNull()
  })
})

describe('buildEventApmTraceHref（事件 → 调用链跳转上下文）', () => {
  const EVT = {
    request_id: 'req-1',
    application_id: '6f4b3a2e-1111-4222-8333-abcdefabcdef',
    occurred_at: '2026-08-30T00:30:00Z',
  }

  it('携带 request_id、application_id、事件时间 ±5 分钟时间窗与站内返回地址', () => {
    const href = buildEventApmTraceHref(EVT)
    expect(href).toBeTruthy()
    const qs = new URLSearchParams(href!.slice('/apm-traces?'.length))
    expect(href!.startsWith('/apm-traces?')).toBe(true)
    expect(qs.get('request_id')).toBe('req-1')
    expect(qs.get('application_id')).toBe(EVT.application_id)
    expect(qs.get('start_time')).toBe('2026-08-30T00:25:00.000Z')
    expect(qs.get('end_time')).toBe('2026-08-30T00:35:00.000Z')
    expect(qs.get('from')).toBe('/security-events')
  })

  it('事件无 application_id 时不携带该参数', () => {
    const href = buildEventApmTraceHref({ ...EVT, application_id: null })
    expect(href).toBeTruthy()
    expect(href!.includes('application_id')).toBe(false)
  })

  it('无 request_id 或事件时间非法时返回 null（不生成无时间窗的误导链接）', () => {
    expect(buildEventApmTraceHref({ ...EVT, request_id: '' })).toBeNull()
    expect(buildEventApmTraceHref({ ...EVT, occurred_at: 'not-a-time' })).toBeNull()
  })

  it('request_id 中的特殊字符被正确编码', () => {
    const href = buildEventApmTraceHref({ ...EVT, request_id: 'req=<script>' })
    expect(href).toBeTruthy()
    expect(href!.includes('<script>')).toBe(false)
  })
})

describe('parseApmUrlTimeWindow（URL 时间窗解析）', () => {
  it('两者都缺省返回 null（不限定窗口）', () => {
    expect(parseApmUrlTimeWindow(null, null)).toBeNull()
    expect(parseApmUrlTimeWindow('', '  ')).toBeNull()
  })

  it('合法窗口原样通过（规范化为 UTC ISO）', () => {
    const r = parseApmUrlTimeWindow('2026-08-30T00:25:00Z', '2026-08-30T00:35:00Z')
    expect(r).toEqual({
      start_time: '2026-08-30T00:25:00.000Z',
      end_time: '2026-08-30T00:35:00.000Z',
    })
  })

  it('只给其一 / 格式非法 / start 不早于 end / 超 24h 均返回错误文案', () => {
    expect(parseApmUrlTimeWindow('2026-08-30T00:25:00Z', null)).toHaveProperty('error')
    expect(parseApmUrlTimeWindow('bad', '2026-08-30T00:35:00Z')).toHaveProperty('error')
    expect(
      parseApmUrlTimeWindow('2026-08-30T00:35:00Z', '2026-08-30T00:25:00Z'),
    ).toHaveProperty('error')
    expect(
      parseApmUrlTimeWindow('2026-08-29T00:00:00Z', '2026-08-30T00:00:01Z'),
    ).toHaveProperty('error')
  })
})

describe('APM_APPLICATION_ID_PATTERN', () => {
  it('UUID 放行，非 UUID 拒绝', () => {
    expect(APM_APPLICATION_ID_PATTERN.test('6f4b3a2e-1111-4222-8333-abcdefabcdef')).toBe(true)
    expect(APM_APPLICATION_ID_PATTERN.test('app-1')).toBe(false)
    expect(APM_APPLICATION_ID_PATTERN.test('<script>')).toBe(false)
  })
})

describe('capApmPlainText（异常消息/堆栈前端限长）', () => {
  it('未超限原样返回；空值返回空串', () => {
    expect(capApmPlainText('hello')).toBe('hello')
    expect(capApmPlainText('')).toBe('')
    expect(capApmPlainText(null)).toBe('')
  })

  it('超限截断并追加可见标记', () => {
    const s = 'x'.repeat(100)
    const out = capApmPlainText(s, 10)
    expect(out.startsWith('xxxxxxxxxx')).toBe(true)
    expect(out).toContain('已截断')
    expect(out).toContain('100')
  })
})
