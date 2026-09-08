import { describe, expect, it } from 'vitest'
import type { EChartOption } from '../EChart'
import { buildAccessibleSummary } from '../EChartAccessibleSummary'

describe('buildAccessibleSummary', () => {
  it('为折线图生成时间范围、首末值、极值和趋势摘要', () => {
    const option: EChartOption = {
      xAxis: { type: 'category', data: ['09:00', '10:00', '11:00'] },
      yAxis: { type: 'value' },
      series: [{ type: 'line', name: '请求量', data: [10, 18, 15] }],
    }

    const summary = buildAccessibleSummary(option, '请求趋势')

    expect(summary).toContain('09:00 至 11:00')
    expect(summary).toContain('请求量')
    expect(summary).toContain('首值 10')
    expect(summary).toContain('末值 15')
    expect(summary).toContain('最低 10')
    expect(summary).toContain('最高 18')
    expect(summary).toContain('总体上升')
  })

  it('为饼图生成总量和主要分类摘要', () => {
    const option: EChartOption = {
      series: [
        {
          type: 'pie',
          data: [
            { name: '阻断', value: 7 },
            { name: '放行', value: 3 },
          ],
        },
      ],
    }

    const summary = buildAccessibleSummary(option, '处置分布')

    expect(summary).toContain('总计 10')
    expect(summary).toContain('阻断 7')
    expect(summary).toContain('放行 3')
  })

  it('无数据时返回明确空状态', () => {
    expect(buildAccessibleSummary({ series: [] }, '风险趋势')).toBe('风险趋势：暂无可供朗读的数据。')
  })
})
