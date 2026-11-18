import { useMemo } from 'react'
import { Empty, Spin, Typography } from 'antd'
import EChart, { type EChartOption } from '../../components/EChart'
import type { AccessLogTrendPoint } from '../../api/accessLogs'

export default function AccessLogTrend({ items, loading }: { items: AccessLogTrendPoint[]; loading: boolean }) {
  const option = useMemo<EChartOption>(() => ({
    color: ['#3976d8', '#c94c4c', '#c7832e'],
    grid: { left: 46, right: 20, top: 36, bottom: 32 },
    legend: { top: 0, data: ['请求', '阻断', '5xx'] },
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'time' },
    yAxis: { type: 'value', min: 0, minInterval: 1 },
    series: [
      {
        name: '请求', type: 'line', showSymbol: false, smooth: false,
        data: items.map((point) => [point.bucket, point.total]),
        areaStyle: { opacity: 0.08 }, lineStyle: { width: 1.8 },
      },
      {
        name: '阻断', type: 'line', showSymbol: false, smooth: false,
        data: items.map((point) => [point.bucket, point.blocked]), lineStyle: { width: 1.5 },
      },
      {
        name: '5xx', type: 'line', showSymbol: false, smooth: false,
        data: items.map((point) => [point.bucket, point.errors]), lineStyle: { width: 1.5 },
      },
    ],
  }), [items])
  const totals = items.reduce((acc, point) => ({
    total: acc.total + point.total,
    blocked: acc.blocked + point.blocked,
    errors: acc.errors + point.errors,
  }), { total: 0, blocked: 0, errors: 0 })

  return (
    <section aria-label="访问日志趋势" style={{ marginBottom: 16, borderBottom: '1px solid #edf0f3', paddingBottom: 8 }}>
      <Typography.Text strong>访问趋势</Typography.Text>
      {loading ? (
        <div style={{ height: 210, display: 'grid', placeItems: 'center' }}><Spin /></div>
      ) : items.length === 0 ? (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前筛选范围暂无访问日志" />
      ) : (
        <EChart
          option={option}
          height={210}
          ariaLabel="访问日志请求、阻断和5xx趋势"
          summary={`当前筛选范围共${totals.total}次请求，${totals.blocked}次阻断，${totals.errors}次5xx。`}
        />
      )}
    </section>
  )
}
