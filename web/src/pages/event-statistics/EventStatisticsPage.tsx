import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Col, Radio, Row, Statistic, Typography } from 'antd'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { analyticsApi } from '../../api/analytics'
import { securityEventsApi } from '../../api/securityEvents'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import {
  ATTACK_TYPE_META,
  DISPOSITION_STATUS_META,
  EVENT_ACTION_META,
} from '../../utils/stage4'
import type { SecurityEventItem } from '../../types'

/** 分布图基于最近样本估算（列表接口单页上限 100），非全量精确占比 */
const SAMPLE_SIZE = 100

function countBy<T extends string>(items: SecurityEventItem[], key: (e: SecurityEventItem) => T) {
  const map = new Map<T, number>()
  for (const e of items) map.set(key(e), (map.get(key(e)) ?? 0) + 1)
  return [...map.entries()].sort((a, b) => b[1] - a[1])
}

function metaLabel(map: Record<string, { label: string }>, name: string): string {
  return map[name]?.label ?? name
}

/** 柱状图：攻击类型分布 */
function barOption(entries: [string, number][], map: Record<string, { label: string }>, color: string): EChartOption {
  return {
    grid: { left: 40, right: 12, top: 20, bottom: 60 },
    tooltip: {},
    xAxis: {
      type: 'category',
      data: entries.map(([k]) => metaLabel(map, k)),
      axisLabel: { rotate: entries.length > 4 ? 30 : 0, hideOverlap: true },
    },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ type: 'bar', data: entries.map(([, v]) => v), itemStyle: { color }, barMaxWidth: 32 }],
  }
}

/** 饼图：动作/处置状态分布 */
function pieOption(entries: [string, number][], map: Record<string, { label: string }>): EChartOption {
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [
      {
        type: 'pie',
        radius: ['35%', '62%'],
        center: ['50%', '44%'],
        data: entries.map(([k, v]) => ({ name: metaLabel(map, k), value: v })),
        label: { formatter: '{b}: {c}' },
      },
    ],
  }
}

/** 折线图：事件趋势（事件/阻断/观察） */
function trendOption(data?: { times?: string[] | null; series?: Record<string, number[]> | null }): EChartOption {
  const times = (data?.times ?? []).map((t) => dayjs(t).format('MM-DD HH:mm'))
  const series = data?.series ?? {}
  return {
    grid: { left: 48, right: 16, top: 40, bottom: 28 },
    tooltip: { trigger: 'axis' },
    legend: { data: ['安全事件', '阻断', '观察'], top: 0 },
    xAxis: { type: 'category', data: times, axisLabel: { hideOverlap: true } },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '安全事件', type: 'line', smooth: true, areaStyle: {}, data: series.events ?? [], itemStyle: { color: '#f5222d' } },
      { name: '阻断', type: 'line', smooth: true, data: series.blocks ?? [] },
      { name: '观察', type: 'line', smooth: true, data: series.observes ?? [] },
    ],
  }
}

/** 事件统计：精确计数走分页 total，分布图基于最近 100 条样本，趋势图走聚合接口 */
export default function EventStatisticsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canAnalytics = hasPermission(permissions, 'analytics.security.read')
  const [trendRange, setTrendRange] = useState('24h')
  const todayStart = dayjs().startOf('day').toISOString()

  const todayQuery = useQuery({
    queryKey: ['security-events', 'stats', 'today'],
    queryFn: () => securityEventsApi.list({ start_time: todayStart, page: 1, page_size: 1 }),
  })

  const unprocessedQuery = useQuery({
    queryKey: ['security-events', 'stats', 'unprocessed'],
    queryFn: () => securityEventsApi.list({ disposition_status: 'UNPROCESSED', page: 1, page_size: 1 }),
  })

  const blockedQuery = useQuery({
    queryKey: ['security-events', 'stats', 'blocked'],
    queryFn: () => securityEventsApi.list({ action: 'BLOCK', page: 1, page_size: 1 }),
  })

  const sampleQuery = useQuery({
    queryKey: ['security-events', 'stats', 'sample'],
    queryFn: () => securityEventsApi.list({ page: 1, page_size: SAMPLE_SIZE }),
  })

  const trendQuery = useQuery({
    queryKey: ['analytics', 'security-event-trend', trendRange],
    queryFn: () => analyticsApi.securityEventTrend({ range: trendRange }),
    enabled: canAnalytics,
  })

  const sample = useMemo(() => sampleQuery.data?.items ?? [], [sampleQuery.data])
  const attackDist = useMemo(() => countBy(sample, (e) => e.attack_type), [sample])
  const actionDist = useMemo(() => countBy(sample, (e) => e.action), [sample])
  const dispositionDist = useMemo(() => countBy(sample, (e) => e.disposition_status), [sample])

  const firstError = [todayQuery, unprocessedQuery, blockedQuery, sampleQuery].find((q) => q.isError)

  return (
    <Card title="事件统计">
      <Typography.Paragraph type="secondary" style={{ marginTop: 0 }}>
        卡片计数使用分页 total（精确）；攻击类型/动作/处置分布基于最近 {SAMPLE_SIZE}{' '}
        条事件样本估算占比，仅供趋势参考。完整统计请使用「统计分析」。
      </Typography.Paragraph>
      {firstError ? (
        <Alert
          type="error"
          showIcon
          message="加载统计数据失败"
          description={firstError.error instanceof ApiError ? firstError.error.message : undefined}
        />
      ) : (
        <>
          <Row gutter={16} style={{ marginBottom: 24 }}>
            <Col span={8}>
              <Card size="small">
                <Statistic title="今日事件数" value={todayQuery.data?.total ?? 0} loading={todayQuery.isLoading} />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small">
                <Statistic
                  title="未处置事件（全部）"
                  value={unprocessedQuery.data?.total ?? 0}
                  loading={unprocessedQuery.isLoading}
                  valueStyle={{ color: '#cf1322' }}
                />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small">
                <Statistic
                  title="阻断事件（全部）"
                  value={blockedQuery.data?.total ?? 0}
                  loading={blockedQuery.isLoading}
                />
              </Card>
            </Col>
          </Row>

          {canAnalytics && (
            <Card
              size="small"
              title="事件趋势"
              style={{ marginBottom: 16 }}
              extra={
                <Radio.Group
                  value={trendRange}
                  onChange={(e) => setTrendRange(e.target.value as string)}
                  options={[
                    { value: '24h', label: '24小时' },
                    { value: '7d', label: '7天' },
                    { value: '30d', label: '30天' },
                  ]}
                  optionType="button"
                  size="small"
                />
              }
            >
              <EChart option={trendOption(trendQuery.data)} height={280} ariaLabel="安全事件趋势" />
            </Card>
          )}

          <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
            以下分布基于最近 {sample.length} 条事件样本统计
          </Typography.Text>

          <Row gutter={16}>
            <Col span={8}>
              <Card size="small" title="攻击类型分布" loading={sampleQuery.isLoading}>
                <EChart option={barOption(attackDist, ATTACK_TYPE_META, '#f5222d')} height={300} ariaLabel="攻击类型分布" />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small" title="动作分布" loading={sampleQuery.isLoading}>
                <EChart option={pieOption(actionDist, EVENT_ACTION_META)} height={300} ariaLabel="事件动作分布" />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small" title="处置状态分布" loading={sampleQuery.isLoading}>
                <EChart option={pieOption(dispositionDist, DISPOSITION_STATUS_META)} height={300} ariaLabel="事件处置状态分布" />
              </Card>
            </Col>
          </Row>
        </>
      )}
    </Card>
  )
}
