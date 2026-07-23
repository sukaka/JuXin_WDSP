import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Col, Row, Statistic, Tag, Typography } from 'antd'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { securityEventsApi } from '../../api/securityEvents'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
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

/** 事件统计（简单版）：精确计数走分页 total，分布基于最近 100 条样本 */
export default function EventStatisticsPage() {
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

  const sample = useMemo(() => sampleQuery.data?.items ?? [], [sampleQuery.data])
  const attackDist = useMemo(() => countBy(sample, (e) => e.attack_type), [sample])
  const actionDist = useMemo(() => countBy(sample, (e) => e.action), [sample])
  const dispositionDist = useMemo(() => countBy(sample, (e) => e.disposition_status), [sample])

  const distColumns = (render: (v: string) => React.ReactNode) => [
    {
      title: '类别',
      dataIndex: 'name',
      render,
    },
    { title: '数量', dataIndex: 'count', align: 'right' as const, width: 90 },
    {
      title: '占比',
      dataIndex: 'percent',
      width: 90,
      render: (v: string) => <Tag>{v}</Tag>,
    },
  ]

  const distRows = (entries: [string, number][]) =>
    entries.map(([name, count]) => ({
      key: name,
      name,
      count,
      percent: sample.length > 0 ? `${Math.round((count / sample.length) * 100)}%` : '-',
    }))

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

          <Typography.Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
            以下分布基于最近 {sample.length} 条事件样本统计
          </Typography.Text>

          <Row gutter={16}>
            <Col span={8}>
              <Card size="small" title="攻击类型分布">
                <SmartTable
                  storageKey="event-statistics"
                  size="small"
                  rowKey="key"
                  loading={sampleQuery.isLoading}
                  columns={distColumns((v) => <StatusTag value={v} map={ATTACK_TYPE_META} />)}
                  dataSource={distRows(attackDist)}
                  pagination={false}
                />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small" title="动作分布">
                <SmartTable
                  storageKey="event-statistics-actions"
                  size="small"
                  rowKey="key"
                  loading={sampleQuery.isLoading}
                  columns={distColumns((v) => <StatusTag value={v} map={EVENT_ACTION_META} />)}
                  dataSource={distRows(actionDist)}
                  pagination={false}
                />
              </Card>
            </Col>
            <Col span={8}>
              <Card size="small" title="处置状态分布">
                <SmartTable
                  storageKey="event-statistics-dispositions"
                  size="small"
                  rowKey="key"
                  loading={sampleQuery.isLoading}
                  columns={distColumns((v) => <StatusTag value={v} map={DISPOSITION_STATUS_META} />)}
                  dataSource={distRows(dispositionDist)}
                  pagination={false}
                />
              </Card>
            </Col>
          </Row>
        </>
      )}
    </Card>
  )
}
