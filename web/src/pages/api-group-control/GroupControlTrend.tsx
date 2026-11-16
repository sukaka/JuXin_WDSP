import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Empty, Spin, Tag, Typography } from 'antd'
import dayjs from 'dayjs'
import {
  apiGroupControlApi,
  type SharedDeviceQuery,
} from '../../api/apiGroupControl'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'

export default function GroupControlTrend({
  query,
}: {
  query: SharedDeviceQuery
}) {
  const trendQuery = useQuery({
    queryKey: ['api-group-control-trends', query],
    queryFn: () =>
      apiGroupControlApi.trends({
        start: query.start,
        end: query.end,
        application_id: query.application_id,
        device_fingerprint: query.device_fingerprint,
        min_accounts: query.min_accounts,
      }),
  })
  const points = useMemo(() => trendQuery.data?.items ?? [], [trendQuery.data])
  const option = useMemo<EChartOption>(() => {
    const bucket = trendQuery.data?.bucket
    return {
      grid: { left: 48, right: 20, top: 42, bottom: 32 },
      tooltip: { trigger: 'axis' },
      legend: { data: ['共享设备分组', '群控观察信号'], top: 0 },
      xAxis: {
        type: 'category',
        data: points.map((point) =>
          dayjs(point.bucket).format(
            bucket === 'day' ? 'MM-DD' : 'MM-DD HH:mm',
          ),
        ),
        axisLabel: { hideOverlap: true },
      },
      yAxis: { type: 'value', min: 0, minInterval: 1 },
      series: [
        {
          name: '共享设备分组',
          type: 'line',
          smooth: true,
          showSymbol: true,
          itemStyle: { color: '#7c9ef8' },
          data: points.map((point) => point.group_count),
        },
        {
          name: '群控观察信号',
          type: 'line',
          smooth: true,
          showSymbol: true,
          itemStyle: { color: '#d69e2e' },
          data: points.map((point) => point.signal_count),
        },
      ],
    }
  }, [points, trendQuery.data?.bucket])
  const summary = `共 ${points.length} 个真实观测时间桶，共享设备分组与群控观察信号按 ${trendQuery.data?.bucket === 'day' ? '天' : '小时'} 聚合；未观测时段不补零。`

  return (
    <Card
      size="small"
      title="群控观察趋势"
      extra={
        <Tag color="blue">
          {trendQuery.data?.bucket === 'day' ? '按天' : '按小时'}
        </Tag>
      }
      style={{ marginBottom: 16 }}
    >
      <Typography.Paragraph type="secondary">
        仅展示有真实观测的 UTC
        时间桶；未采集时段保持为空，不以补零表示已确认无风险。
      </Typography.Paragraph>
      <QueryErrorAlert error={trendQuery.error} message="加载群控趋势失败" />
      {trendQuery.isLoading ? (
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin />
        </div>
      ) : trendQuery.data && points.length === 0 ? (
        <Empty description="当前时间范围暂无达到阈值的群控趋势观测" />
      ) : trendQuery.data ? (
        <EChart
          option={option}
          height={280}
          ariaLabel="共享设备分组与群控观察信号趋势"
          summary={summary}
        />
      ) : null}
    </Card>
  )
}
