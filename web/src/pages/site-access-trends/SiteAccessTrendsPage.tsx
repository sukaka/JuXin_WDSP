import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Input, Select, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { analyticsApi } from '../../api/analytics'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import SmartTable from '../../components/SmartTable'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import type {
  DomainAccessTrendItem,
  SiteAccessTrendItem,
  SiteAccessTrendPoint,
} from '../../types'

const RANGE_OPTIONS = [
  { value: 'today', label: '今天' },
  { value: '24h', label: '最近24小时' },
  { value: '7d', label: '最近7天' },
]

/** sparkline：无坐标轴折线 + 面积填充，主色 #2f54eb */
function sparkOption(points: SiteAccessTrendPoint[]): EChartOption {
  return {
    grid: { left: 0, right: 0, top: 4, bottom: 0 },
    tooltip: {
      trigger: 'axis',
      formatter: (params) => {
        const list = Array.isArray(params) ? params : [params]
        const p = list[0] as { axisValue?: string; data?: number } | undefined
        return `${dayjs(p?.axisValue).format('MM-DD HH:mm')}：${Number(p?.data ?? 0).toLocaleString()} 次`
      },
    },
    xAxis: { type: 'category', show: false, data: points.map((p) => p.t) },
    yAxis: { type: 'value', show: false, min: 0 },
    series: [
      {
        type: 'line',
        smooth: true,
        symbol: 'none',
        data: points.map((p) => p.requests),
        lineStyle: { color: '#2f54eb', width: 1.5 },
        itemStyle: { color: '#2f54eb' },
        areaStyle: { color: '#2f54eb', opacity: 0.12 },
      },
    ],
  }
}

/** 趋势单元格：有序列画 sparkline，零数据显示占位符 */
function TrendCell({ series }: { series?: SiteAccessTrendPoint[] | null }) {
  if (!series || series.length === 0) {
    return <Typography.Text type="secondary">-</Typography.Text>
  }
  return <EChart option={sparkOption(series)} height={48} ariaLabel="站点访问量趋势" />
}

/** 展开行：该应用下各域名的访问量与趋势（展开时按应用单独查询） */
function DomainTrends({ applicationId, range }: { applicationId: string; range: string }) {
  const [detailRecord, setDetailRecord] = useState<DomainAccessTrendItem | null>(null)
  const domainsQuery = useQuery({
    queryKey: ['analytics', 'site-access-trend-domains', applicationId, range],
    queryFn: () => analyticsApi.siteAccessTrendDomains({ application_id: applicationId, range }),
  })

  const columns: ColumnsType<DomainAccessTrendItem> = [
    { title: '域名', dataIndex: 'domain', ellipsis: true },
    {
      title: '访问趋势',
      dataIndex: 'series',
      width: 220,
      render: (series: SiteAccessTrendPoint[] | null | undefined) => <TrendCell series={series} />,
    },
    {
      title: '访问量',
      dataIndex: 'total_requests',
      width: 140,
      align: 'right',
      sorter: (a, b) => a.total_requests - b.total_requests,
      defaultSortOrder: 'descend',
      render: (v: number) => v.toLocaleString(),
    },
  ]

  if (domainsQuery.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="加载域名访问趋势失败"
        description={domainsQuery.error instanceof ApiError ? domainsQuery.error.message : undefined}
      />
    )
  }

  return (
    <>
      <Table<DomainAccessTrendItem>
        size="small"
        rowKey="domain"
        loading={domainsQuery.isLoading}
        columns={columns}
        dataSource={domainsQuery.data?.items ?? []}
        pagination={false}
        onRow={(record) => ({ onDoubleClick: () => setDetailRecord(record), style: { cursor: 'pointer' } })}
      />
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="域名访问详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}

/** 网站访问趋势：按网站应用聚合访问量与趋势，展开钻取到域名维度 */
export default function SiteAccessTrendsPage() {
  const [range, setRange] = useState('today')
  const [keyword, setKeyword] = useState('')
  const [detailRecord, setDetailRecord] = useState<SiteAccessTrendItem | null>(null)

  const trendsQuery = useQuery({
    queryKey: ['analytics', 'site-access-trends', range],
    queryFn: () => analyticsApi.siteAccessTrends({ range }),
  })

  // 应用名称/编码前端过滤（接口返回全量应用，含零流量）
  const items = useMemo(() => {
    const list = trendsQuery.data?.items ?? []
    const kw = keyword.trim().toLowerCase()
    if (!kw) return list
    return list.filter(
      (it) => it.app_name.toLowerCase().includes(kw) || it.app_code.toLowerCase().includes(kw),
    )
  }, [trendsQuery.data, keyword])

  const columns: ColumnsType<SiteAccessTrendItem> = [
    {
      title: '应用名称',
      dataIndex: 'app_name',
      render: (v: string, record) => (
        <div>
          <div>{v}</div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.app_code}
          </Typography.Text>
        </div>
      ),
    },
    {
      title: '访问趋势',
      dataIndex: 'series',
      width: 220,
      render: (series: SiteAccessTrendPoint[] | null | undefined) => <TrendCell series={series} />,
    },
    {
      title: '访问量',
      dataIndex: 'total_requests',
      width: 140,
      align: 'right',
      sorter: (a, b) => a.total_requests - b.total_requests,
      defaultSortOrder: 'descend',
      render: (v: number) => v.toLocaleString(),
    },
  ]

  return (
    <Card title="网站访问趋势">
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="访问明细数据保留期约 7 天，仅支持查询最近 7 天内的访问趋势。"
      />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          value={range}
          style={{ width: 140 }}
          options={RANGE_OPTIONS}
          onChange={(v) => setRange(v)}
        />
        <Input.Search
          placeholder="应用名称 / 编码"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => setKeyword(v)}
        />
      </Space>

      {trendsQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载网站访问趋势失败"
          description={trendsQuery.error instanceof ApiError ? trendsQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<SiteAccessTrendItem>
          storageKey="site-access-trends"
          rowKey="application_id"
          loading={trendsQuery.isLoading}
          columns={columns}
          dataSource={items}
          onRow={(record) => ({ onDoubleClick: () => setDetailRecord(record), style: { cursor: 'pointer' } })}
          expandable={{
            expandedRowRender: (record) => (
              <DomainTrends applicationId={record.application_id} range={range} />
            ),
          }}
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
          }}
        />
      )}
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="应用访问详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
