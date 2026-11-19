import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Input,
  Row,
  Segmented,
  Space,
  Spin,
  Statistic,
  Table,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { analyticsApi } from '../../api/analytics'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import SmartTable from '../../components/SmartTable'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { formatBytes, formatDateTime } from '../../utils/format'
import type {
  DomainAccessTrendItem,
  SiteAccessTrendPoint,
  SiteTrafficItem,
  SiteTrafficPoint,
} from '../../types'

type RangeKey = 'realtime' | 'today' | '7d' | '30d'

const RANGE_OPTIONS: { value: RangeKey; label: string }[] = [
  { value: 'realtime', label: '实时' },
  { value: 'today', label: '今天' },
  { value: '7d', label: '近7天' },
  { value: '30d', label: '近30天' },
]

const RANGE_LABEL: Record<RangeKey, string> = {
  realtime: '实时（最近1小时）',
  today: '今天',
  '7d': '近7天',
  '30d': '近30天',
}

/** 域名钻取沿用旧接口（时间跨度上限 7 天）：实时档映射为 1h；近30天档不发起查询 */
const DOMAIN_RANGE_MAP: Record<Exclude<RangeKey, '30d'>, string> = {
  realtime: '1h',
  today: 'today',
  '7d': '7d',
}

const GRANULARITY_LABEL: Record<string, string> = {
  minute: '分钟',
  hour: '小时',
  day: '天',
}

const SOURCE_LABEL: Record<string, string> = {
  access_logs: '访问日志实时聚合',
  site_traffic_daily: '按日汇总数据',
}

/** 档位换算为起止时间（RFC3339）：实时=最近1小时，今天=当日零点至今，近7/30天=向前回溯 */
function rangeToQuery(range: RangeKey): { start_time: string; end_time: string } {
  const end = dayjs()
  let start: dayjs.Dayjs
  switch (range) {
    case 'realtime':
      start = end.subtract(1, 'hour')
      break
    case 'today':
      start = end.startOf('day')
      break
    case '7d':
      start = end.subtract(7, 'day')
      break
    case '30d':
      start = end.subtract(30, 'day')
      break
  }
  return { start_time: start.toISOString(), end_time: end.toISOString() }
}

/** 可空计数渲染：null（日聚合口径不提供）显示占位符 */
function renderCount(v: number | null | undefined): string {
  return v === null || v === undefined ? '-' : v.toLocaleString()
}

/** sparkline：无坐标轴折线 + 面积填充，主色 #2f54eb */
function sparkOption(points: { t: string; requests: number }[]): EChartOption {
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
function TrendCell({ series }: { series?: { t: string; requests: number }[] | null }) {
  if (!series || series.length === 0) {
    return <Typography.Text type="secondary">-</Typography.Text>
  }
  return <EChart option={sparkOption(series)} height={48} ariaLabel="站点访问量趋势" />
}

/** 详情大图：时间 X 轴 + 请求数面积图，tooltip 附带流入/流出流量字节数 */
function trafficChartOption(points: SiteTrafficPoint[], granularity: string): EChartOption {
  const labelFmt = granularity === 'day' ? 'MM-DD' : 'MM-DD HH:mm'
  return {
    grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    tooltip: {
      trigger: 'axis',
      formatter: (params) => {
        const list = Array.isArray(params) ? params : [params]
        const first = list[0] as { dataIndex?: number } | undefined
        const pt = points[first?.dataIndex ?? 0]
        if (!pt) return ''
        const time = dayjs(pt.t).format(granularity === 'day' ? 'YYYY-MM-DD' : 'YYYY-MM-DD HH:mm')
        return [
          time,
          `请求数：${pt.requests.toLocaleString()} 次`,
          `流入流量：${formatBytes(pt.bytes_in)}`,
          `流出流量：${formatBytes(pt.bytes_out)}`,
        ].join('<br/>')
      },
    },
    xAxis: {
      type: 'category',
      data: points.map((pt) => pt.t),
      axisLabel: { formatter: (v: string) => dayjs(v).format(labelFmt) },
    },
    yAxis: { type: 'value', min: 0, name: '请求数' },
    series: [
      {
        type: 'line',
        smooth: true,
        symbol: 'none',
        data: points.map((pt) => pt.requests),
        lineStyle: { color: '#2f54eb', width: 2 },
        itemStyle: { color: '#2f54eb' },
        areaStyle: { color: '#2f54eb', opacity: 0.18 },
      },
    ],
  }
}

/** 展开行：该应用下各域名的访问量与趋势（旧接口跨度上限 7 天，近30天档仅提示不查询） */
function DomainTrends({ applicationId, range }: { applicationId: string; range: RangeKey }) {
  const [detailRecord, setDetailRecord] = useState<DomainAccessTrendItem | null>(null)
  const domainRange = range === '30d' ? null : DOMAIN_RANGE_MAP[range]
  const domainsQuery = useQuery({
    queryKey: ['analytics', 'site-access-trend-domains', applicationId, range],
    queryFn: () =>
      analyticsApi.siteAccessTrendDomains({
        application_id: applicationId,
        range: domainRange ?? 'today',
      }),
    enabled: domainRange !== null,
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

  if (domainRange === null) {
    return (
      <Alert
        type="info"
        showIcon
        message="域名明细仅支持 7 天内范围"
        description="域名访问明细来自访问日志（保留期约 7 天），近30天档位不提供域名钻取。"
      />
    )
  }

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

/** 站点流量详情抽屉：单站点大图趋势 + 汇总小卡片 + 时间范围/粒度/数据来源说明 */
function SiteTrafficDrawer({
  item,
  range,
  onClose,
}: {
  item: SiteTrafficItem | null
  range: RangeKey
  onClose: () => void
}) {
  const detailQuery = useQuery({
    queryKey: ['analytics', 'site-traffic', 'detail', item?.application_id, range],
    queryFn: () =>
      analyticsApi.siteTraffic({ ...rangeToQuery(range), application_id: item?.application_id }),
    enabled: item !== null,
  })

  const detail = detailQuery.data
  const appItem =
    detail?.items?.find((it) => it.application_id === item?.application_id) ?? detail?.items?.[0]
  const series = appItem?.series ?? []

  const stats: { title: string; value: string | number }[] = appItem
    ? [
        { title: '总请求数', value: appItem.total_requests },
        { title: '流出流量', value: formatBytes(appItem.total_bytes_out) },
        { title: '独立访客IP', value: renderCount(appItem.unique_ips) },
        { title: '被拦截请求数', value: renderCount(appItem.blocked_requests) },
        { title: '峰值桶请求数', value: renderCount(detail?.summary?.peak_bucket_requests) },
      ]
    : []

  return (
    <Drawer
      title={item ? `站点流量详情：${item.app_name}` : '站点流量详情'}
      open={item !== null}
      onClose={onClose}
      width={720}
    >
      {detailQuery.isLoading ? (
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin />
        </div>
      ) : detailQuery.isError ? (
        <QueryErrorAlert error={detailQuery.error} message="加载站点流量详情失败" />
      ) : detail ? (
        <Space direction="vertical" size={16} style={{ display: 'flex' }}>
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="站点">
              {appItem?.app_name ?? item?.app_name}
              <Typography.Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
                {appItem?.app_code ?? item?.app_code}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="时间范围">
              {formatDateTime(detail.start)} ~ {formatDateTime(detail.end)}（{RANGE_LABEL[range]}）
            </Descriptions.Item>
            <Descriptions.Item label="统计粒度">
              {GRANULARITY_LABEL[detail.granularity] ?? detail.granularity}
            </Descriptions.Item>
            <Descriptions.Item label="数据来源">
              {SOURCE_LABEL[detail.source] ?? detail.source}
            </Descriptions.Item>
          </Descriptions>
          <Row gutter={[12, 12]}>
            {stats.map((s) => (
              <Col key={s.title} flex="1 1 120px">
                <Card size="small">
                  <Statistic title={s.title} value={s.value} valueStyle={{ fontSize: 20 }} />
                </Card>
              </Col>
            ))}
          </Row>
          <Card size="small" title="请求数趋势">
            {series.length === 0 ? (
              <Typography.Text type="secondary">该时间范围内无流量数据</Typography.Text>
            ) : (
              <EChart
                option={trafficChartOption(series, detail.granularity)}
                height={320}
                ariaLabel="站点请求数趋势"
              />
            )}
          </Card>
        </Space>
      ) : null}
    </Drawer>
  )
}

/** 站点流量分析：按站点应用聚合请求数与流量，支持实时/今天/近7天/近30天四档时间范围 */
export default function SiteAccessTrendsPage() {
  const [range, setRange] = useState<RangeKey>('today')
  const [keyword, setKeyword] = useState('')
  const [detailRecord, setDetailRecord] = useState<SiteTrafficItem | null>(null)
  const [trafficDetail, setTrafficDetail] = useState<SiteTrafficItem | null>(null)

  const trafficQuery = useQuery({
    queryKey: ['analytics', 'site-traffic', range],
    queryFn: () => analyticsApi.siteTraffic(rangeToQuery(range)),
    // 实时档每 30 秒自动刷新
    refetchInterval: range === 'realtime' ? 30_000 : false,
  })

  const summary = trafficQuery.data?.summary

  // 应用名称/编码前端过滤（接口返回全量应用，含零流量）
  const items = useMemo(() => {
    const list = trafficQuery.data?.items ?? []
    const kw = keyword.trim().toLowerCase()
    if (!kw) return list
    return list.filter(
      (it) => it.app_name.toLowerCase().includes(kw) || it.app_code.toLowerCase().includes(kw),
    )
  }, [trafficQuery.data, keyword])

  const columns: ColumnsType<SiteTrafficItem> = [
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
      width: 200,
      render: (series: SiteTrafficPoint[] | null | undefined) => <TrendCell series={series} />,
    },
    {
      title: '访问量',
      dataIndex: 'total_requests',
      width: 130,
      align: 'right',
      sorter: (a, b) => a.total_requests - b.total_requests,
      defaultSortOrder: 'descend',
      render: (v: number) => v.toLocaleString(),
    },
    {
      title: '总流量（流出）',
      dataIndex: 'total_bytes_out',
      width: 130,
      align: 'right',
      render: (v: number) => formatBytes(v),
    },
    {
      title: '独立IP',
      dataIndex: 'unique_ips',
      width: 110,
      align: 'right',
      render: renderCount,
    },
    {
      title: '拦截数',
      dataIndex: 'blocked_requests',
      width: 110,
      align: 'right',
      render: renderCount,
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setTrafficDetail(record)}>
          详情
        </Button>
      ),
    },
  ]

  return (
    <Card title="站点流量分析">
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="实时 / 今天 / 近7天数据来自访问日志实时聚合；近30天来自按日汇总数据，独立访客 IP 不跨天去重。域名明细仅支持 7 天内范围。"
      />
      <Space style={{ marginBottom: 16 }} wrap>
        <Segmented<RangeKey> value={range} options={RANGE_OPTIONS} onChange={setRange} />
        {range === 'realtime' && (
          <Typography.Text type="secondary">每30秒自动刷新</Typography.Text>
        )}
        <Input.Search
          placeholder="应用名称 / 编码"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => setKeyword(v)}
        />
      </Space>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={12} sm={8} md={8} lg={4}>
          <Card size="small">
            <Statistic
              title="总请求数"
              value={summary?.total_requests ?? 0}
              loading={trafficQuery.isLoading}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              峰值桶请求数 {renderCount(summary?.peak_bucket_requests)}
            </Typography.Text>
          </Card>
        </Col>
        <Col xs={12} sm={8} md={8} lg={4}>
          <Card size="small">
            <Statistic
              title="总流入流量"
              value={formatBytes(summary?.total_bytes_in)}
              loading={trafficQuery.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={8} md={8} lg={4}>
          <Card size="small">
            <Statistic
              title="总流出流量"
              value={formatBytes(summary?.total_bytes_out)}
              loading={trafficQuery.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={8} md={8} lg={4}>
          <Card size="small">
            <Statistic
              title={
                <Tooltip title="按时间范围去重的独立访客 IP；近30天档来自按日汇总数据，不跨天去重，显示为 -">
                  <span>独立访客IP</span>
                </Tooltip>
              }
              value={renderCount(summary?.unique_ips)}
              loading={trafficQuery.isLoading}
            />
          </Card>
        </Col>
        <Col xs={12} sm={8} md={8} lg={4}>
          <Card size="small">
            <Statistic
              title="被拦截请求数"
              value={renderCount(summary?.blocked_requests)}
              loading={trafficQuery.isLoading}
            />
          </Card>
        </Col>
      </Row>

      {trafficQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载站点流量失败"
          description={trafficQuery.error instanceof ApiError ? trafficQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<SiteTrafficItem>
          storageKey="site-access-trends"
          rowKey="application_id"
          loading={trafficQuery.isLoading}
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
      <SiteTrafficDrawer item={trafficDetail} range={range} onClose={() => setTrafficDetail(null)} />
    </Card>
  )
}
