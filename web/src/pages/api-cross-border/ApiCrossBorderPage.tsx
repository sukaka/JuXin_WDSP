import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Card,
  Col,
  Input,
  Radio,
  Row,
  Select,
  Space,
  Statistic,
  Tabs,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  apiCrossBorderApi,
  type ApiCrossBorderCountryStat,
  type ApiCrossBorderCountryTypeStat,
  type ApiCrossBorderEndpointStat,
  type ApiCrossBorderEvent,
} from '../../api/apiCrossBorder'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { API_COUNTRY_META, API_SENSITIVE_TYPE_META } from '../../utils/stage8'

/** 方向展示映射（与 apigeo Direction 词表一致） */
const DIRECTION_META: Record<string, { color: string; label: string }> = {
  OUT: { color: 'volcano', label: '出境' },
  IN: { color: 'geekblue', label: '入境' },
}

/** 风险等级展示映射（与 apigeo RiskLevel 词表一致） */
const RISK_LEVEL_META: Record<string, { color: string; label: string }> = {
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
}

/** 趋势图（按天事件数） */
function trendOption(points?: { date: string; event_count: number }[]): EChartOption {
  const rows = points ?? []
  return {
    grid: { left: 48, right: 16, top: 24, bottom: 28 },
    tooltip: { trigger: 'axis' },
    xAxis: { type: 'category', data: rows.map((p) => p.date), axisLabel: { hideOverlap: true } },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '跨境事件', type: 'line', smooth: true, areaStyle: {}, data: rows.map((p) => p.event_count), itemStyle: { color: '#fa8c16' } },
    ],
  }
}

/** 国家聚合表 */
const countryColumns: ColumnsType<ApiCrossBorderCountryStat> = [
  { title: '国家/地区', dataIndex: 'country', width: 110, render: (v: string) => <StatusTag value={v} map={API_COUNTRY_META} /> },
  { title: '事件数', dataIndex: 'event_count', width: 90 },
  { title: '涉及 API 数', dataIndex: 'endpoint_count', width: 110 },
  {
    title: '敏感类型',
    dataIndex: 'data_types',
    render: (v: string[] | null) =>
      v && v.length > 0
        ? v.map((t) => <StatusTag key={t} value={t} map={API_SENSITIVE_TYPE_META} />)
        : '-',
  },
]

/** 国家×敏感类型聚合表 */
const countryTypeColumns: ColumnsType<ApiCrossBorderCountryTypeStat> = [
  { title: '国家/地区', dataIndex: 'country', width: 110, render: (v: string) => <StatusTag value={v} map={API_COUNTRY_META} /> },
  { title: '敏感类型', dataIndex: 'data_type', render: (v: string) => <StatusTag value={v} map={API_SENSITIVE_TYPE_META} /> },
  { title: '事件数', dataIndex: 'event_count', width: 90 },
]

/** 端点聚合表 */
const endpointColumns: ColumnsType<ApiCrossBorderEndpointStat> = [
  {
    title: 'API',
    dataIndex: 'endpoint_key',
    ellipsis: true,
    render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
  },
  { title: '事件数', dataIndex: 'event_count', width: 90 },
  { title: '涉及国家/地区数', dataIndex: 'country_count', width: 140 },
]

/**
 * 数据出境看板（WDSP / 阶段8 W15）：境外客户端涉敏流量的聚合看板与明细分页。
 * 只读页面，权限点 api_data.read；GeoIP 数据源未加载时 geo_enabled=false，看板降级为历史数据并显式提示。
 */
export default function ApiCrossBorderPage() {
  const [days, setDays] = useState(7)
  const [country, setCountry] = useState('')
  const [appliedCountry, setAppliedCountry] = useState('')
  const [direction, setDirection] = useState<string | undefined>()
  const [riskLevel, setRiskLevel] = useState<string | undefined>()
  const [endpointKey, setEndpointKey] = useState('')
  const [appliedEndpointKey, setAppliedEndpointKey] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<Record<string, unknown> | null>(null)
  const [detailTitle, setDetailTitle] = useState('记录详情')

  const query = useQuery({
    queryKey: ['api-cross-border', days, appliedCountry, direction, riskLevel, appliedEndpointKey, page, pageSize],
    queryFn: () =>
      apiCrossBorderApi.get({
        days,
        country: appliedCountry || undefined,
        direction,
        risk_level: riskLevel,
        endpoint_key: appliedEndpointKey || undefined,
        page,
        page_size: pageSize,
      }),
  })

  const data = query.data
  const dashboard = data?.dashboard
  const summary = dashboard?.summary

  const eventColumns: ColumnsType<ApiCrossBorderEvent> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    { title: '国家/地区', dataIndex: 'country', width: 100, render: (v: string) => (v ? <StatusTag value={v} map={API_COUNTRY_META} /> : '-') },
    {
      title: '方向',
      dataIndex: 'direction',
      width: 80,
      render: (v: string) => <StatusTag value={v} map={DIRECTION_META} />,
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={RISK_LEVEL_META} />,
    },
    {
      title: 'API',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
    {
      title: '敏感类型',
      dataIndex: 'data_types',
      width: 200,
      render: (v: string[] | null) =>
        v && v.length > 0
          ? v.map((t) => <StatusTag key={t} value={t} map={API_SENSITIVE_TYPE_META} />)
          : '-',
    },
    { title: '客户端 IP', dataIndex: 'client_ip', width: 130, render: (v: string) => v || '-' },
  ]

  return (
    <Card title="数据出境看板">
      <Typography.Paragraph type="secondary">
        境外客户端涉敏流量观察：响应侧涉敏数据流向境外记为「出境」，境外客户端提交涉敏数据记为「入境」；
        观察记录不改变流量处置，风险等级由命中数据类型推导。
      </Typography.Paragraph>
      <QueryErrorAlert error={query.error} />
      {data && data.geo_enabled === false ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="GeoIP 数据源未加载，跨境识别已降级"
          description="当前看板展示的是历史观察数据，新流量不再产生跨境记录；请检查 GeoIP 数据源配置后刷新。"
        />
      ) : null}

      <Space style={{ marginBottom: 16 }} wrap size={16}>
        <Space size={8}>
          <Typography.Text type="secondary">本土地区判定基准：</Typography.Text>
          {(data?.home_regions ?? []).map((r) => (
            <Tag key={r} color="green">
              {r}
            </Tag>
          ))}
        </Space>
        <Radio.Group
          value={days}
          onChange={(e) => setDays(e.target.value as number)}
          options={[
            { value: 7, label: '7天' },
            { value: 14, label: '14天' },
            { value: 30, label: '30天' },
          ]}
          optionType="button"
          size="small"
        />
      </Space>

      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col flex="1 1 160px">
          <Card size="small">
            <Statistic title="跨境事件" value={summary?.total_events ?? 0} loading={query.isLoading} />
          </Card>
        </Col>
        <Col flex="1 1 160px">
          <Card size="small">
            <Statistic title="涉及国家/地区" value={summary?.country_count ?? 0} loading={query.isLoading} />
          </Card>
        </Col>
        <Col flex="1 1 160px">
          <Card size="small">
            <Statistic title="涉及 API" value={summary?.endpoint_count ?? 0} loading={query.isLoading} />
          </Card>
        </Col>
        <Col flex="1 1 160px">
          <Card size="small">
            <Statistic
              title="高风险事件"
              value={summary?.high_risk_count ?? 0}
              loading={query.isLoading}
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
      </Row>

      <Card size="small" title="趋势（按天）" style={{ marginBottom: 16 }}>
        <EChart option={trendOption(dashboard?.trend)} height={240} ariaLabel="跨境事件按天趋势" />
      </Card>

      <Card size="small" title="聚合" style={{ marginBottom: 16 }}>
        <Tabs
          size="small"
          items={[
            {
              key: 'country',
              label: '按国家/地区',
              children: (
                <SmartTable<ApiCrossBorderCountryStat>
                  storageKey="api-cross-border-by-country"
                  rowKey="country"
                  onRow={(record) => ({
                    onDoubleClick: () => {
                      setDetailTitle('国家/地区聚合详情')
                      setDetailRecord(record as unknown as Record<string, unknown>)
                    },
                    style: { cursor: 'pointer' },
                  })}
                  size="small"
                  columns={countryColumns}
                  dataSource={dashboard?.by_country ?? []}
                  pagination={false}
                />
              ),
            },
            {
              key: 'country-type',
              label: '国家×敏感类型',
              children: (
                <SmartTable<ApiCrossBorderCountryTypeStat>
                  storageKey="api-cross-border-by-country-type"
                  rowKey={(r) => `${r.country}-${r.data_type}`}
                  onRow={(record) => ({
                    onDoubleClick: () => {
                      setDetailTitle('国家×敏感类型聚合详情')
                      setDetailRecord(record as unknown as Record<string, unknown>)
                    },
                    style: { cursor: 'pointer' },
                  })}
                  size="small"
                  columns={countryTypeColumns}
                  dataSource={dashboard?.by_country_type ?? []}
                  pagination={false}
                />
              ),
            },
            {
              key: 'endpoint',
              label: '按 API',
              children: (
                <SmartTable<ApiCrossBorderEndpointStat>
                  storageKey="api-cross-border-by-endpoint"
                  rowKey="endpoint_key"
                  onRow={(record) => ({
                    onDoubleClick: () => {
                      setDetailTitle('API 聚合详情')
                      setDetailRecord(record as unknown as Record<string, unknown>)
                    },
                    style: { cursor: 'pointer' },
                  })}
                  size="small"
                  columns={endpointColumns}
                  dataSource={dashboard?.by_endpoint ?? []}
                  pagination={false}
                />
              ),
            },
          ]}
        />
      </Card>

      <Typography.Title level={5} style={{ marginTop: 0 }}>
        明细
      </Typography.Title>
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="国家码（两位，如 US）"
          allowClear
          style={{ width: 200 }}
          value={country}
          onChange={(e) => setCountry(e.target.value)}
          onSearch={(v) => {
            setAppliedCountry(v.trim().toUpperCase())
            setPage(1)
          }}
        />
        <Select
          placeholder="方向"
          allowClear
          style={{ width: 110 }}
          value={direction}
          options={Object.entries(DIRECTION_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setDirection(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="风险等级"
          allowClear
          style={{ width: 120 }}
          value={riskLevel}
          options={Object.entries(RISK_LEVEL_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setRiskLevel(v)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="API 键（精确匹配）"
          allowClear
          style={{ width: 300 }}
          value={endpointKey}
          onChange={(e) => setEndpointKey(e.target.value)}
          onSearch={(v) => {
            setAppliedEndpointKey(v.trim())
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiCrossBorderEvent>
        storageKey="api-cross-border-events"
        rowKey="id"
        onRow={(record) => ({
          onDoubleClick: () => {
            setDetailTitle('跨境事件详情')
            setDetailRecord(record as unknown as Record<string, unknown>)
          },
          style: { cursor: 'pointer' },
        })}
        loading={query.isLoading}
        columns={eventColumns}
        dataSource={data?.events.items ?? []}
        scroll={{ x: 1200 }}
        pagination={{
          current: page,
          pageSize,
          total: data?.events.total ?? 0,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
      />
      <RecordDetailDrawer
        open={detailRecord !== null}
        title={detailTitle}
        record={detailRecord}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
