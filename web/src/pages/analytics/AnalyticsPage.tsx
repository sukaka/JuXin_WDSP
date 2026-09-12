import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Col, DatePicker, Radio, Row, Select, Space, Statistic, Tabs } from 'antd'
import SmartTable from '../../components/SmartTable'
import dayjs from 'dayjs'
import type { Dayjs } from 'dayjs'
import { analyticsApi } from '../../api/analytics'
import type { AnalyticsParams } from '../../api/analytics'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { hasAnyPermission, hasPermission } from '../../utils/permission'
import { ATTACK_TYPE_META, DISPOSITION_STATUS_META, EVENT_SEVERITY_META } from '../../utils/stage4'
import { CLIENT_IP_SOURCE_META } from '../../utils/stage5'
import { TREND_RANGE_OPTIONS } from '../../utils/stage6'
import type { CountPoint, KeyValue } from '../../types'

type RangeValue = [Dayjs | null, Dayjs | null] | null

function metaLabel(map: Record<string, { label: string }>, name: string): string {
  return map[name]?.label ?? name
}

function kvBarOption(items: KeyValue[], map?: Record<string, { label: string }>, color = '#1677ff'): EChartOption {
  return {
    grid: { left: 48, right: 16, top: 24, bottom: 60 },
    tooltip: {},
    xAxis: {
      type: 'category',
      data: items.map((i) => (map ? metaLabel(map, i.key) : i.key)),
      axisLabel: { rotate: items.length > 5 ? 30 : 0, hideOverlap: true },
    },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ type: 'bar', data: items.map((i) => i.value), itemStyle: { color }, barMaxWidth: 40 }],
  }
}

function kvPieOption(items: KeyValue[], map: Record<string, { label: string }>): EChartOption {
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0 },
    series: [
      {
        type: 'pie',
        radius: ['35%', '65%'],
        center: ['50%', '45%'],
        data: items.map((i) => ({ name: metaLabel(map, i.key), value: i.value })),
        label: { formatter: '{b}: {c}' },
      },
    ],
  }
}

function trendLineOption(points: CountPoint[], name: string, color: string): EChartOption {
  return {
    grid: { left: 48, right: 16, top: 24, bottom: 28 },
    tooltip: { trigger: 'axis' },
    xAxis: {
      type: 'category',
      data: points.map((p) => dayjs(p.time).format('MM-DD HH:mm')),
      axisLabel: { hideOverlap: true },
    },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ name, type: 'line', smooth: true, areaStyle: {}, data: points.map((p) => p.count), itemStyle: { color } }],
  }
}

const EMPTY_KV: KeyValue[] = []

/** 统计分析：请求/WAF/风险/攻击类型/CC/访问控制/处置 多视角分析 */
export default function AnalyticsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canSecurity = hasPermission(permissions, 'analytics.security.read')
  const canDisposition = hasPermission(permissions, 'analytics.disposition.read')

  const [range, setRange] = useState('24h')
  const [customRange, setCustomRange] = useState<RangeValue>(null)
  const [applicationId, setApplicationId] = useState<string | undefined>()
  // 审计管理员（仅有处置权限）默认落在处置 Tab
  const [activeTab, setActiveTab] = useState(canSecurity ? 'requests' : 'disposition')

  const params: AnalyticsParams = useMemo(() => {
    const p: AnalyticsParams = { application_id: applicationId }
    if (range === 'custom' && customRange?.[0] && customRange?.[1]) {
      p.start_time = customRange[0].toISOString()
      p.end_time = customRange[1].toISOString()
    } else {
      p.range = range === 'custom' ? '24h' : range
    }
    return p
  }, [range, customRange, applicationId])

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-analytics'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    // 应用列表非关键控件，无权限时静默降级为「全部应用」
    retry: false,
  })

  const requestTrendQuery = useQuery({
    queryKey: ['analytics', 'request-trend', params],
    queryFn: () => analyticsApi.requestTrend(params),
    enabled: activeTab === 'requests' && canSecurity,
  })
  const eventTrendQuery = useQuery({
    queryKey: ['analytics', 'security-event-trend', params],
    queryFn: () => analyticsApi.securityEventTrend(params),
    enabled: activeTab === 'waf' && canSecurity,
  })
  const riskLevelsQuery = useQuery({
    queryKey: ['analytics', 'risk-levels', params],
    queryFn: () => analyticsApi.riskLevels(params),
    enabled: activeTab === 'risk' && canSecurity,
  })
  const attackTypesQuery = useQuery({
    queryKey: ['analytics', 'attack-types', params],
    queryFn: () => analyticsApi.attackTypes(params),
    enabled: activeTab === 'attack' && canSecurity,
  })
  const ccQuery = useQuery({
    queryKey: ['analytics', 'cc-overview', params],
    queryFn: () => analyticsApi.ccOverview(params),
    enabled: activeTab === 'cc' && canSecurity,
  })
  const acQuery = useQuery({
    queryKey: ['analytics', 'access-control-overview', params],
    queryFn: () => analyticsApi.accessControlOverview(params),
    enabled: activeTab === 'access' && canSecurity,
  })
  const dispositionQuery = useQuery({
    queryKey: ['analytics', 'disposition-overview', params],
    queryFn: () => analyticsApi.dispositionOverview(params),
    enabled: activeTab === 'disposition' && canDisposition,
  })

  const requestOption = useMemo<EChartOption>(() => {
    const data = requestTrendQuery.data
    const times = (data?.times ?? []).map((t) => dayjs(t).format('MM-DD HH:mm'))
    const series = data?.series ?? {}
    return {
      grid: { left: 56, right: 56, top: 40, bottom: 28 },
      tooltip: { trigger: 'axis' },
      legend: { data: ['请求量', 'P50', 'P95', 'P99'], top: 0 },
      xAxis: { type: 'category', data: times, axisLabel: { hideOverlap: true } },
      yAxis: [
        { type: 'value', name: '请求量', minInterval: 1 },
        { type: 'value', name: '毫秒' },
      ],
      series: [
        { name: '请求量', type: 'bar', data: series.requests ?? [], itemStyle: { color: '#91caff' }, barMaxWidth: 24 },
        { name: 'P50', type: 'line', yAxisIndex: 1, smooth: true, data: series.p50_ms ?? [] },
        { name: 'P95', type: 'line', yAxisIndex: 1, smooth: true, data: series.p95_ms ?? [] },
        { name: 'P99', type: 'line', yAxisIndex: 1, smooth: true, data: series.p99_ms ?? [] },
      ],
    }
  }, [requestTrendQuery.data])

  const methodDistOption = useMemo<EChartOption>(
    () => kvBarOption(requestTrendQuery.data?.method_distribution ?? EMPTY_KV, undefined, '#1677ff'),
    [requestTrendQuery.data],
  )

  const contentTypeDistOption = useMemo<EChartOption>(
    () => kvBarOption(requestTrendQuery.data?.content_type_distribution ?? EMPTY_KV, undefined, '#722ed1'),
    [requestTrendQuery.data],
  )

  const clientIPSourceDistOption = useMemo<EChartOption>(
    () => kvBarOption(requestTrendQuery.data?.client_ip_source_distribution ?? EMPTY_KV, CLIENT_IP_SOURCE_META, '#13c2c2'),
    [requestTrendQuery.data],
  )

  const trustedProxyDistOption = useMemo<EChartOption>(
    () => kvBarOption(requestTrendQuery.data?.trusted_proxy_distribution ?? EMPTY_KV, undefined, '#fa8c16'),
    [requestTrendQuery.data],
  )

  const eventTrendOption = useMemo<EChartOption>(() => {
    const data = eventTrendQuery.data
    const times = (data?.times ?? []).map((t) => dayjs(t).format('MM-DD HH:mm'))
    const series = data?.series ?? {}
    return {
      grid: { left: 48, right: 16, top: 40, bottom: 28 },
      tooltip: { trigger: 'axis' },
      legend: { data: ['安全事件', '阻断', '观察'], top: 0 },
      xAxis: { type: 'category', data: times, axisLabel: { hideOverlap: true } },
      yAxis: { type: 'value', minInterval: 1 },
      series: [
        { name: '安全事件', type: 'line', smooth: true, data: series.events ?? [], itemStyle: { color: '#f5222d' } },
        { name: '阻断', type: 'line', smooth: true, data: series.blocks ?? [] },
        { name: '观察', type: 'line', smooth: true, data: series.observes ?? [] },
      ],
    }
  }, [eventTrendQuery.data])

  const cc = ccQuery.data
  const ac = acQuery.data
  const disp = dispositionQuery.data
  const dispUnprocessed = (disp?.status_distribution ?? []).find((s) => s.status === 'UNPROCESSED')?.count ?? 0
  const dispAvgMinutes = disp ? Math.round((disp.avg_disposition_seconds / 60) * 10) / 10 : 0

  const tabItems = [
    ...(canSecurity
      ? [
          {
            key: 'requests',
            label: '请求趋势',
            children: requestTrendQuery.isError ? (
              <QueryErrorAlert error={requestTrendQuery.error} message="加载请求趋势失败" />
            ) : (
              <Space direction="vertical" size={16} style={{ display: 'flex' }}>
                <EChart option={requestOption} height={360} ariaLabel="请求趋势" />
                <Row gutter={16}>
                  <Col xs={24} md={12}>
                    <Card size="small" title="请求方法分布">
                      <EChart option={methodDistOption} height={280} ariaLabel="请求方法分布" />
                    </Card>
                  </Col>
                  <Col xs={24} md={12}>
                    <Card size="small" title="Content-Type 分布">
                      <EChart option={contentTypeDistOption} height={280} ariaLabel="Content-Type 分布" />
                    </Card>
                  </Col>
                </Row>
                <Row gutter={16}>
                  <Col xs={24} md={12}>
                    <Card size="small" title="客户端 IP 来源分布">
                      <EChart option={clientIPSourceDistOption} height={280} ariaLabel="客户端 IP 来源分布" />
                    </Card>
                  </Col>
                  <Col xs={24} md={12}>
                    <Card size="small" title="可信代理来源分布">
                      <EChart option={trustedProxyDistOption} height={280} ariaLabel="可信代理来源分布" />
                    </Card>
                  </Col>
                </Row>
              </Space>
            ),
          },
          {
            key: 'waf',
            label: '防护趋势',
            children: eventTrendQuery.isError ? (
              <QueryErrorAlert error={eventTrendQuery.error} message="加载防护趋势失败" />
            ) : (
              <EChart option={eventTrendOption} height={360} ariaLabel="防护趋势（安全事件与处置动作）" />
            ),
          },
          {
            key: 'risk',
            label: '风险等级',
            children: riskLevelsQuery.isError ? (
              <QueryErrorAlert error={riskLevelsQuery.error} message="加载风险等级失败" />
            ) : (
              <EChart option={kvPieOption(riskLevelsQuery.data ?? EMPTY_KV, EVENT_SEVERITY_META)} height={360} ariaLabel="风险等级分布" />
            ),
          },
          {
            key: 'attack',
            label: '攻击类型',
            children: attackTypesQuery.isError ? (
              <QueryErrorAlert error={attackTypesQuery.error} message="加载攻击类型失败" />
            ) : (
              <EChart option={kvBarOption(attackTypesQuery.data ?? EMPTY_KV, ATTACK_TYPE_META, '#f5222d')} height={360} ariaLabel="攻击类型分布" />
            ),
          },
          {
            key: 'cc',
            label: '频率防护概览',
            children: ccQuery.isError ? (
              <QueryErrorAlert error={ccQuery.error} message="加载频率防护概览失败" />
            ) : (
              <Space direction="vertical" size={16} style={{ display: 'flex' }}>
                <Row gutter={16}>
                  <Col span={6}>
                    <Card size="small"><Statistic title="频率触发次数" value={cc?.threshold_exceeded ?? 0} /></Card>
                  </Col>
                  <Col span={6}>
                    <Card size="small"><Statistic title="拒绝请求(429)" value={cc?.requests_rejected ?? 0} valueStyle={{ color: '#cf1322' }} /></Card>
                  </Col>
                  <Col span={6}>
                    <Card size="small"><Statistic title="新增临时封禁" value={cc?.temp_blocks_created ?? 0} /></Card>
                  </Col>
                  <Col span={6}>
                    <Card size="small"><Statistic title="到期/解除封禁" value={(cc?.temp_blocks_expired ?? 0) + (cc?.temp_blocks_released ?? 0)} valueStyle={{ color: '#3f8600' }} /></Card>
                  </Col>
                </Row>
                <Card size="small" title="临时封禁趋势">
                  <EChart option={trendLineOption(cc?.temp_block_trend ?? [], '临时封禁', '#fa8c16')} height={260} ariaLabel="临时封禁趋势" />
                </Card>
              </Space>
            ),
          },
          {
            key: 'access',
            label: '访问控制',
            children: acQuery.isError ? (
              <QueryErrorAlert error={acQuery.error} message="加载访问控制概览失败" />
            ) : (
              <Space direction="vertical" size={16} style={{ display: 'flex' }}>
                <Row gutter={16}>
                  <Col span={6}>
                    <Card size="small"><Statistic title="白名单命中" value={ac?.allow_matches ?? 0} valueStyle={{ color: '#3f8600' }} /></Card>
                  </Col>
                  <Col span={6}>
                    <Card size="small"><Statistic title="黑名单命中" value={ac?.deny_matches ?? 0} valueStyle={{ color: '#cf1322' }} /></Card>
                  </Col>
                  <Col span={6}>
                    <Card size="small"><Statistic title="当前封禁中" value={ac?.active_temp_blocks ?? 0} /></Card>
                  </Col>
                  <Col span={6}>
                    <Card size="small"><Statistic title="规则命中条目" value={(ac?.rule_hits ?? []).length} /></Card>
                  </Col>
                </Row>
                <Card size="small" title="规则命中 TOP">
                  <SmartTable
                    storageKey="analytics"
                    size="small"
                    rowKey={(r) => `${r.rule_id}-${r.event_type}`}
                    pagination={false}
                    dataSource={ac?.rule_hits ?? []}
                    locale={{ emptyText: '暂无数据' }}
                    columns={[
                      { title: '规则', dataIndex: 'rule_id', width: 220, ellipsis: true },
                      { title: '事件类型', dataIndex: 'event_type', width: 200, ellipsis: true },
                      { title: '命中次数', dataIndex: 'hits', width: 100 },
                    ]}
                  />
                </Card>
              </Space>
            ),
          },
        ]
      : []),
    ...(canDisposition
      ? [
          {
            key: 'disposition',
            label: '处置统计',
            children: dispositionQuery.isError ? (
              <QueryErrorAlert error={dispositionQuery.error} message="加载处置统计失败" />
            ) : (
              <Space direction="vertical" size={16} style={{ display: 'flex' }}>
                <Row gutter={16}>
                  <Col span={8}>
                    <Card size="small"><Statistic title="未处置事件" value={dispUnprocessed} valueStyle={{ color: '#cf1322' }} /></Card>
                  </Col>
                  <Col span={8}>
                    <Card size="small"><Statistic title="平均处置时长（分钟）" value={dispAvgMinutes} /></Card>
                  </Col>
                  <Col span={8}>
                    <Card size="small"><Statistic title="参与处置人数" value={(disp?.handlers ?? []).length} /></Card>
                  </Col>
                </Row>
                <Row gutter={16}>
                  <Col xs={24} md={12}>
                    <Card size="small" title="处置状态分布">
                      <SmartTable
                        storageKey="analytics-2"
                        size="small"
                        rowKey="status"
                        pagination={false}
                        dataSource={disp?.status_distribution ?? []}
                        locale={{ emptyText: '暂无数据' }}
                        columns={[
                          {
                            title: '状态',
                            dataIndex: 'status',
                            render: (v: string) => <StatusTag value={v} map={DISPOSITION_STATUS_META} />,
                          },
                          { title: '数量', dataIndex: 'count', width: 90 },
                        ]}
                      />
                    </Card>
                  </Col>
                  <Col xs={24} md={12}>
                    <Card size="small" title="处置人 TOP">
                      <SmartTable
                        storageKey="analytics-3"
                        size="small"
                        rowKey="username"
                        pagination={false}
                        dataSource={disp?.handlers ?? []}
                        locale={{ emptyText: '暂无数据' }}
                        columns={[
                          { title: '处置人', dataIndex: 'username', ellipsis: true },
                          { title: '处置数', dataIndex: 'count', width: 90 },
                        ]}
                      />
                    </Card>
                  </Col>
                </Row>
              </Space>
            ),
          },
        ]
      : []),
  ]

  return (
    <Card title="统计分析">
      <Space style={{ marginBottom: 16 }} wrap>
        <Radio.Group
          value={range}
          onChange={(e) => setRange(e.target.value as string)}
          options={[...TREND_RANGE_OPTIONS, { value: 'custom', label: '自定义' }]}
          optionType="button"
          size="small"
        />
        {range === 'custom' && (
          <DatePicker.RangePicker
            showTime
            value={customRange}
            onChange={(v) => setCustomRange(v)}
            presets={[
              { label: '最近24小时', value: [dayjs().subtract(24, 'hour'), dayjs()] },
              { label: '最近7天', value: [dayjs().subtract(7, 'day'), dayjs()] },
              { label: '最近30天', value: [dayjs().subtract(30, 'day'), dayjs()] },
            ]}
          />
        )}
        <Select
          placeholder="全部应用"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 220 }}
          loading={appsQuery.isLoading}
          options={(appsQuery.data?.items ?? []).map((a) => ({ value: a.id, label: `${a.name}（${a.code}）` }))}
          onChange={(v) => setApplicationId(v)}
        />
      </Space>
      {hasAnyPermission(permissions, ['analytics.security.read', 'analytics.disposition.read']) ? (
        <Tabs activeKey={activeTab} onChange={setActiveTab} items={tabItems} />
      ) : (
        <QueryErrorAlert error={new ApiError('无权限', 'PERMISSION_DENIED', 403)} />
      )}
    </Card>
  )
}
