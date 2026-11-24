import { useContext, useMemo, useState } from 'react'
import { useInRouterContext, useNavigate } from 'react-router-dom'
import { QueryClientContext, useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  Col,
  Empty,
  Progress,
  Row,
  Segmented,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { FundProjectionScreenOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { systemHealthApi } from '../../api/systemHealth'
import EChart, { type EChartOption } from '../../components/EChart'
import { useAuthStore } from '../../stores/auth'
import { formatBytesPerSecond, pickBandwidthScale } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type {
  GatewayTCPStates,
  GatewayTrendApplication,
  GatewayTrendPoint,
  GatewayTrendRange,
  GatewayTrendResponse,
  GatewayTrendSource,
  RuntimeComponent,
} from '../../types'

const DEFAULT_SESSION_CAPACITY = 10000

const BYPASS_REASONS: Record<string, string> = {
  CPU_THRESHOLD: 'CPU 超过阈值',
  MEMORY_THRESHOLD: '内存超过阈值',
  CPU_AND_MEMORY_THRESHOLD: 'CPU 与内存超过阈值',
  MIN_HOLD_OR_SAMPLE_UNAVAILABLE: '最短保持期内或采样暂不可用',
}

const RANGE_OPTIONS: { label: string; value: GatewayTrendRange }[] = [
  { label: '实时 10 分钟', value: '10m' },
  { label: '近 1 小时', value: '1h' },
  { label: '近 6 小时', value: '6h' },
  { label: '近 24 小时', value: '24h' },
]

const SOURCE_META: Record<GatewayTrendSource, { label: string; color: string }> = {
  gateway_live: { label: '实时 2s 采样', color: 'cyan' },
  database: { label: '历史 30s 采样', color: 'blue' },
  database_fallback: { label: '历史降级 30s 采样', color: 'gold' },
}

const TCP_STATE_ROWS: { key: keyof GatewayTCPStates; label: string; color: string }[] = [
  { key: 'established', label: 'ESTABLISHED（已建立）', color: '#52c41a' },
  { key: 'time_wait', label: 'TIME_WAIT（等待关闭）', color: '#1677ff' },
  { key: 'close_wait', label: 'CLOSE_WAIT（待应用关闭）', color: '#fa8c16' },
  { key: 'syn_recv', label: 'SYN_RECV（半连接）', color: '#faad14' },
  { key: 'fin_wait', label: 'FIN_WAIT（主动关闭）', color: '#722ed1' },
  { key: 'listen', label: 'LISTEN（监听）', color: '#13c2c2' },
  { key: 'other', label: 'OTHER（其他）', color: '#8c8c8c' },
]

function numberMetric(component: RuntimeComponent, key: string): number | undefined {
  const value = component.metrics?.[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function booleanMetric(component: RuntimeComponent, key: string): boolean {
  return component.metrics?.[key] === true
}

function stringMetric(component: RuntimeComponent, key: string): string | undefined {
  const value = component.metrics?.[key]
  return typeof value === 'string' && value !== '' ? value : undefined
}

function parseTcpStates(raw: unknown): GatewayTCPStates | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  const read = (k: string) => (typeof r[k] === 'number' && Number.isFinite(r[k]) ? (r[k] as number) : 0)
  return {
    established: read('established'),
    time_wait: read('time_wait'),
    close_wait: read('close_wait'),
    syn_recv: read('syn_recv'),
    fin_wait: read('fin_wait'),
    listen: read('listen'),
    other: read('other'),
  }
}

function parseApplications(raw: unknown): GatewayTrendApplication[] {
  if (!Array.isArray(raw)) return []
  return raw
    .filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object')
    .map((item) => ({
      app_id: String(item.app_id ?? ''),
      app_code: typeof item.app_code === 'string' ? item.app_code : undefined,
      app_name: typeof item.app_name === 'string' ? item.app_name : undefined,
      requests_in_flight: Number(item.requests_in_flight ?? 0) || 0,
      requests_total: Number(item.requests_total ?? 0) || 0,
      requests_per_second: Number(item.requests_per_second ?? 0) || 0,
      bypassed_requests_total: Number(item.bypassed_requests_total ?? 0) || 0,
      bytes_in_total: Number(item.bytes_in_total ?? 0) || 0,
      bytes_out_total: Number(item.bytes_out_total ?? 0) || 0,
      bytes_in_per_second: Number(item.bytes_in_per_second ?? 0) || 0,
      bytes_out_per_second: Number(item.bytes_out_per_second ?? 0) || 0,
      status_4xx_total: Number(item.status_4xx_total ?? 0) || 0,
      status_5xx_total: Number(item.status_5xx_total ?? 0) || 0,
    }))
    .filter((item) => item.app_id !== '')
}

function decimal(value: number | null | undefined, digits = 1): string {
  return value === undefined || value === null || !Number.isFinite(value) ? '-' : value.toFixed(digits)
}

function formatTimeAxis(takenAt: string, range: GatewayTrendRange): string {
  const d = dayjs(takenAt)
  if (!d.isValid()) return takenAt
  if (range === '10m') return d.format('HH:mm:ss')
  if (range === '24h') return d.format('MM-DD HH:mm')
  return d.format('HH:mm')
}

function RouterBigScreenButton() {
  const navigate = useNavigate()
  return (
    <Button
      size="small"
      type="primary"
      ghost
      icon={<FundProjectionScreenOutlined />}
      onClick={() => navigate('/big-screen/gateway-connections')}
    >
      进入大屏监控
    </Button>
  )
}

function BigScreenEntryButton() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const inRouter = useInRouterContext()
  if (!hasPermission(permissions, 'big_screen.runtime.read')) return null
  if (inRouter) return <RouterBigScreenButton />
  return (
    <Button
      size="small"
      type="primary"
      ghost
      icon={<FundProjectionScreenOutlined />}
      href="/big-screen/gateway-connections"
    >
      进入大屏监控
    </Button>
  )
}

const APP_COLUMNS: ColumnsType<GatewayTrendApplication> = [
  {
    title: '应用',
    dataIndex: 'app_name',
    key: 'app',
    ellipsis: true,
    render: (_, row) => (
      <Space size={4}>
        <Typography.Text strong>{row.app_name || row.app_code || row.app_id}</Typography.Text>
        {row.app_code && row.app_name && row.app_code !== row.app_name && (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            ({row.app_code})
          </Typography.Text>
        )}
      </Space>
    ),
  },
  {
    title: '实时 QPS',
    dataIndex: 'requests_per_second',
    key: 'qps',
    width: 100,
    align: 'right',
    render: (v: number) => `${decimal(v, 2)} /s`,
  },
  {
    title: '在途请求',
    dataIndex: 'requests_in_flight',
    key: 'in_flight',
    width: 90,
    align: 'right',
  },
  {
    title: '累计请求',
    dataIndex: 'requests_total',
    key: 'total',
    width: 105,
    align: 'right',
    render: (v: number) => v.toLocaleString(),
  },
  {
    title: '入站速率',
    dataIndex: 'bytes_in_per_second',
    key: 'bps_in',
    width: 110,
    align: 'right',
    render: (v: number) => formatBytesPerSecond(v),
  },
  {
    title: '出站速率',
    dataIndex: 'bytes_out_per_second',
    key: 'bps_out',
    width: 110,
    align: 'right',
    render: (v: number) => formatBytesPerSecond(v),
  },
  {
    title: '4xx / 5xx',
    key: 'errors',
    width: 115,
    align: 'right',
    render: (_, row) => (
      <Space size={4}>
        <Tag color={row.status_4xx_total > 0 ? 'orange' : 'default'} style={{ marginInlineEnd: 0 }}>
          {row.status_4xx_total}
        </Tag>
        <Tag color={row.status_5xx_total > 0 ? 'red' : 'default'} style={{ marginInlineEnd: 0 }}>
          {row.status_5xx_total}
        </Tag>
      </Space>
    ),
  },
  {
    title: '旁路透传',
    dataIndex: 'bypassed_requests_total',
    key: 'bypassed',
    width: 95,
    align: 'right',
    render: (v: number) => (v > 0 ? <Tag color="red">{v}</Tag> : 0),
  },
]

interface GatewayTrafficCardViewProps {
  gateway: RuntimeComponent
  range: GatewayTrendRange
  onRangeChange: (next: GatewayTrendRange) => void
  trend?: GatewayTrendResponse
  trendLoading?: boolean
  trendError?: boolean
}

function buildTrendCharts(
  points: GatewayTrendPoint[],
  range: GatewayTrendRange,
  cpuThreshold: number | undefined,
  memoryThreshold: number | undefined,
): {
  tcpOption: EChartOption
  sessionQpsOption: EChartOption
  bandwidthOption: EChartOption
  bandwidthUnit: string
  resourceOption: EChartOption
} {
  const times = points.map((p) => formatTimeAxis(p.taken_at, range))

  const tcpOption: EChartOption = {
    tooltip: { trigger: 'axis' },
    legend: { top: 0 },
    grid: { left: 48, right: 52, top: 34, bottom: 26 },
    xAxis: { type: 'category', boundaryGap: false, data: times },
    yAxis: [
      { type: 'value', name: '并发连接', minInterval: 1 },
      { type: 'value', name: '新建/秒', splitLine: { show: false } },
    ],
    series: [
      {
        name: '并发连接',
        type: 'line',
        yAxisIndex: 0,
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#1677ff' },
        areaStyle: { opacity: 0.16 },
        data: points.map((p) => p.tcp_connections_active),
      },
      {
        name: '新建连接/秒',
        type: 'line',
        yAxisIndex: 1,
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#13c2c2' },
        data: points.map((p) => Number(p.tcp_connections_accepted_per_second.toFixed(2))),
      },
    ],
  }

  const sessionQpsOption: EChartOption = {
    tooltip: { trigger: 'axis' },
    legend: { top: 0 },
    grid: { left: 48, right: 52, top: 34, bottom: 26 },
    xAxis: { type: 'category', boundaryGap: false, data: times },
    yAxis: [
      { type: 'value', name: '活跃会话', minInterval: 1 },
      { type: 'value', name: '速率(/s)', splitLine: { show: false } },
    ],
    series: [
      {
        name: '活跃会话',
        type: 'line',
        yAxisIndex: 0,
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#722ed1' },
        areaStyle: { opacity: 0.14 },
        data: points.map((p) => p.http_sessions_active),
      },
      {
        name: '实时 QPS',
        type: 'line',
        yAxisIndex: 1,
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#52c41a' },
        data: points.map((p) => Number(p.http_requests_per_second.toFixed(2))),
      },
      {
        name: '新建会话/秒',
        type: 'line',
        yAxisIndex: 1,
        smooth: true,
        showSymbol: false,
        lineStyle: { type: 'dashed' },
        itemStyle: { color: '#fa8c16' },
        data: points.map((p) => Number(p.http_sessions_new_per_second.toFixed(2))),
      },
    ],
  }

  const maxBps = points.reduce(
    (max, p) => Math.max(max, p.bytes_in_per_second, p.bytes_out_per_second),
    0,
  )
  const { unit: bandwidthUnit, divisor } = pickBandwidthScale(maxBps)

  const bandwidthOption: EChartOption = {
    tooltip: { trigger: 'axis' },
    legend: { top: 0 },
    grid: { left: 54, right: 20, top: 34, bottom: 26 },
    xAxis: { type: 'category', boundaryGap: false, data: times },
    yAxis: { type: 'value', name: bandwidthUnit },
    series: [
      {
        name: `入站 (${bandwidthUnit})`,
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#1677ff' },
        areaStyle: { opacity: 0.16 },
        data: points.map((p) => Number((p.bytes_in_per_second / divisor).toFixed(2))),
      },
      {
        name: `出站 (${bandwidthUnit})`,
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#52c41a' },
        areaStyle: { opacity: 0.14 },
        data: points.map((p) => Number((p.bytes_out_per_second / divisor).toFixed(2))),
      },
    ],
  }

  const cpuMarkLines =
    cpuThreshold !== undefined
      ? [
          {
            yAxis: cpuThreshold,
            name: `CPU 旁路阈值`,
            lineStyle: { type: 'dashed' as const, color: '#ff4d4f' },
            label: { formatter: `CPU 阈值 ${cpuThreshold}%`, color: '#ff4d4f' },
          },
        ]
      : []

  const memMarkLines =
    memoryThreshold !== undefined
      ? [
          {
            yAxis: memoryThreshold,
            name: `内存 旁路阈值`,
            lineStyle: { type: 'dashed' as const, color: '#fa8c16' },
            label: { formatter: `内存 阈值 ${memoryThreshold}%`, color: '#fa8c16' },
          },
        ]
      : []

  const resourceOption: EChartOption = {
    tooltip: { trigger: 'axis' },
    legend: { top: 0 },
    grid: { left: 48, right: 28, top: 34, bottom: 26 },
    xAxis: { type: 'category', boundaryGap: false, data: times },
    yAxis: { type: 'value', name: '%', min: 0, max: 100 },
    series: [
      {
        name: 'CPU %',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#1677ff' },
        data: points.map((p) => (p.cpu_percent != null ? Number(p.cpu_percent.toFixed(1)) : null)),
        markLine: cpuMarkLines.length > 0 ? { silent: true, symbol: 'none', data: cpuMarkLines } : undefined,
      },
      {
        name: '内存 %',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#faad14' },
        data: points.map((p) => (p.memory_percent != null ? Number(p.memory_percent.toFixed(1)) : null)),
        markLine: memMarkLines.length > 0 ? { silent: true, symbol: 'none', data: memMarkLines } : undefined,
      },
      {
        name: 'FD %',
        type: 'line',
        smooth: true,
        showSymbol: false,
        itemStyle: { color: '#722ed1' },
        data: points.map((p) =>
          p.fd_usage_percent != null ? Number(p.fd_usage_percent.toFixed(1)) : null,
        ),
      },
    ],
  }

  return { tcpOption, sessionQpsOption, bandwidthOption, bandwidthUnit, resourceOption }
}

function GatewayTrafficCardView({
  gateway,
  range,
  onRangeChange,
  trend,
  trendLoading = false,
  trendError = false,
}: GatewayTrafficCardViewProps) {
  const current = trend?.current ?? null
  const bypass = current?.software_bypass ?? null

  const enabled = bypass ? bypass.enabled : booleanMetric(gateway, 'software_bypass_enabled')
  const active = bypass ? bypass.active : booleanMetric(gateway, 'software_bypass_active')
  const reason = bypass?.reason || stringMetric(gateway, 'software_bypass_reason')
  const cpuThreshold =
    bypass?.cpu_threshold_percent ?? numberMetric(gateway, 'software_bypass_cpu_threshold_percent')
  const memoryThreshold =
    bypass?.memory_threshold_percent ??
    numberMetric(gateway, 'software_bypass_memory_threshold_percent')
  const sampleError = current?.resource_sample_error || stringMetric(gateway, 'resource_sample_error')

  const cpuPercent =
    current?.cpu_percent ??
    numberMetric(gateway, 'cpu_usage_percent') ??
    numberMetric(gateway, 'cpu_percent')
  const memoryPercent =
    current?.memory_percent ??
    numberMetric(gateway, 'memory_usage_percent') ??
    numberMetric(gateway, 'memory_percent')
  const tcpActive = current?.tcp_connections_active ?? numberMetric(gateway, 'tcp_connections_active')
  const tcpAcceptedPerSec =
    current?.tcp_connections_accepted_per_second ??
    numberMetric(gateway, 'tcp_connections_accepted_per_second')
  const tcpAcceptedTotal =
    current?.tcp_connections_accepted_total ??
    numberMetric(gateway, 'tcp_connections_accepted_total')
  const sessionsActive = current?.http_sessions_active ?? numberMetric(gateway, 'http_sessions_active')
  const sessionsNewTotal =
    current?.http_sessions_new_total ?? numberMetric(gateway, 'http_sessions_new_total')
  const sessionsNewPerSec =
    current?.http_sessions_new_per_second ?? numberMetric(gateway, 'http_sessions_new_per_second')
  const sessionOverflow =
    current?.http_sessions_overflow_total ??
    numberMetric(gateway, 'http_sessions_overflow_total') ??
    0
  const sessionCapacity =
    current?.http_sessions_capacity ??
    numberMetric(gateway, 'http_sessions_capacity') ??
    DEFAULT_SESSION_CAPACITY
  const httpInFlight =
    current?.http_requests_in_flight ?? numberMetric(gateway, 'http_requests_in_flight')
  const httpQps =
    current?.http_requests_per_second ?? numberMetric(gateway, 'http_requests_per_second')
  const bytesInPerSec =
    current?.bytes_in_per_second ?? numberMetric(gateway, 'bytes_in_per_second')
  const bytesOutPerSec =
    current?.bytes_out_per_second ?? numberMetric(gateway, 'bytes_out_per_second')
  const load1 = current?.load1 ?? numberMetric(gateway, 'load1')
  const load5 = current?.load5 ?? numberMetric(gateway, 'load5')
  const load15 = current?.load15 ?? numberMetric(gateway, 'load15')
  const fdOpen = current?.fd_open ?? numberMetric(gateway, 'fd_open') ?? numberMetric(gateway, 'fd_open_files')
  const fdMax = current?.fd_max ?? numberMetric(gateway, 'fd_max') ?? numberMetric(gateway, 'fd_max_open_files')
  const fdUsagePercent =
    current?.fd_usage_percent ?? numberMetric(gateway, 'fd_usage_percent')

  const tcpStates = current?.tcp_states ?? parseTcpStates(gateway.metrics?.tcp_states)
  const applications = useMemo(() => {
    if (trend?.applications && trend.applications.length > 0) return trend.applications
    return parseApplications(gateway.metrics?.applications)
  }, [trend?.applications, gateway.metrics?.applications])

  const statusBreakdown = useMemo(() => {
    const s2 = current?.status_2xx_total ?? numberMetric(gateway, 'status_2xx_total') ?? 0
    const s3 = current?.status_3xx_total ?? numberMetric(gateway, 'status_3xx_total') ?? 0
    const s4 = current?.status_4xx_total ?? numberMetric(gateway, 'status_4xx_total') ?? 0
    const s5 = current?.status_5xx_total ?? numberMetric(gateway, 'status_5xx_total') ?? 0
    const r2 = current?.status_2xx_per_second ?? numberMetric(gateway, 'status_2xx_per_second')
    const r3 = current?.status_3xx_per_second ?? numberMetric(gateway, 'status_3xx_per_second')
    const r4 = current?.status_4xx_per_second ?? numberMetric(gateway, 'status_4xx_per_second')
    const r5 = current?.status_5xx_per_second ?? numberMetric(gateway, 'status_5xx_per_second')
    const total = s2 + s3 + s4 + s5
    return {
      total,
      rows: [
        { code: '2xx 成功', total: s2, rate: r2, color: '#52c41a', tagColor: 'green' },
        { code: '3xx 重定向', total: s3, rate: r3, color: '#1677ff', tagColor: 'blue' },
        { code: '4xx 客户端错误', total: s4, rate: r4, color: '#fa8c16', tagColor: 'orange' },
        { code: '5xx 服务端错误', total: s5, rate: r5, color: '#ff4d4f', tagColor: 'red' },
      ],
    }
  }, [current, gateway])

  const points = useMemo(() => trend?.points ?? [], [trend?.points])
  const charts = useMemo(
    () => buildTrendCharts(points, range, cpuThreshold, memoryThreshold),
    [points, range, cpuThreshold, memoryThreshold],
  )

  const tcpStateTotal = useMemo(() => {
    if (!tcpStates) return 0
    return TCP_STATE_ROWS.reduce((sum, item) => sum + (tcpStates[item.key] ?? 0), 0)
  }, [tcpStates])

  const loadDisplay =
    load1 !== undefined || load5 !== undefined || load15 !== undefined
      ? `${decimal(load1, 2)} / ${decimal(load5, 2)} / ${decimal(load15, 2)}`
      : '-'

  const sourceMeta = trend?.source ? SOURCE_META[trend.source] : undefined
  const summary = trend?.summary

  return (
    <Card
      title="网关流量与软件旁路"
      extra={
        <Space wrap size={8}>
          {sourceMeta && <Tag color={sourceMeta.color}>{sourceMeta.label}</Tag>}
          <Tag color={active ? 'red' : enabled ? 'blue' : 'default'}>
            {active ? '旁路中（未检测）' : enabled ? '自动旁路已启用' : '自动旁路未启用'}
          </Tag>
          <BigScreenEntryButton />
        </Space>
      }
    >
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        {active && (
          <Alert
            type="warning"
            showIcon
            message={`当前为纯透传${reason ? `：${BYPASS_REASONS[reason] ?? reason}` : ''}`}
            description="访问控制、CC、Bot、API 动态防护与 WAF 均已跳过；请求 ID、安全响应头和源站反向代理仍保留。"
          />
        )}
        {sampleError && (
          <Alert
            type="error"
            showIcon
            message="部分系统资源采样不可用"
            description={sampleError}
          />
        )}
        {sessionOverflow > 0 && (
          <Alert
            type="warning"
            showIcon
            message={`会话跟踪已达到 ${sessionCapacity} 条容量上限`}
            description={`溢出次数：${sessionOverflow}；连接与请求计数不受影响。`}
          />
        )}
        {trendError && (
          <Alert
            type="info"
            showIcon
            message="趋势数据暂不可用，已自动降级为当前快照指标展示"
          />
        )}

        <Row gutter={[16, 16]}>
          <Col xs={12} md={6} lg={3}>
            <Statistic title="CPU 使用率" value={decimal(cpuPercent)} suffix="%" />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic title="内存使用率" value={decimal(memoryPercent)} suffix="%" />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic title="当前 TCP 连接" value={tcpActive ?? '-'} />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic title="新建连接/秒" value={decimal(tcpAcceptedPerSec, 2)} />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic title="累计新建连接" value={tcpAcceptedTotal ?? '-'} />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic title="活跃 HTTP 会话" value={sessionsActive ?? '-'} />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic title="累计新建会话" value={sessionsNewTotal ?? '-'} />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic title="在途 HTTP 请求" value={httpInFlight ?? '-'} />
          </Col>
        </Row>

        <Row gutter={[16, 16]}>
          <Col xs={12} md={8} lg={4}>
            <Statistic title="实时 QPS" value={decimal(httpQps, 2)} suffix="/s" />
          </Col>
          <Col xs={12} md={8} lg={4}>
            <Statistic title="新建会话/秒" value={decimal(sessionsNewPerSec, 2)} suffix="/s" />
          </Col>
          <Col xs={12} md={8} lg={4}>
            <Statistic title="入站带宽" value={formatBytesPerSecond(bytesInPerSec)} />
          </Col>
          <Col xs={12} md={8} lg={4}>
            <Statistic title="出站带宽" value={formatBytesPerSecond(bytesOutPerSec)} />
          </Col>
          <Col xs={12} md={8} lg={4}>
            <Statistic title="系统负载 (1/5/15m)" value={loadDisplay} />
          </Col>
          <Col xs={12} md={8} lg={4}>
            <Statistic
              title={
                fdOpen !== undefined && fdMax !== undefined
                  ? `FD 占用率 (${fdOpen}/${fdMax})`
                  : 'FD 占用率'
              }
              value={decimal(fdUsagePercent, 1)}
              suffix="%"
            />
          </Col>
        </Row>

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            paddingTop: 4,
            borderTop: '1px solid #f0f0f0',
          }}
        >
          <Segmented
            value={range}
            options={RANGE_OPTIONS}
            onChange={(value) => onRangeChange(value as GatewayTrendRange)}
          />
          {summary && (
            <Space wrap size={12}>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                峰值连接：{summary.peak_tcp_connections_active}（均值{' '}
                {summary.avg_tcp_connections_active.toFixed(1)}）
              </Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                峰值会话：{summary.peak_http_sessions_active}
              </Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                峰值 QPS：{summary.peak_http_requests_per_second.toFixed(2)}
              </Typography.Text>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                峰值入/出站：{formatBytesPerSecond(summary.peak_bytes_in_per_second)} /{' '}
                {formatBytesPerSecond(summary.peak_bytes_out_per_second)}
              </Typography.Text>
            </Space>
          )}
        </div>

        {points.length > 0 ? (
          <Row gutter={[16, 16]}>
            <Col xs={24} lg={12}>
              <Card size="small" title="TCP 并发连接与新建连接/秒">
                <EChart
                  option={charts.tcpOption}
                  height={230}
                  ariaLabel="TCP 并发连接与新建连接速率趋势图"
                />
              </Card>
            </Col>
            <Col xs={24} lg={12}>
              <Card size="small" title="活跃 HTTP 会话、新建会话/秒与实时 QPS">
                <EChart
                  option={charts.sessionQpsOption}
                  height={230}
                  ariaLabel="活跃 HTTP 会话、新建会话速率与实时 QPS 趋势图"
                />
              </Card>
            </Col>
            <Col xs={24} lg={12}>
              <Card size="small" title={`实时进出站带宽吞吐（${charts.bandwidthUnit}）`}>
                <EChart
                  option={charts.bandwidthOption}
                  height={230}
                  ariaLabel="实时进出站带宽吞吐趋势图"
                />
              </Card>
            </Col>
            <Col xs={24} lg={12}>
              <Card size="small" title="网关资源水位与旁路阈值">
                <EChart
                  option={charts.resourceOption}
                  height={230}
                  ariaLabel="网关 CPU、内存与文件句柄水位趋势图"
                />
              </Card>
            </Col>
          </Row>
        ) : (
          !trendError && (
            <Card size="small" loading={trendLoading}>
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="暂无当前时间窗口的历史趋势采样点，系统持续采集中"
              />
            </Card>
          )
        )}

        <Row gutter={[16, 16]}>
          <Col xs={24} md={12}>
            <Card size="small" title="TCP 连接状态分布">
              {tcpStates ? (
                <Space direction="vertical" size={8} style={{ display: 'flex' }}>
                  {TCP_STATE_ROWS.map((item) => {
                    const count = tcpStates[item.key] ?? 0
                    const percent = tcpStateTotal > 0 ? Number(((count / tcpStateTotal) * 100).toFixed(1)) : 0
                    return (
                      <div key={item.key}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                          <span>{item.label}</span>
                          <span>
                            {count.toLocaleString()} ({percent}%)
                          </span>
                        </div>
                        <Progress
                          percent={percent}
                          showInfo={false}
                          size="small"
                          strokeColor={item.color}
                        />
                      </div>
                    )
                  })}
                </Space>
              ) : (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  当前平台未提供 TCP 状态细分（仅 Linux 节点采集）
                </Typography.Text>
              )}
            </Card>
          </Col>
          <Col xs={24} md={12}>
            <Card size="small" title="HTTP 状态码分布（2xx/3xx/4xx/5xx）">
              <Space direction="vertical" size={10} style={{ display: 'flex' }}>
                {statusBreakdown.rows.map((row) => {
                  const percent =
                    statusBreakdown.total > 0
                      ? Number(((row.total / statusBreakdown.total) * 100).toFixed(1))
                      : 0
                  return (
                    <div key={row.code}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                        <Space size={6}>
                          <Tag color={row.tagColor} style={{ marginInlineEnd: 0 }}>
                            {row.code}
                          </Tag>
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            {decimal(row.rate, 2)} /s
                          </Typography.Text>
                        </Space>
                        <span>
                          {row.total.toLocaleString()} ({percent}%)
                        </span>
                      </div>
                      <Progress
                        percent={percent}
                        showInfo={false}
                        size="small"
                        strokeColor={row.color}
                      />
                    </div>
                  )
                })}
              </Space>
            </Card>
          </Col>
          <Col xs={24}>
            <Card size="small" title="应用实时负载 TOP">
              <Table<GatewayTrendApplication>
                size="small"
                rowKey="app_id"
                pagination={false}
                columns={APP_COLUMNS}
                dataSource={applications.slice(0, 10)}
                locale={{ emptyText: '暂无按应用实时负载明细' }}
                scroll={{ x: 760 }}
              />
            </Card>
          </Col>
        </Row>

        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          触发条件：CPU &gt; {cpuThreshold ?? '-'}% 或内存 &gt; {memoryThreshold ?? '-'}%；
          恢复阈值为触发值减 5 个百分点。会话按应用与配置的 Cookie 去重，常态统计，5
          分钟空闲后不计为活跃；无会话 Cookie 的请求不计入会话数。
        </Typography.Text>
      </Space>
    </Card>
  )
}

function GatewayTrafficCardWithQuery({ gateway }: { gateway: RuntimeComponent }) {
  const [range, setRange] = useState<GatewayTrendRange>('10m')
  const refetchInterval = range === '10m' ? 5000 : 30000

  const trendQuery = useQuery({
    queryKey: ['system-health', 'gateway-trend', range],
    queryFn: () => systemHealthApi.gatewayTrend(range),
    refetchInterval,
  })

  return (
    <GatewayTrafficCardView
      gateway={gateway}
      range={range}
      onRangeChange={setRange}
      trend={trendQuery.data}
      trendLoading={trendQuery.isLoading}
      trendError={trendQuery.isError}
    />
  )
}

function GatewayTrafficCardStandalone({ gateway }: { gateway: RuntimeComponent }) {
  const [range, setRange] = useState<GatewayTrendRange>('10m')
  return <GatewayTrafficCardView gateway={gateway} range={range} onRangeChange={setRange} />
}

export default function GatewayTrafficCard({ gateway }: { gateway: RuntimeComponent }) {
  const queryClient = useContext(QueryClientContext)
  const hasRuntimeMetrics =
    gateway.metrics?.software_bypass_enabled !== undefined ||
    numberMetric(gateway, 'tcp_connections_active') !== undefined
  if (!hasRuntimeMetrics) return null

  if (!queryClient) {
    return <GatewayTrafficCardStandalone gateway={gateway} />
  }
  return <GatewayTrafficCardWithQuery gateway={gateway} />
}
