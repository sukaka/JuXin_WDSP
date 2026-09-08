import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Card,
  Col,
  DatePicker,
  Input,
  Radio,
  Row,
  Space,
  Spin,
  Statistic,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apmApi } from '../../api/apm'
import ApmTraceDrawer from '../../components/ApmTraceDrawer'
import EChart from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { TREND_RANGE_OPTIONS } from '../../utils/stage6'
import { apmTrendOption } from '../../utils/apmCharts'
import {
  APM_TRACE_ID_PATTERN,
  formatMs,
  formatPercent,
  resolveApmTimeRange,
  type ApmRangeValue,
} from '../../utils/apm'
import type { ApmTopApplicationItem, ApmTopEndpointItem } from '../../types'

/** 数据来源角标（APM 设计 §17.2：任何图表都显示当前数据来源） */
const AGENTLESS_TAG = <Tag color="blue">无 Agent</Tag>

const TOP_APP_COLUMNS: ColumnsType<ApmTopApplicationItem> = [
  {
    title: '应用',
    key: 'app',
    ellipsis: true,
    render: (_, r) => (
      <>
        <div>{r.name || '-'}</div>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {r.app}
        </Typography.Text>
      </>
    ),
  },
  { title: '请求量', dataIndex: 'requests', width: 80 },
  {
    title: '错误率',
    dataIndex: 'error_rate',
    width: 90,
    render: (v: number) => (
      <Typography.Text type={v >= 0.05 ? 'danger' : undefined}>{formatPercent(v)}</Typography.Text>
    ),
  },
  { title: 'P95', dataIndex: 'p95', width: 90, render: (v: number) => formatMs(v) },
]

/** 业务性能总览：RED 指标卡 + 请求与错误趋势 + Top 列表 + trace 检索（30 秒自动刷新）；
 *  Trace 抽屉复用公共组件 ApmTraceDrawer（有 otel_spans 时自动升级为瀑布图） */
export default function ApmOverviewPage() {
  const { message } = AntdApp.useApp()
  const navigate = useNavigate()
  const permissions = useAuthStore((s) => s.user?.permissions)
  // trace 检索挂在 apm.traces.read 权限点上（接口合同），无权限不展示入口
  const canTraces = hasPermission(permissions, 'apm.traces.read')

  const [range, setRange] = useState('1h')
  const [customRange, setCustomRange] = useState<ApmRangeValue>(null)
  const [traceId, setTraceId] = useState<string | null>(null)

  const timeParams = useMemo(() => resolveApmTimeRange(range, customRange), [range, customRange])

  const overviewQuery = useQuery({
    queryKey: ['apm', 'overview', timeParams],
    queryFn: () => apmApi.overview(timeParams),
    refetchInterval: 30000,
  })

  const searchTrace = (value: string) => {
    const v = value.trim()
    if (!APM_TRACE_ID_PATTERN.test(v)) {
      message.warning('Trace ID 格式不正确（应为 32 位十六进制字符）')
      return
    }
    setTraceId(v.toLowerCase())
  }

  const data = overviewQuery.data

  return (
    <Card
      title="业务性能总览"
      extra={
        <Space>
          <Tag color="blue">数据来源：无 Agent</Tag>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            30 秒自动刷新
          </Typography.Text>
        </Space>
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Radio.Group
          value={range}
          onChange={(e) => setRange(String(e.target.value))}
          options={[...TREND_RANGE_OPTIONS, { value: 'custom', label: '自定义' }]}
          optionType="button"
          size="small"
        />
        {range === 'custom' && (
          <DatePicker.RangePicker
            showTime
            value={customRange}
            onChange={(v) => setCustomRange(v)}
            size="small"
          />
        )}
        {canTraces && (
          <Input.Search
            placeholder="Trace ID（32 位十六进制）"
            allowClear
            enterButton="检索"
            style={{ width: 360 }}
            onSearch={searchTrace}
          />
        )}
      </Space>

      {overviewQuery.isLoading ? (
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin />
        </div>
      ) : overviewQuery.isError ? (
        <QueryErrorAlert error={overviewQuery.error} message="加载业务性能总览失败" />
      ) : data ? (
        <Space direction="vertical" size={16} style={{ display: 'flex' }}>
          <Row gutter={[16, 16]}>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic title="请求量" value={data.requests_total} />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic
                  title="错误率"
                  value={formatPercent(data.error_rate)}
                  valueStyle={data.error_rate > 0 ? { color: '#cf1322' } : undefined}
                />
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  5xx {data.error_5xx_total} / 4xx {data.error_4xx_total}
                </Typography.Text>
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic title="P95 时延" value={formatMs(data.latency.p95)} />
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  P50 {formatMs(data.latency.p50)} / P99 {formatMs(data.latency.p99)}
                </Typography.Text>
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic title="阻断量" value={data.blocked_total} />
              </Card>
            </Col>
          </Row>

          {data.unclassified_requests > 0 && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              未归类请求 {data.unclassified_requests} 条（路径无法归一化，已计入「端点性能」页未归类端点桶，不污染单端点指标）
            </Typography.Text>
          )}

          <Card size="small" title="请求与错误趋势" extra={AGENTLESS_TAG}>
            <EChart option={apmTrendOption(data.trend ?? [])} height={300} ariaLabel="请求与错误趋势" />
          </Card>

          <Row gutter={[16, 16]}>
            <Col xs={24} lg={8}>
              <Card size="small" title="慢应用 TOP" extra={AGENTLESS_TAG}>
                <SmartTable<ApmTopApplicationItem>
                  storageKey="apm-overview-slow-apps"
                  size="small"
                  rowKey="application_id"
                  pagination={false}
                  dataSource={data.top_slow_applications ?? []}
                  locale={{ emptyText: '暂无数据' }}
                  columns={TOP_APP_COLUMNS}
                />
              </Card>
            </Col>
            <Col xs={24} lg={8}>
              <Card size="small" title="高错误应用 TOP" extra={AGENTLESS_TAG}>
                <SmartTable<ApmTopApplicationItem>
                  storageKey="apm-overview-error-apps"
                  size="small"
                  rowKey="application_id"
                  pagination={false}
                  dataSource={data.top_error_applications ?? []}
                  locale={{ emptyText: '暂无数据' }}
                  columns={TOP_APP_COLUMNS}
                />
              </Card>
            </Col>
            <Col xs={24} lg={8}>
              <Card size="small" title="慢端点 TOP" extra={AGENTLESS_TAG}>
                {data.access_log_enabled === false ? (
                  <Alert
                    type="warning"
                    showIcon
                    message="端点级数据需开启全量访问日志"
                    description="当前未开启全量访问日志（logging.access_log_enabled），端点级性能数据不可用；请联系系统管理员在日志配置中开启。应用级 RED 指标不受影响。"
                  />
                ) : (
                  <SmartTable<ApmTopEndpointItem>
                    storageKey="apm-overview-slow-endpoints"
                    size="small"
                    rowKey={(r) => `${r.app}-${r.endpoint}`}
                    pagination={false}
                    dataSource={data.top_slow_endpoints ?? []}
                    locale={{ emptyText: '暂无数据' }}
                    onRow={() => ({
                      onClick: () => navigate('/apm-endpoints'),
                      style: { cursor: 'pointer' },
                    })}
                    columns={[
                      {
                        title: '端点',
                        dataIndex: 'endpoint',
                        ellipsis: true,
                        render: (v: string) => (
                          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                            {v}
                          </Typography.Text>
                        ),
                      },
                      { title: '应用', dataIndex: 'app', width: 90, ellipsis: true },
                      { title: 'P95', dataIndex: 'p95', width: 90, render: (v: number) => formatMs(v) },
                    ]}
                  />
                )}
              </Card>
            </Col>
          </Row>
        </Space>
      ) : null}

      <ApmTraceDrawer traceId={traceId} onClose={() => setTraceId(null)} context={timeParams} />
    </Card>
  )
}
