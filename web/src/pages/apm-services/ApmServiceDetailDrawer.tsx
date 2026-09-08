import { Alert, Card, Col, Descriptions, Drawer, Row, Space, Spin, Statistic, Table, Tag, Typography } from 'antd'
import { useQuery } from '@tanstack/react-query'
import { apmApi } from '../../api/apm'
import type { ApmTimeRangeParams } from '../../api/apm'
import EChart from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { APM_WAF_ACTION_META, formatMs, formatPercent } from '../../utils/apm'
import { apmKvPieOption, apmTrendOption } from '../../utils/apmCharts'
import type { ApmServiceDetail } from '../../types'

/** 服务详情抽屉：RED 趋势 + 状态码分布 + WAF 动作分布 + Top 端点（全部来自无 Agent 管道） */
export default function ApmServiceDetailDrawer({
  serviceId,
  timeParams,
  onClose,
}: {
  serviceId: string | null
  timeParams: ApmTimeRangeParams
  onClose: () => void
}) {
  const detailQuery = useQuery({
    queryKey: ['apm', 'service', serviceId, timeParams],
    queryFn: () => apmApi.service(serviceId as string, timeParams),
    enabled: serviceId !== null,
  })

  const detail: ApmServiceDetail | undefined = detailQuery.data

  return (
    <Drawer title="服务性能详情" open={serviceId !== null} onClose={onClose} width={860}>
      {detailQuery.isLoading ? (
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin />
        </div>
      ) : detailQuery.isError ? (
        <QueryErrorAlert error={detailQuery.error} message="加载服务性能详情失败" />
      ) : detail ? (
        <Space direction="vertical" size={16} style={{ display: 'flex' }}>
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="应用名称">{detail.name || '-'}</Descriptions.Item>
            <Descriptions.Item label="应用编码">{detail.app || '-'}</Descriptions.Item>
            <Descriptions.Item label="观测模式">
              <Tag color="blue">无 Agent</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="数据来源">网关访问日志与分钟聚合</Descriptions.Item>
          </Descriptions>

          <Row gutter={[16, 16]}>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic title="请求量" value={detail.requests_total} />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic
                  title="错误率"
                  value={formatPercent(detail.error_rate)}
                  valueStyle={detail.error_rate > 0 ? { color: '#cf1322' } : undefined}
                />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic title="P95 时延" value={formatMs(detail.latency.p95)} />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic
                  title="P50 / P99"
                  value={`${formatMs(detail.latency.p50)} / ${formatMs(detail.latency.p99)}`}
                  valueStyle={{ fontSize: 20 }}
                />
              </Card>
            </Col>
          </Row>

          <Card size="small" title="请求与错误趋势" extra={<Tag color="blue">无 Agent</Tag>}>
            <EChart option={apmTrendOption(detail.trend ?? [])} height={280} ariaLabel="请求与错误趋势" />
          </Card>

          <Row gutter={[16, 16]}>
            <Col xs={24} md={12}>
              <Card size="small" title="状态码分布" extra={<Tag color="blue">无 Agent</Tag>}>
                <EChart
                  option={apmKvPieOption(
                    (detail.status_classes ?? []).map((s) => ({ name: s.status_class, value: s.count })),
                  )}
                  height={260}
                  ariaLabel="状态码分布"
                />
              </Card>
            </Col>
            <Col xs={24} md={12}>
              <Card size="small" title="WAF 动作分布" extra={<Tag color="blue">无 Agent</Tag>}>
                <EChart
                  option={apmKvPieOption(
                    (detail.actions ?? []).map((a) => ({
                      name: APM_WAF_ACTION_META[a.action]?.label ?? a.action,
                      value: a.count,
                    })),
                  )}
                  height={260}
                  ariaLabel="WAF 动作分布"
                />
              </Card>
            </Col>
          </Row>

          <Card size="small" title="Top 端点" extra={<Tag color="blue">无 Agent</Tag>}>
            {(detail.top_endpoints ?? []).length === 0 ? (
              <Alert
                type="info"
                showIcon
                message="无端点级数据"
                description="端点级数据依赖全量访问日志（logging.access_log_enabled），未开启或无流量时为空。"
              />
            ) : (
              <Table
                size="small"
                rowKey="endpoint"
                pagination={false}
                dataSource={detail.top_endpoints}
                columns={[
                  {
                    title: '端点',
                    dataIndex: 'endpoint',
                    ellipsis: true,
                    render: (v: string) => (
                      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Typography.Text>
                    ),
                  },
                  { title: '请求量', dataIndex: 'requests', width: 100 },
                  {
                    title: '错误率',
                    dataIndex: 'error_rate',
                    width: 100,
                    render: (v: number) => formatPercent(v),
                  },
                  { title: 'P95', dataIndex: 'p95', width: 100, render: (v: number) => formatMs(v) },
                ]}
              />
            )}
          </Card>
        </Space>
      ) : null}
    </Drawer>
  )
}
