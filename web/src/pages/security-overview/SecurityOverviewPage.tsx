import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Col, List, Radio, Row, Space, Statistic, Table, Tabs, Tag, Typography } from 'antd'
import dayjs from 'dayjs'
import { dashboardsApi } from '../../api/dashboards'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { ATTACK_TYPE_META, DISPOSITION_STATUS_META, EVENT_SEVERITY_META } from '../../utils/stage4'
import { COMPONENT_NAME_META, TREND_RANGE_OPTIONS } from '../../utils/stage6'
import type { KeyValue } from '../../types'

/** KV 排行小表 */
function KVTable({ items, nameTitle, nameMap }: { items: KeyValue[]; nameTitle: string; nameMap?: Record<string, { label: string }> }) {
  return (
    <Table
      size="small"
      rowKey="key"
      pagination={false}
      dataSource={items}
      locale={{ emptyText: '暂无数据' }}
      columns={[
        {
          title: nameTitle,
          dataIndex: 'key',
          ellipsis: true,
          render: (v: string) => nameMap?.[v]?.label ?? v,
        },
        { title: '数量', dataIndex: 'value', width: 90, align: 'right' },
      ]}
    />
  )
}

/** 安全总览：12 项今日指标 + 趋势 + 排行 + 风险区；审计视角附加处置统计 */
export default function SecurityOverviewPage() {
  const [range, setRange] = useState('24h')
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canReadAudit = hasPermission(permissions, 'dashboard.audit.read')

  const overviewQuery = useQuery({
    queryKey: ['dashboard', 'security-overview', range],
    queryFn: () => dashboardsApi.securityOverview(range),
  })

  const auditQuery = useQuery({
    queryKey: ['dashboard', 'audit-overview'],
    queryFn: () => dashboardsApi.auditOverview(),
    enabled: canReadAudit,
  })

  const data = overviewQuery.data
  const today = data?.today

  const cards: { title: string; value?: number; color?: string }[] = [
    { title: '今日请求总数', value: today?.requests_total },
    { title: '今日安全事件', value: today?.waf_events, color: '#fa8c16' },
    { title: '今日阻断', value: today?.waf_blocks, color: '#cf1322' },
    { title: '今日观察事件', value: today?.waf_observes },
    { title: '今日CC超限', value: today?.cc_exceeded, color: '#fa8c16' },
    { title: '今日黑名单命中', value: today?.ip_deny_matches, color: '#cf1322' },
    { title: '当前临时封禁IP', value: today?.temp_blocked_ips },
    { title: '未处置高危事件', value: today?.unprocessed_high_events, color: '#cf1322' },
    { title: '受保护应用数', value: today?.protected_apps },
    { title: '异常应用数', value: today?.abnormal_apps, color: '#fa8c16' },
    { title: '异常源站数', value: today?.abnormal_upstreams, color: '#fa8c16' },
    { title: '即将到期证书数', value: today?.expiring_certs, color: '#fa8c16' },
  ]

  const trends = data?.trends
  const timeLabels = useMemo(
    () => (trends?.times ?? []).map((t) => dayjs(t).format('MM-DD HH:mm')),
    [trends],
  )

  const requestOption = useMemo<EChartOption>(
    () => ({
      grid: { left: 48, right: 16, top: 32, bottom: 28 },
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: timeLabels, axisLabel: { hideOverlap: true } },
      yAxis: { type: 'value', minInterval: 1 },
      series: [
        {
          name: '请求总数',
          type: 'line',
          smooth: true,
          areaStyle: {},
          data: trends?.requests ?? [],
          itemStyle: { color: '#1677ff' },
        },
      ],
    }),
    [trends, timeLabels],
  )

  const securityOption = useMemo<EChartOption>(
    () => ({
      grid: { left: 48, right: 16, top: 40, bottom: 28 },
      tooltip: { trigger: 'axis' },
      legend: { data: ['安全事件', '阻断', '观察', 'CC超限', '黑名单命中'] },
      xAxis: { type: 'category', data: timeLabels, axisLabel: { hideOverlap: true } },
      yAxis: { type: 'value', minInterval: 1 },
      series: [
        { name: '安全事件', type: 'line', smooth: true, data: trends?.security_events ?? [] },
        { name: '阻断', type: 'line', smooth: true, data: trends?.blocks ?? [] },
        { name: '观察', type: 'line', smooth: true, data: trends?.observes ?? [] },
        { name: 'CC超限', type: 'line', smooth: true, data: trends?.cc_exceeded ?? [] },
        { name: '黑名单命中', type: 'line', smooth: true, data: trends?.ip_deny ?? [] },
      ],
    }),
    [trends, timeLabels],
  )

  const top = data?.top
  const risks = data?.risks
  const audit = auditQuery.data

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="安全总览"
        extra={
          <Radio.Group
            value={range}
            onChange={(e) => setRange(e.target.value as string)}
            options={TREND_RANGE_OPTIONS}
            optionType="button"
            size="small"
          />
        }
      >
        {overviewQuery.isError ? (
          <QueryErrorAlert error={overviewQuery.error} message="加载安全总览失败" />
        ) : (
          <Row gutter={[16, 16]}>
            {cards.map((c) => (
              <Col key={c.title} xs={12} sm={8} md={6} lg={4}>
                <Card size="small">
                  <Statistic
                    title={c.title}
                    value={c.value ?? 0}
                    loading={overviewQuery.isLoading}
                    valueStyle={c.color ? { color: c.color } : undefined}
                  />
                </Card>
              </Col>
            ))}
          </Row>
        )}
      </Card>

      {!overviewQuery.isError && (
        <>
          <Row gutter={16}>
            <Col xs={24} lg={12}>
              <Card size="small" title="请求趋势">
                <EChart option={requestOption} height={260} />
              </Card>
            </Col>
            <Col xs={24} lg={12}>
              <Card size="small" title="安全趋势">
                <EChart option={securityOption} height={260} />
              </Card>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col xs={24} lg={14}>
              <Card size="small" title="排行">
                <Tabs
                  items={[
                    {
                      key: 'attack_types',
                      label: '攻击类型',
                      children: <KVTable items={top?.attack_types ?? []} nameTitle="攻击类型" nameMap={ATTACK_TYPE_META} />,
                    },
                    {
                      key: 'source_ips',
                      label: '源IP',
                      children: (
                        <Table
                          size="small"
                          rowKey="ip"
                          pagination={false}
                          dataSource={top?.source_ips ?? []}
                          locale={{ emptyText: '暂无数据' }}
                          columns={[
                            { title: '源IP', dataIndex: 'ip', ellipsis: true },
                            { title: '事件数', dataIndex: 'events', width: 90, align: 'right' },
                            { title: '阻断数', dataIndex: 'blocks', width: 90, align: 'right' },
                          ]}
                        />
                      ),
                    },
                    {
                      key: 'applications',
                      label: '应用',
                      children: <KVTable items={top?.applications ?? []} nameTitle="应用" />,
                    },
                    {
                      key: 'rules',
                      label: '规则',
                      children: <KVTable items={top?.rules ?? []} nameTitle="规则ID" />,
                    },
                    {
                      key: 'uris',
                      label: 'URI',
                      children: (
                        <Table
                          size="small"
                          rowKey="path"
                          pagination={false}
                          dataSource={top?.uris ?? []}
                          locale={{ emptyText: '暂无数据' }}
                          columns={[
                            { title: 'URI', dataIndex: 'path', ellipsis: true },
                            { title: '事件数', dataIndex: 'events', width: 90, align: 'right' },
                            { title: '阻断数', dataIndex: 'blocks', width: 90, align: 'right' },
                          ]}
                        />
                      ),
                    },
                  ]}
                />
              </Card>
            </Col>
            <Col xs={24} lg={10}>
              <Card size="small" title="风险提示">
                <List size="small" locale={{ emptyText: '暂无风险提示' }}>
                  {(risks?.high_unprocessed_events ?? []).map((e) => (
                    <List.Item key={`event-${e.id}`}>
                      <Space direction="vertical" size={2}>
                        <Space>
                          <StatusTag value={e.severity} map={EVENT_SEVERITY_META} />
                          <Typography.Text strong>
                            {ATTACK_TYPE_META[e.attack_type]?.label ?? e.attack_type}
                          </Typography.Text>
                          <Typography.Text type="secondary">{e.client_ip}</Typography.Text>
                        </Space>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {e.application_name || '-'}｜{e.request_path}｜{formatDateTime(e.occurred_at)}
                        </Typography.Text>
                      </Space>
                    </List.Item>
                  ))}
                  {(risks?.failed_publish_tasks ?? []).map((p) => (
                    <List.Item key={`publish-${p.id}`}>
                      <Space direction="vertical" size={2}>
                        <Space>
                          <Tag color="volcano">发布失败</Tag>
                          <Typography.Text strong>配置发布任务 {p.id.slice(0, 8)}</Typography.Text>
                        </Space>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {p.failure_message || '未记录失败原因'}｜{formatDateTime(p.requested_at)}
                        </Typography.Text>
                      </Space>
                    </List.Item>
                  ))}
                  {(risks?.gateway_issues ?? []).map((g) => (
                    <List.Item key={`issue-${g.component}`}>
                      <Space direction="vertical" size={2}>
                        <Space>
                          <Tag color="red">组件异常</Tag>
                          <Typography.Text strong>
                            {COMPONENT_NAME_META[g.component] ?? g.component}
                          </Typography.Text>
                          <Tag>{g.status}</Tag>
                        </Space>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {g.message || '-'}｜{formatDateTime(g.taken_at)}
                        </Typography.Text>
                      </Space>
                    </List.Item>
                  ))}
                  {risks?.collector_lag && (risks.collector_lag.recent_job_failures > 0 || (risks.collector_lag.lag_seconds ?? 0) > 60) && (
                    <List.Item key="collector-lag">
                      <Space direction="vertical" size={2}>
                        <Space>
                          <Tag color="orange">采集积压</Tag>
                          <Typography.Text strong>事件采集/聚合异常</Typography.Text>
                        </Space>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          延迟 {risks.collector_lag.lag_seconds != null ? `${Math.round(risks.collector_lag.lag_seconds)} 秒` : '-'}
                          ｜24 小时内聚合失败 {risks.collector_lag.recent_job_failures} 次
                        </Typography.Text>
                      </Space>
                    </List.Item>
                  )}
                </List>
              </Card>
            </Col>
          </Row>
        </>
      )}

      {canReadAudit && (
        <Card size="small" title="审计态势（处置统计）">
          {auditQuery.isError ? (
            <QueryErrorAlert error={auditQuery.error} message="加载审计态势失败" />
          ) : (
            <>
              <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
                <Col xs={12} md={8}>
                  <Statistic title="今日处置事件" value={audit?.today_dispositions ?? 0} loading={auditQuery.isLoading} />
                </Col>
                <Col xs={12} md={8}>
                  <Statistic
                    title="未处置事件（全部）"
                    value={audit?.unprocessed_events ?? 0}
                    loading={auditQuery.isLoading}
                    valueStyle={{ color: '#cf1322' }}
                  />
                </Col>
                <Col xs={12} md={8}>
                  <Statistic title="今日审计记录" value={audit?.today_audits ?? 0} loading={auditQuery.isLoading} />
                </Col>
              </Row>
              <Row gutter={16}>
                <Col xs={24} md={12}>
                  <Typography.Text type="secondary">处置状态分布</Typography.Text>
                  <Table
                    size="small"
                    rowKey="status"
                    pagination={false}
                    dataSource={audit?.disposition_distribution ?? []}
                    locale={{ emptyText: '暂无数据' }}
                    columns={[
                      {
                        title: '处置状态',
                        dataIndex: 'status',
                        render: (v: string) => <StatusTag value={v} map={DISPOSITION_STATUS_META} />,
                      },
                      { title: '数量', dataIndex: 'count', width: 90, align: 'right' },
                    ]}
                  />
                </Col>
                <Col xs={24} md={12}>
                  <Typography.Text type="secondary">今日操作类型 TOP</Typography.Text>
                  <Table
                    size="small"
                    rowKey="action"
                    pagination={false}
                    dataSource={audit?.action_stats ?? []}
                    locale={{ emptyText: '暂无数据' }}
                    columns={[
                      { title: '操作', dataIndex: 'action', ellipsis: true },
                      { title: '数量', dataIndex: 'count', width: 90, align: 'right' },
                    ]}
                  />
                </Col>
              </Row>
            </>
          )}
        </Card>
      )}
    </Space>
  )
}
