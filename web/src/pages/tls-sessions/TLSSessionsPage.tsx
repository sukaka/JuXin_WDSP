import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  Col,
  DatePicker,
  Descriptions,
  Drawer,
  Empty,
  Input,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs, { type Dayjs } from 'dayjs'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import {
  tlsSessionsApi,
  type TLSSessionListParams,
} from '../../api/tlsSessions'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type { TLSSessionItem } from '../../types'

type RangeValue = [Dayjs | null, Dayjs | null] | null

type Filters = Omit<TLSSessionListParams, 'page' | 'page_size'>

const PROTOCOL_OPTIONS = [
  'TLCP1.1',
  'TLS1.3',
  'TLS1.2',
  'TLS1.1',
  'TLS1.0',
  'SSLv3',
  'SSLv2/v3',
  'SSLv2',
  'UNKNOWN',
].map((p) => ({ value: p, label: p }))

const ACTION_META: Record<string, { color: string; label: string }> = {
  ALLOWED: { color: 'green', label: '允许放行' },
  BLOCKED_LEGACY_SSL: { color: 'red', label: '弱 SSL 拦截' },
  BLOCKED_PROTOCOL_POLICY: { color: 'orange', label: '协议策略拦截' },
  HANDSHAKE_FAILED: { color: 'magenta', label: '握手失败' },
}

const ACTION_OPTIONS = Object.entries(ACTION_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

const GM_FILTER_OPTIONS: { value: 'true' | 'false'; label: string }[] = [
  { value: 'true', label: '仅国密 TLCP' },
  { value: 'false', label: '仅国际 TLS' },
]

function protocolTagColor(protocol: string): string {
  if (protocol === 'TLCP1.1') return 'volcano'
  if (protocol === 'SSLv2' || protocol === 'SSLv2/v3' || protocol === 'SSLv3') {
    return 'red'
  }
  if (protocol === 'TLS1.0' || protocol === 'TLS1.1') return 'orange'
  if (protocol === 'TLS1.3') return 'green'
  if (protocol === 'TLS1.2') return 'blue'
  return 'default'
}

function defaultTimeRange(): Filters {
  return {
    start_time: dayjs().subtract(24, 'hour').toISOString(),
    end_time: dayjs().toISOString(),
  }
}

export default function TLSSessionsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canReadApps = hasPermission(permissions, 'applications.read')

  const [filters, setFilters] = useState<Filters>(defaultTimeRange)
  const [sniDraft, setSniDraft] = useState('')
  const [clientIpDraft, setClientIpDraft] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<TLSSessionItem | null>(null)

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'tls-session-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: canReadApps,
  })

  const summaryQuery = useQuery({
    queryKey: [
      'tls-sessions-summary',
      filters.start_time,
      filters.end_time,
      filters.application_id,
    ],
    queryFn: () =>
      tlsSessionsApi.summary({
        start_time: filters.start_time,
        end_time: filters.end_time,
        application_id: filters.application_id,
      }),
  })

  const listQuery = useQuery({
    queryKey: ['tls-sessions', filters, page, pageSize],
    queryFn: () => tlsSessionsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const setFilter = (patch: Partial<Filters>) => {
    setFilters((prev) => ({ ...prev, ...patch }))
    setPage(1)
  }

  const resetFilters = () => {
    setFilters(defaultTimeRange())
    setSniDraft('')
    setClientIpDraft('')
    setPage(1)
  }

  const onRangeChange = (range: RangeValue) => {
    setFilter({
      start_time: range?.[0]?.toISOString(),
      end_time: range?.[1]?.toISOString(),
    })
  }

  const summary = summaryQuery.data
  const totalForPercent = Math.max(summary?.total_handshakes ?? 0, 1)

  const columns: ColumnsType<TLSSessionItem> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: 'SNI / 目标站点',
      dataIndex: 'sni',
      width: 190,
      ellipsis: true,
      render: (v: string) => (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {v || '-'}
        </Typography.Text>
      ),
    },
    {
      title: '客户端地址',
      key: 'client',
      width: 165,
      render: (_, r) => (
        <span style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {r.client_ip || '-'}
          {r.client_port ? `:${r.client_port}` : ''}
        </span>
      ),
    },
    {
      title: '检测协议',
      dataIndex: 'detected_protocol',
      width: 115,
      render: (v: string) => (
        <Tag color={protocolTagColor(v)}>{v || 'UNKNOWN'}</Tag>
      ),
    },
    {
      title: '协商协议',
      dataIndex: 'negotiated_protocol',
      width: 115,
      render: (v: string) =>
        v ? <Tag color={protocolTagColor(v)}>{v}</Tag> : <Typography.Text type="secondary">-</Typography.Text>,
    },
    {
      title: '协议族',
      dataIndex: 'is_gm',
      width: 90,
      render: (isGm: boolean) =>
        isGm ? <Tag color="volcano">国密</Tag> : <Tag color="blue">国际</Tag>,
    },
    {
      title: '算法套件',
      dataIndex: 'cipher_suite',
      width: 240,
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Tooltip title={v}>
            <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {v}
            </Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '处置动作',
      dataIndex: 'action',
      width: 130,
      render: (v: string) => {
        const meta = ACTION_META[v]
        return meta ? <Tag color={meta.color}>{meta.label}</Tag> : <Tag>{v || '-'}</Tag>
      },
    },
    {
      title: '网关节点',
      dataIndex: 'gateway_node_id',
      width: 120,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          onClick={(e) => {
            e.stopPropagation()
            setSelected(record)
          }}
        >
          详情
        </Button>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card title="SSL/HTTPS 加密会话分析">
        <Space style={{ marginBottom: 16 }} wrap>
          <DatePicker.RangePicker
            showTime
            allowClear={false}
            value={
              filters.start_time && filters.end_time
                ? [dayjs(filters.start_time), dayjs(filters.end_time)]
                : null
            }
            onChange={onRangeChange}
          />
          {canReadApps && (
            <Select
              aria-label="应用"
              placeholder="全部应用"
              allowClear
              showSearch
              optionFilterProp="label"
              style={{ width: 190 }}
              value={filters.application_id}
              loading={applicationsQuery.isLoading}
              options={(applicationsQuery.data?.items ?? []).map((app) => ({
                value: app.id,
                label: `${app.name} (${app.code})`,
              }))}
              onChange={(v) => setFilter({ application_id: v || undefined })}
            />
          )}
          <Select
            aria-label="协议版本"
            placeholder="协议版本"
            allowClear
            style={{ width: 135 }}
            value={filters.detected_protocol}
            options={PROTOCOL_OPTIONS}
            onChange={(v) => setFilter({ detected_protocol: v || undefined })}
          />
          <Select
            aria-label="国密/国际"
            placeholder="国密 / 国际"
            allowClear
            style={{ width: 135 }}
            value={filters.is_gm}
            options={GM_FILTER_OPTIONS}
            onChange={(v: 'true' | 'false' | undefined) =>
              setFilter({ is_gm: v })
            }
          />
          <Select
            aria-label="处置动作"
            placeholder="处置动作"
            allowClear
            style={{ width: 150 }}
            value={filters.action}
            options={ACTION_OPTIONS}
            onChange={(v) => setFilter({ action: v || undefined })}
          />
          <Input.Search
            placeholder="SNI 域名"
            allowClear
            style={{ width: 180 }}
            value={sniDraft}
            onChange={(e) => setSniDraft(e.target.value)}
            onSearch={(v) => setFilter({ sni: v.trim() || undefined })}
          />
          <Input.Search
            placeholder="客户端 IP"
            allowClear
            style={{ width: 150 }}
            value={clientIpDraft}
            onChange={(e) => setClientIpDraft(e.target.value)}
            onSearch={(v) => setFilter({ client_ip: v.trim() || undefined })}
          />
          <Button onClick={resetFilters}>重置筛选</Button>
        </Space>

        {canReadApps && (
          <QueryErrorAlert
            error={applicationsQuery.error}
            message="加载应用列表失败"
          />
        )}
        <QueryErrorAlert
          error={summaryQuery.error}
          message="加载加密会话统计摘要失败"
        />

        {/* KPI 指标卡 */}
        <Row gutter={[12, 12]} style={{ marginBottom: 16 }}>
          <Col xs={12} sm={8} lg={4}>
            <Card size="small">
              <Statistic
                title="总握手数"
                value={summary?.total_handshakes ?? 0}
                loading={summaryQuery.isLoading}
              />
            </Card>
          </Col>
          <Col xs={12} sm={8} lg={4}>
            <Card size="small">
              <Statistic
                title="国密 TLCP 会话"
                value={summary?.gm_count ?? 0}
                loading={summaryQuery.isLoading}
                valueStyle={{ color: '#d4380d' }}
              />
            </Card>
          </Col>
          <Col xs={12} sm={8} lg={4}>
            <Card size="small">
              <Statistic
                title="国际 TLS 会话"
                value={summary?.intl_count ?? 0}
                loading={summaryQuery.isLoading}
                valueStyle={{ color: '#2f54eb' }}
              />
            </Card>
          </Col>
          <Col xs={12} sm={8} lg={4}>
            <Card size="small">
              <Statistic
                title="弱协议 SSLv2/v3 拦截"
                value={summary?.legacy_ssl_blocked_count ?? 0}
                loading={summaryQuery.isLoading}
                valueStyle={
                  (summary?.legacy_ssl_blocked_count ?? 0) > 0
                    ? { color: '#cf1322' }
                    : undefined
                }
              />
            </Card>
          </Col>
          <Col xs={12} sm={8} lg={4}>
            <Card size="small">
              <Statistic
                title="协议策略拦截"
                value={summary?.policy_blocked_count ?? 0}
                loading={summaryQuery.isLoading}
                valueStyle={
                  (summary?.policy_blocked_count ?? 0) > 0
                    ? { color: '#d46b08' }
                    : undefined
                }
              />
            </Card>
          </Col>
          <Col xs={12} sm={8} lg={4}>
            <Card size="small">
              <Statistic
                title="握手失败"
                value={summary?.handshake_failed_count ?? 0}
                loading={summaryQuery.isLoading}
              />
            </Card>
          </Col>
        </Row>

        {/* 协议分布 & 算法套件明细 */}
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col xs={24} lg={12}>
            <Card size="small" title="协议版本分布">
              {(summary?.by_protocol ?? []).length === 0 ? (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="当前时间窗口暂无协议握手数据"
                />
              ) : (
                <Space direction="vertical" size={10} style={{ display: 'flex' }}>
                  {(summary?.by_protocol ?? []).map((item) => {
                    const pct = Math.round((item.count / totalForPercent) * 100)
                    return (
                      <div key={item.protocol}>
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            marginBottom: 4,
                          }}
                        >
                          <Space size={6}>
                            <Tag
                              color={protocolTagColor(item.protocol)}
                              style={{ cursor: 'pointer', marginInlineEnd: 0 }}
                              onClick={() =>
                                setFilter({ detected_protocol: item.protocol })
                              }
                            >
                              {item.protocol}
                            </Tag>
                            {item.is_gm && (
                              <Tag color="volcano" style={{ marginInlineEnd: 0 }}>
                                国密
                              </Tag>
                            )}
                            {item.is_legacy && (
                              <Tag color="red" style={{ marginInlineEnd: 0 }}>
                                弱协议
                              </Tag>
                            )}
                          </Space>
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            {item.count} 次（{pct}%）
                          </Typography.Text>
                        </div>
                        <Progress
                          percent={pct}
                          size="small"
                          showInfo={false}
                          strokeColor={
                            item.is_legacy
                              ? '#cf1322'
                              : item.is_gm
                                ? '#d4380d'
                                : '#2f54eb'
                          }
                        />
                      </div>
                    )
                  })}
                </Space>
              )}
            </Card>
          </Col>
          <Col xs={24} lg={12}>
            <Card size="small" title="协商算法套件分布">
              {(summary?.by_cipher_suite ?? []).length === 0 ? (
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="当前时间窗口暂无算法套件数据"
                />
              ) : (
                <Space direction="vertical" size={10} style={{ display: 'flex' }}>
                  {(summary?.by_cipher_suite ?? []).slice(0, 8).map((item) => {
                    const pct = Math.round((item.count / totalForPercent) * 100)
                    return (
                      <div key={item.cipher_suite}>
                        <div
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            gap: 8,
                            marginBottom: 4,
                          }}
                        >
                          <Space size={6} style={{ minWidth: 0 }}>
                            <Typography.Text
                              ellipsis={{ tooltip: item.cipher_suite }}
                              style={{
                                fontFamily: 'monospace',
                                fontSize: 12,
                                maxWidth: 320,
                              }}
                            >
                              {item.cipher_suite}
                            </Typography.Text>
                            {item.is_gm && (
                              <Tag color="volcano" style={{ marginInlineEnd: 0 }}>
                                国密
                              </Tag>
                            )}
                          </Space>
                          <Typography.Text
                            type="secondary"
                            style={{ fontSize: 12, flexShrink: 0 }}
                          >
                            {item.count} 次（{pct}%）
                          </Typography.Text>
                        </div>
                        <Progress
                          percent={pct}
                          size="small"
                          showInfo={false}
                          strokeColor={item.is_gm ? '#d4380d' : '#1677ff'}
                        />
                      </div>
                    )
                  })}
                </Space>
              )}
            </Card>
          </Col>
        </Row>

        {listQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载加密会话记录失败"
            description={
              listQuery.error instanceof ApiError
                ? listQuery.error.message
                : undefined
            }
          />
        ) : (
          <SmartTable<TLSSessionItem>
            storageKey="tls-sessions"
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            scroll={{ x: 1460 }}
            onRow={(record) => ({
              onClick: () => setSelected(record),
              style: { cursor: 'pointer' },
            })}
            pagination={{
              current: page,
              pageSize,
              total: listQuery.data?.total ?? 0,
              showSizeChanger: true,
              showTotal: (t) => `共 ${t} 条`,
              onChange: (p, ps) => {
                setPage(ps !== pageSize ? 1 : p)
                setPageSize(ps)
              },
            }}
          />
        )}
      </Card>

      <Drawer
        title="加密会话详情"
        open={selected !== null}
        onClose={() => setSelected(null)}
        width={620}
        destroyOnHidden
      >
        {selected && (
          <Descriptions column={1} size="small" bordered>
            <Descriptions.Item label="发生时间">
              {formatDateTime(selected.occurred_at)}
            </Descriptions.Item>
            <Descriptions.Item label="网关节点">
              {selected.gateway_node_id || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="应用 ID">
              {selected.application_id || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="SNI">
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                {selected.sni || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="客户端地址">
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                {selected.client_ip || '-'}
                {selected.client_port ? `:${selected.client_port}` : ''}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="服务监听端口">
              {selected.server_port || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="检测协议">
              <Tag color={protocolTagColor(selected.detected_protocol)}>
                {selected.detected_protocol || 'UNKNOWN'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="协商协议">
              {selected.negotiated_protocol ? (
                <Tag color={protocolTagColor(selected.negotiated_protocol)}>
                  {selected.negotiated_protocol}
                </Tag>
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="协议族">
              {selected.is_gm ? (
                <Tag color="volcano">国密 SM2 / TLCP</Tag>
              ) : (
                <Tag color="blue">通用国际 TLS</Tag>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="协商算法套件">
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                {selected.cipher_suite || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="ALPN 协议">
              {selected.alpn || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="JA3 指纹">
              {selected.ja3_hash ? (
                <Typography.Text
                  copyable
                  style={{ fontFamily: 'monospace', fontSize: 12 }}
                >
                  {selected.ja3_hash}
                </Typography.Text>
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="处置动作">
              {ACTION_META[selected.action] ? (
                <Tag color={ACTION_META[selected.action].color}>
                  {ACTION_META[selected.action].label}
                </Tag>
              ) : (
                selected.action || '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="阻断 / 失败原因">
              {selected.error_reason || '-'}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </Space>
  )
}
