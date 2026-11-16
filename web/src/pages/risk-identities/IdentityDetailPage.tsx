import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Empty,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Spin,
  Table,
  Tabs,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ArrowLeftOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import type { Dayjs } from 'dayjs'
import { useNavigate, useParams } from 'react-router-dom'
import { ApiError } from '../../api/client'
import { securityIdentitiesApi } from '../../api/securityIdentities'
import type {
  IdentityBehaviorItem,
  IdentityCredentialItem,
  IdentityEventItem,
  IdentityIpHistoryItem,
} from '../../api/securityIdentities'
import EChart, { type EChartOption } from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { useBreadcrumbObjectName } from '../../stores/breadcrumb'
import { formatDateTime } from '../../utils/format'
import {
  IDENTITY_TYPE_META,
  RISK_LEVEL_META,
  SIGNAL_META,
} from '../../utils/identitySecurity'
import { hasPermission } from '../../utils/permission'

type RangeValue = [Dayjs | null, Dayjs | null] | null

const IDENTITY_STATUS_META: Record<string, { color: string; label: string }> = {
  ACTIVE: { color: 'green', label: '正常' },
  BLOCKED: { color: 'red', label: '已封禁' },
}

const TREND_SERIES = [
  {
    name: '请求数',
    color: '#1677ff',
    pick: (b: IdentityBehaviorItem) => b.request_count,
  },
  {
    name: '唯一URI数',
    color: '#52c41a',
    pick: (b: IdentityBehaviorItem) => b.unique_uri_count,
  },
  {
    name: '404数',
    color: '#f5222d',
    pick: (b: IdentityBehaviorItem) => b.status_404_count,
  },
] as const

/** 行为趋势折线：5m 窗口时间序列（请求数 / 唯一URI数 / 404数） */
function behaviorTrendOption(items: IdentityBehaviorItem[]): EChartOption {
  const points = [...items].sort((a, b) =>
    a.window_start < b.window_start ? -1 : 1,
  )
  return {
    grid: { left: 48, right: 16, top: 40, bottom: 28 },
    tooltip: { trigger: 'axis' },
    legend: { data: TREND_SERIES.map((s) => s.name), top: 0 },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: points.map((p) => dayjs(p.window_start).format('MM-DD HH:mm')),
      axisLabel: { hideOverlap: true },
    },
    yAxis: { type: 'value', minInterval: 1 },
    series: TREND_SERIES.map((s) => ({
      name: s.name,
      type: 'line',
      smooth: true,
      symbol: 'none',
      data: points.map((p) => s.pick(p)),
      itemStyle: { color: s.color },
      lineStyle: { width: 2, color: s.color },
    })),
  }
}

/** 长值（指纹/哈希）截断展示 + 完整值复制；空值占位 */
function CopyableLongValue({
  value,
  maxWidth = 260,
}: {
  value?: string
  maxWidth?: number
}) {
  if (!value) return <span>-</span>
  return (
    <Typography.Text
      copyable={{ text: value, tooltips: ['复制', '已复制'] }}
      style={{ fontFamily: 'monospace', fontSize: 12, maxWidth }}
      ellipsis={{
        tooltip: <span style={{ fontFamily: 'monospace' }}>{value}</span>,
      }}
    >
      {value}
    </Typography.Text>
  )
}

const ipHistoryColumns: ColumnsType<IdentityIpHistoryItem> = [
  { title: 'IP 地址', dataIndex: 'ip', width: 160 },
  {
    title: '首次发现',
    dataIndex: 'first_seen_at',
    width: 180,
    render: (v: string) => formatDateTime(v),
  },
  {
    title: '最近活跃',
    dataIndex: 'last_seen_at',
    width: 180,
    render: (v: string) => formatDateTime(v),
  },
  { title: '请求数', dataIndex: 'request_count', width: 120 },
]

const credentialColumns: ColumnsType<IdentityCredentialItem> = [
  { title: '凭据类型', dataIndex: 'credential_type', width: 160 },
  {
    title: '凭据哈希',
    dataIndex: 'credential_hash',
    render: (v: string) => <CopyableLongValue value={v} maxWidth={360} />,
  },
  {
    title: '首次发现',
    dataIndex: 'first_seen_at',
    width: 180,
    render: (v: string) => formatDateTime(v),
  },
  {
    title: '最近活跃',
    dataIndex: 'last_seen_at',
    width: 180,
    render: (v: string) => formatDateTime(v),
  },
]

export default function IdentityDetailPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const { message } = AntdApp.useApp()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canBlock = hasPermission(permissions, 'security_identities.block')

  // 行为趋势时间范围（默认最近 24 小时）
  const [trendRange, setTrendRange] = useState<[Dayjs, Dayjs]>(() => [
    dayjs().subtract(24, 'hour'),
    dayjs(),
  ])
  // 行为事件筛选与分页
  const [eventSignal, setEventSignal] = useState<string | undefined>()
  const [eventPage, setEventPage] = useState(1)
  const [eventPageSize, setEventPageSize] = useState(20)
  // 行双击通用详情（IP 历史 / 关联凭据 / 行为事件共用）
  const [recordDetail, setRecordDetail] = useState<{
    title: string
    record: Record<string, unknown>
  } | null>(null)
  const [blockOpen, setBlockOpen] = useState(false)
  const [blockForm] = Form.useForm<{ reason: string }>()

  const detailQuery = useQuery({
    queryKey: ['security-identities', 'detail', id],
    queryFn: () => securityIdentitiesApi.get(id),
    enabled: !!id,
  })

  const statusMut = useMutation({
    mutationFn: ({
      action,
      reason,
    }: {
      action: 'BLOCK' | 'UNBLOCK'
      reason?: string
    }) =>
      action === 'BLOCK'
        ? securityIdentitiesApi.block(id, reason ?? '')
        : securityIdentitiesApi.unblock(id),
    onSuccess: async (_result, variables) => {
      message.success(
        variables.action === 'BLOCK' ? '身份已封禁' : '身份已解封',
      )
      if (variables.action === 'BLOCK') {
        setBlockOpen(false)
        blockForm.resetFields()
      }
      await detailQuery.refetch()
    },
    onError: (error: unknown, variables) => {
      const fallback = variables.action === 'BLOCK' ? '封禁失败' : '解封失败'
      message.error(error instanceof ApiError ? error.message : fallback)
    },
  })

  const openBlock = () => {
    statusMut.reset()
    blockForm.resetFields()
    setBlockOpen(true)
  }

  const behaviorQuery = useQuery({
    queryKey: [
      'security-identities',
      'behavior',
      id,
      trendRange[0].toISOString(),
      trendRange[1].toISOString(),
    ],
    queryFn: () =>
      securityIdentitiesApi.behavior(id, {
        window: '5m',
        from: trendRange[0].toISOString(),
        to: trendRange[1].toISOString(),
        page: 1,
        page_size: 500,
      }),
    enabled: !!id,
  })

  const eventsQuery = useQuery({
    queryKey: [
      'security-identities',
      'events',
      id,
      eventSignal,
      eventPage,
      eventPageSize,
    ],
    queryFn: () =>
      securityIdentitiesApi.events(id, {
        signal: eventSignal,
        page: eventPage,
        page_size: eventPageSize,
      }),
    enabled: !!id,
  })

  // 面包屑注入当前身份标识（卸载时自动清理）
  useBreadcrumbObjectName(detailQuery.data?.identity_key)

  const onTrendRangeChange = (range: RangeValue) => {
    if (range?.[0] && range[1]) {
      setTrendRange([range[0], range[1]])
    }
  }

  const eventColumns: ColumnsType<IdentityEventItem> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '信号',
      dataIndex: 'signal',
      width: 130,
      render: (v: string) => <StatusTag value={v} map={SIGNAL_META} />,
    },
    {
      title: '规则',
      key: 'rule',
      width: 170,
      render: (_, record) => (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {record.rule_code}
          {record.rule_version ? ` (v${record.rule_version})` : ''}
        </Typography.Text>
      ),
    },
    {
      title: '加分',
      dataIndex: 'risk_score_delta',
      width: 80,
      render: (v: number) => (
        <Typography.Text type={v > 0 ? 'danger' : undefined}>
          {v > 0 ? `+${v}` : v}
        </Typography.Text>
      ),
    },
    {
      title: '原因',
      dataIndex: 'reason',
      width: 240,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v} placement="topLeft">
          <span>{v || '-'}</span>
        </Tooltip>
      ),
    },
    {
      title: '路径',
      key: 'path',
      ellipsis: true,
      render: (_, record) => (
        <Tooltip title={`${record.method} ${record.path}`} placement="topLeft">
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
            {record.method} {record.path}
          </Typography.Text>
        </Tooltip>
      ),
    },
  ]

  if (detailQuery.isError) {
    return (
      <Card>
        <Alert
          type="error"
          showIcon
          message="加载身份详情失败"
          description={
            detailQuery.error instanceof ApiError
              ? detailQuery.error.message
              : undefined
          }
          action={
            <Button onClick={() => navigate('/risk-identities')}>
              返回列表
            </Button>
          }
        />
      </Card>
    )
  }

  const detail = detailQuery.data

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card
        title={
          <Space>
            <Button
              type="text"
              icon={<ArrowLeftOutlined />}
              aria-label="返回列表"
              onClick={() => navigate('/risk-identities')}
            />
            <span>身份详情</span>
            {detail && (
              <StatusTag value={detail.risk_level} map={RISK_LEVEL_META} />
            )}
          </Space>
        }
        extra={
          <Space>
            {canBlock && detail ? (
              detail.status === 'BLOCKED' ? (
                <Button
                  loading={statusMut.isPending}
                  onClick={() => statusMut.mutate({ action: 'UNBLOCK' })}
                >
                  解封
                </Button>
              ) : (
                <Button
                  danger
                  loading={statusMut.isPending}
                  onClick={openBlock}
                >
                  封禁
                </Button>
              )
            ) : null}
            <Button onClick={() => navigate('/risk-identities')}>
              返回列表
            </Button>
          </Space>
        }
        loading={detailQuery.isLoading}
      >
        {detail && (
          <Descriptions bordered size="small" column={{ xs: 1, sm: 2 }}>
            <Descriptions.Item label="身份标识">
              <CopyableLongValue value={detail.identity_key} />
            </Descriptions.Item>
            <Descriptions.Item label="类型">
              <StatusTag
                value={detail.identity_type}
                map={IDENTITY_TYPE_META}
              />
            </Descriptions.Item>
            <Descriptions.Item label="识别置信度">
              {detail.identity_confidence ?? 0}%
            </Descriptions.Item>
            <Descriptions.Item label="置信度依据" span={2}>
              {detail.confidence_source.length > 0
                ? detail.confidence_source.join('、')
                : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="风险分">
              {detail.risk_score}
            </Descriptions.Item>
            <Descriptions.Item label="风险等级">
              <StatusTag value={detail.risk_level} map={RISK_LEVEL_META} />
            </Descriptions.Item>
            <Descriptions.Item label="状态">
              <StatusTag value={detail.status} map={IDENTITY_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="主IP">
              {detail.primary_ip || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="ASN">
              {detail.asn || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="设备类型">
              {detail.device_type || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="账号">
              {detail.account_id || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="JWT Subject">
              <CopyableLongValue value={detail.jwt_subject} />
            </Descriptions.Item>
            <Descriptions.Item label="API Key 哈希">
              <CopyableLongValue value={detail.api_key_hash} />
            </Descriptions.Item>
            <Descriptions.Item label="OAuth Client ID">
              <CopyableLongValue value={detail.oauth_client_id} />
            </Descriptions.Item>
            <Descriptions.Item label="TLS 指纹">
              <CopyableLongValue value={detail.tls_fingerprint} />
            </Descriptions.Item>
            <Descriptions.Item label="浏览器指纹">
              <CopyableLongValue value={detail.browser_fingerprint} />
            </Descriptions.Item>
            <Descriptions.Item label="请求数">
              {detail.request_count}
            </Descriptions.Item>
            <Descriptions.Item label="首次发现">
              {formatDateTime(detail.first_seen_at)}
            </Descriptions.Item>
            <Descriptions.Item label="最近活跃">
              {formatDateTime(detail.last_seen_at)}
            </Descriptions.Item>
            <Descriptions.Item label="创建时间">
              {formatDateTime(detail.created_at)}
            </Descriptions.Item>
            <Descriptions.Item label="更新时间">
              {formatDateTime(detail.updated_at)}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Card>

      <Card>
        <Tabs
          items={[
            {
              key: 'ip-history',
              label: `IP 历史（${detail?.ip_history.length ?? 0}）`,
              children: (
                <Table<IdentityIpHistoryItem>
                  rowKey="ip"
                  size="small"
                  columns={ipHistoryColumns}
                  dataSource={detail?.ip_history}
                  loading={detailQuery.isLoading}
                  pagination={false}
                  onRow={(record) => ({
                    onDoubleClick: () =>
                      setRecordDetail({
                        title: 'IP 历史详情',
                        record: { ...record },
                      }),
                    style: { cursor: 'pointer' },
                  })}
                />
              ),
            },
            {
              key: 'credentials',
              label: `关联凭据（${detail?.credentials.length ?? 0}）`,
              children: (
                <Table<IdentityCredentialItem>
                  rowKey={(r) => `${r.credential_type}:${r.credential_hash}`}
                  size="small"
                  columns={credentialColumns}
                  dataSource={detail?.credentials}
                  loading={detailQuery.isLoading}
                  pagination={false}
                  onRow={(record) => ({
                    onDoubleClick: () =>
                      setRecordDetail({
                        title: '凭据详情',
                        record: { ...record },
                      }),
                    style: { cursor: 'pointer' },
                  })}
                />
              ),
            },
            {
              key: 'behavior-trend',
              label: '行为趋势',
              children: (
                <>
                  <Space style={{ marginBottom: 16 }} wrap>
                    <DatePicker.RangePicker
                      showTime
                      value={trendRange}
                      allowClear={false}
                      onChange={onTrendRangeChange}
                    />
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      统计窗口：5 分钟
                    </Typography.Text>
                  </Space>
                  {behaviorQuery.isLoading ? (
                    <div
                      style={{
                        height: 320,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <Spin />
                    </div>
                  ) : behaviorQuery.isError ? (
                    <QueryErrorAlert
                      error={behaviorQuery.error}
                      message="加载行为趋势失败"
                    />
                  ) : (behaviorQuery.data?.items.length ?? 0) > 0 ? (
                    <EChart
                      option={behaviorTrendOption(
                        behaviorQuery.data?.items ?? [],
                      )}
                      height={320}
                      ariaLabel="身份行为趋势（5分钟统计窗口）"
                    />
                  ) : (
                    <Empty
                      image={Empty.PRESENTED_IMAGE_SIMPLE}
                      description="该时间范围内暂无行为数据"
                      style={{ margin: '48px 0' }}
                    />
                  )}
                </>
              ),
            },
            {
              key: 'behavior-events',
              label: '行为事件',
              children: (
                <>
                  <Space style={{ marginBottom: 16 }} wrap>
                    <Select
                      placeholder="信号类型"
                      allowClear
                      style={{ width: 170 }}
                      options={Object.entries(SIGNAL_META).map(
                        ([value, m]) => ({
                          value,
                          label: m.label,
                        }),
                      )}
                      onChange={(v) => {
                        setEventSignal(v)
                        setEventPage(1)
                      }}
                    />
                  </Space>
                  {eventsQuery.isError ? (
                    <QueryErrorAlert
                      error={eventsQuery.error}
                      message="加载行为事件失败"
                    />
                  ) : (
                    <SmartTable<IdentityEventItem>
                      storageKey="risk-identity-events"
                      rowKey="id"
                      size="small"
                      loading={eventsQuery.isLoading}
                      columns={eventColumns}
                      dataSource={eventsQuery.data?.items}
                      scroll={{ x: 1100 }}
                      pagination={{
                        current: eventPage,
                        pageSize: eventPageSize,
                        total: eventsQuery.data?.total ?? 0,
                        showSizeChanger: true,
                        showTotal: (t) => `共 ${t} 条`,
                        onChange: (p, ps) => {
                          setEventPage(p)
                          setEventPageSize(ps)
                        },
                      }}
                    />
                  )}
                </>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        title="封禁身份"
        open={blockOpen}
        onCancel={() => {
          setBlockOpen(false)
          blockForm.resetFields()
        }}
        onOk={() => blockForm.submit()}
        okText="确认封禁"
        okButtonProps={{ danger: true }}
        confirmLoading={statusMut.isPending}
        destroyOnHidden
      >
        <Form<{ reason: string }>
          form={blockForm}
          layout="vertical"
          onFinish={(values) =>
            statusMut.mutate({ action: 'BLOCK', reason: values.reason.trim() })
          }
        >
          <Form.Item
            name="reason"
            label="封禁原因（reason）"
            rules={[
              { required: true, message: '请输入封禁原因' },
              { whitespace: true, message: '请输入封禁原因' },
              { max: 512, message: '封禁原因不超过 512 字符' },
            ]}
          >
            <Input.TextArea
              rows={4}
              maxLength={512}
              showCount
              placeholder="请输入封禁原因"
            />
          </Form.Item>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={recordDetail !== null}
        title={recordDetail?.title ?? '详情'}
        record={recordDetail?.record ?? null}
        onClose={() => setRecordDetail(null)}
      />
    </Space>
  )
}
