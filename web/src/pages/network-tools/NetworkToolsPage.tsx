import { useState, type CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Input,
  InputNumber,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined, PlayCircleOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { networkToolsApi, type CreateNetworkToolJobBody } from '../../api/networkTools'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { isValidIPLiteral } from '../../utils/stage5'
import { PRE_STYLE } from '../../utils/styles'
import type { NetworkToolAction, NetworkToolCapturePacket, NetworkToolJob } from '../../types'

/** 动作展示 */
const ACTION_META: Record<string, { color: string; label: string }> = {
  ping: { color: 'blue', label: 'Ping' },
  tcp_probe: { color: 'cyan', label: 'TCP 端口探测' },
  traceroute: { color: 'purple', label: 'Traceroute' },
  dns_query: { color: 'geekblue', label: 'DNS 查询' },
  capture: { color: 'orange', label: '流量抓包' },
}

/** 任务状态展示（与 reports 状态 Tag 着色口径一致） */
const STATUS_META: Record<string, { color: string; label: string }> = {
  PENDING: { color: 'default', label: '排队中' },
  RUNNING: { color: 'processing', label: '执行中' },
  SUCCESS: { color: 'success', label: '成功' },
  FAILED: { color: 'error', label: '失败' },
  STOPPED: { color: 'warning', label: '已停止' },
  TIMEOUT: { color: 'warning', label: '超时' },
}

/** 主机名校验：点分标签（字母数字/连字符），与 syslog 服务器主机校验同口径 */
function isValidHostname(v: string): boolean {
  const label = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
  return v
    .toLowerCase()
    .split('.')
    .every((l) => label.test(l))
}

/** 诊断目标校验：IPv4/IPv6 字面量或合法主机名，禁止协议/路径/端口/空白 */
function validateTarget(raw: string): string | null {
  const v = raw.trim()
  if (!v) return '请输入目标地址'
  if (/\s/.test(v)) return '目标地址不能包含空白字符'
  if (v.includes('://') || v.includes('/')) return '目标地址不能包含协议或路径'
  if (isValidIPLiteral(v) || isValidHostname(v)) return null
  return '目标需为 IPv4/IPv6 地址或合法主机名'
}

/** 耗时展示：毫秒级原样展示，秒级保留两位小数 */
function formatDuration(ms?: number | null): string {
  if (ms === null || ms === undefined) return '-'
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms} ms`
}

/** 抓包大小展示（字节 → KB/MB） */
function formatCaptureSize(bytes?: number | null): string {
  if (bytes === null || bytes === undefined) return '-'
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(2)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

/** 诊断任务参数键中文展示映射 */
const PARAM_KEY_LABELS: Record<string, string> = {
  count: '次数',
  port: '端口',
  max_hops: '最大跳数',
  iface: '网口',
  duration_sec: '时长(秒)',
  filter_proto: '协议',
  filter_port: '过滤端口',
  filter_host: '过滤主机',
  timeout_sec: '超时(秒)',
  domain: '域名',
  record_type: '记录类型',
}

/** 参数摘要：params 回显为中文键=值序列 */
function paramsSummary(params: Record<string, unknown>): string {
  const entries = Object.entries(params ?? {})
  if (entries.length === 0) return '-'
  return entries.map(([k, v]) => `${PARAM_KEY_LABELS[k] ?? k}=${String(v)}`).join('  ')
}

/** 后端最多解析并返回的数据包条数，达到该值提示可能截断 */
const CAPTURE_PACKET_LIMIT = 200

/** 数据包协议 Tag 着色（TCP/UDP/ICMP 之外使用 default） */
const PACKET_PROTO_COLORS: Record<string, string> = {
  TCP: 'blue',
  UDP: 'green',
  ICMP: 'orange',
}

/** 数据包时间：表格内展示 HH:mm:ss.SSS */
function formatPacketTime(ts: string): string {
  const d = dayjs(ts)
  return d.isValid() ? d.format('HH:mm:ss.SSS') : ts
}

/** 数据包时间 tooltip：完整日期时间（毫秒） */
function formatPacketTimeFull(ts: string): string {
  const d = dayjs(ts)
  return d.isValid() ? d.format('YYYY-MM-DD HH:mm:ss.SSS') : ts
}

/** 端点展示：TCP/UDP 携带端口时拼接 ip:port，否则仅 IP */
function formatEndpoint(ip: string, port?: number | null): string {
  return port === null || port === undefined ? ip : `${ip}:${port}`
}

const MONO_STYLE: CSSProperties = { fontFamily: 'monospace' }

/** 抓包数据包表格列（详情抽屉内嵌，客户端分页） */
const packetColumns: ColumnsType<NetworkToolCapturePacket> = [
  { title: '#', dataIndex: 'no', width: 56 },
  {
    title: '时间',
    dataIndex: 'ts',
    width: 108,
    render: (v: string) => (
      <Tooltip title={formatPacketTimeFull(v)}>
        <span style={MONO_STYLE}>{formatPacketTime(v)}</span>
      </Tooltip>
    ),
  },
  {
    title: '源',
    key: 'src',
    width: 140,
    ellipsis: true,
    render: (_, r) => <span style={MONO_STYLE}>{formatEndpoint(r.src, r.sport)}</span>,
  },
  {
    title: '目的',
    key: 'dst',
    width: 140,
    ellipsis: true,
    render: (_, r) => <span style={MONO_STYLE}>{formatEndpoint(r.dst, r.dport)}</span>,
  },
  {
    title: '协议',
    dataIndex: 'proto',
    width: 88,
    render: (v: string) => <Tag color={PACKET_PROTO_COLORS[v] ?? 'default'}>{v}</Tag>,
  },
  {
    title: '标志',
    dataIndex: 'flags',
    width: 96,
    render: (v: string) => (v ? <span style={MONO_STYLE}>{v}</span> : '-'),
  },
  { title: '长度', dataIndex: 'length', width: 72 },
  {
    title: '数据预览',
    dataIndex: 'preview',
    ellipsis: { showTitle: false },
    render: (v: string) =>
      v ? (
        <Tooltip title={v}>
          <span style={MONO_STYLE}>{v}</span>
        </Tooltip>
      ) : (
        '-'
      ),
  },
]

/** 网络工具：ping/TCP 端口探测/traceroute/DNS 查询/流量抓包 任务创建、轮询、停止与 pcap 下载 */
export default function NetworkToolsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canDownload = hasPermission(permissions, 'network_tools.download')

  // 诊断表单（受控字段，按动作动态显隐）
  const [action, setAction] = useState<NetworkToolAction>('ping')
  const [target, setTarget] = useState('')
  const [port, setPort] = useState<number | null>(null)
  const [count, setCount] = useState<number | null>(4)
  const [maxHops, setMaxHops] = useState<number | null>(30)
  const [iface, setIface] = useState('')
  const [durationSec, setDurationSec] = useState<number | null>(10)
  const [filterProto, setFilterProto] = useState<'' | 'tcp' | 'udp' | 'icmp'>('')
  const [filterPort, setFilterPort] = useState<number | null>(null)
  const [filterHost, setFilterHost] = useState('')

  // 任务列表
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [actionFilter, setActionFilter] = useState<string>()
  const [statusFilter, setStatusFilter] = useState<string>()
  const [detailJob, setDetailJob] = useState<NetworkToolJob | null>(null)

  const listQuery = useQuery({
    queryKey: ['network-tools-jobs', actionFilter, statusFilter, page, pageSize],
    queryFn: () =>
      networkToolsApi.list({ action: actionFilter, status: statusFilter, page, page_size: pageSize }),
    // 存在非终态任务时轮询执行进度
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((j) => j.status === 'PENDING' || j.status === 'RUNNING')
        ? 3000
        : false,
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['network-tools-jobs'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  // 抓包任务打开详情时拉取完整 job（列表行不含 capture_packets）
  const detailQuery = useQuery({
    queryKey: ['network-tools-job', detailJob?.id],
    queryFn: () => networkToolsApi.get(detailJob!.id),
    enabled: detailJob?.action === 'capture',
  })
  const detail = detailQuery.data ?? detailJob
  const capturePackets = detail?.action === 'capture' ? (detail.capture_packets ?? []) : []
  const hasPackets = capturePackets.length > 0

  const createMutation = useMutation({
    mutationFn: (body: CreateNetworkToolJobBody) => networkToolsApi.create(body),
    onSuccess: () => {
      message.success('诊断任务已创建，正在后台执行')
      invalidate()
    },
    onError,
  })

  const stopMutation = useMutation({
    mutationFn: (id: string) => networkToolsApi.stop(id),
    onSuccess: () => {
      message.success('已请求停止任务')
      invalidate()
    },
    onError,
  })

  /** 前端校验后组装创建请求体：仅携带当前动作相关参数 */
  const submit = () => {
    const targetError = validateTarget(target)
    if (targetError) {
      message.error(targetError)
      return
    }
    const body: CreateNetworkToolJobBody = { action, target: target.trim() }
    switch (action) {
      case 'ping':
        if (count === null) {
          message.error('请输入 Ping 次数')
          return
        }
        body.count = count
        break
      case 'tcp_probe':
        if (port === null) {
          message.error('请输入探测端口')
          return
        }
        body.port = port
        break
      case 'traceroute':
        if (maxHops === null) {
          message.error('请输入最大跳数')
          return
        }
        body.max_hops = maxHops
        break
      case 'capture':
        if (!iface.trim()) {
          message.error('请输入抓包网口')
          return
        }
        if (durationSec === null) {
          message.error('请输入抓包时长')
          return
        }
        body.iface = iface.trim()
        body.duration_sec = durationSec
        if (filterProto) body.filter_proto = filterProto
        if (filterPort !== null) body.filter_port = filterPort
        if (filterHost.trim()) body.filter_host = filterHost.trim()
        break
    }
    createMutation.mutate(body)
  }

  const columns: ColumnsType<NetworkToolJob> = [
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '动作',
      dataIndex: 'action',
      width: 130,
      render: (v: string) => <StatusTag value={v} map={ACTION_META} />,
    },
    {
      title: '目标',
      dataIndex: 'target',
      width: 200,
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '参数摘要',
      key: 'params',
      ellipsis: true,
      render: (_, record) => (
        <Typography.Text style={{ fontSize: 12 }} type="secondary">
          {paramsSummary(record.params)}
        </Typography.Text>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={STATUS_META} />,
    },
    {
      title: '耗时',
      dataIndex: 'duration_ms',
      width: 100,
      render: (v?: number | null) => formatDuration(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 210,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          <Button type="link" size="small" onClick={() => setDetailJob(record)}>
            详情
          </Button>
          {(record.status === 'PENDING' || record.status === 'RUNNING') && (
            <Button
              type="link"
              size="small"
              danger
              loading={stopMutation.isPending && stopMutation.variables === record.id}
              onClick={() => stopMutation.mutate(record.id)}
            >
              停止
            </Button>
          )}
          {record.action === 'capture' && record.status === 'SUCCESS' && canDownload && (
            <Button
              type="link"
              size="small"
              icon={<DownloadOutlined />}
              onClick={() => window.open(networkToolsApi.downloadUrl(record.id), '_blank')}
            >
              下载 pcap
            </Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card title="新建诊断任务">
        <Space wrap size={[12, 12]}>
          <Space>
            <Typography.Text>动作</Typography.Text>
            <Select
              style={{ width: 150 }}
              value={action}
              options={Object.entries(ACTION_META).map(([value, meta]) => ({
                value,
                label: meta.label,
              }))}
              onChange={(v: NetworkToolAction) => setAction(v)}
              aria-label="动作"
            />
          </Space>
          <Space>
            <Typography.Text>目标</Typography.Text>
            <Input
              style={{ width: 240 }}
              placeholder="IP 或主机名，如 10.0.0.1 / example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              aria-label="目标"
            />
          </Space>
          {action === 'tcp_probe' && (
            <Space>
              <Typography.Text>端口</Typography.Text>
              <InputNumber
                min={1}
                max={65535}
                placeholder="1-65535"
                value={port}
                onChange={(v) => setPort(v)}
                aria-label="端口"
              />
            </Space>
          )}
          {action === 'ping' && (
            <Space>
              <Typography.Text>次数</Typography.Text>
              <InputNumber
                min={1}
                max={20}
                value={count}
                onChange={(v) => setCount(v)}
                aria-label="次数"
              />
            </Space>
          )}
          {action === 'traceroute' && (
            <Space>
              <Typography.Text>最大跳数</Typography.Text>
              <InputNumber
                min={1}
                max={30}
                value={maxHops}
                onChange={(v) => setMaxHops(v)}
                aria-label="最大跳数"
              />
            </Space>
          )}
          {action === 'capture' && (
            <>
              <Space>
                <Typography.Text>网口</Typography.Text>
                <Input
                  style={{ width: 140 }}
                  placeholder="如 eth0"
                  value={iface}
                  onChange={(e) => setIface(e.target.value)}
                  aria-label="网口"
                />
              </Space>
              <Space>
                <Typography.Text>抓包时长（秒）</Typography.Text>
                <InputNumber
                  min={5}
                  max={300}
                  value={durationSec}
                  onChange={(v) => setDurationSec(v)}
                  aria-label="抓包时长"
                />
              </Space>
              <Space>
                <Typography.Text>过滤协议</Typography.Text>
                <Select
                  style={{ width: 100 }}
                  value={filterProto}
                  options={[
                    { value: '', label: '全部' },
                    { value: 'tcp', label: 'TCP' },
                    { value: 'udp', label: 'UDP' },
                    { value: 'icmp', label: 'ICMP' },
                  ]}
                  onChange={(v: '' | 'tcp' | 'udp' | 'icmp') => setFilterProto(v)}
                  aria-label="过滤协议"
                />
              </Space>
              <Space>
                <Typography.Text>过滤端口</Typography.Text>
                <InputNumber
                  min={1}
                  max={65535}
                  placeholder="可选"
                  value={filterPort}
                  onChange={(v) => setFilterPort(v)}
                  aria-label="过滤端口"
                />
              </Space>
              <Space>
                <Typography.Text>过滤主机</Typography.Text>
                <Input
                  style={{ width: 160 }}
                  placeholder="可选，如 10.0.0.2"
                  value={filterHost}
                  onChange={(e) => setFilterHost(e.target.value)}
                  aria-label="过滤主机"
                />
              </Space>
            </>
          )}
          <Button
            type="primary"
            icon={<PlayCircleOutlined />}
            loading={createMutation.isPending}
            onClick={submit}
          >
            开始诊断
          </Button>
        </Space>
        {action === 'capture' && (
          <Alert
            style={{ marginTop: 12 }}
            type="warning"
            showIcon
            message="流量抓包在网关节点上执行，可能包含业务明文数据"
            description="抓包文件（pcap）生成后可下载，请按数据安全要求妥善保管并及时清理；建议配置过滤条件缩小采集范围。"
          />
        )}
      </Card>

      <Card title="任务列表">
        <Space style={{ marginBottom: 16 }} wrap>
          <Select
            placeholder="动作"
            allowClear
            style={{ width: 150 }}
            options={Object.entries(ACTION_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setActionFilter(v)
              setPage(1)
            }}
            aria-label="按动作过滤"
          />
          <Select
            placeholder="状态"
            allowClear
            style={{ width: 130 }}
            options={Object.entries(STATUS_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setStatusFilter(v)
              setPage(1)
            }}
            aria-label="按状态过滤"
          />
        </Space>
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载网络工具任务失败" />
        ) : (
          <SmartTable<NetworkToolJob>
            storageKey="network-tools-jobs"
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            scroll={{ x: 1200 }}
            pagination={{
              current: page,
              pageSize,
              total: listQuery.data?.total ?? 0,
              showSizeChanger: true,
              showTotal: (t) => `共 ${t} 条`,
              onChange: (p, ps) => {
                setPage(p)
                setPageSize(ps)
              },
            }}
            locale={{ emptyText: '暂无诊断任务' }}
          />
        )}
      </Card>

      <Drawer
        open={detailJob !== null}
        title="任务详情"
        width={hasPackets ? 880 : 640}
        onClose={() => setDetailJob(null)}
      >
        {detail && (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions
              column={2}
              size="small"
              bordered
              items={[
                { key: 'id', label: '任务编号', children: detail.id, span: 2 },
                { key: 'node', label: '节点', children: detail.node || '-' },
                {
                  key: 'action',
                  label: '动作',
                  children: <StatusTag value={detail.action} map={ACTION_META} />,
                },
                { key: 'target', label: '目标', children: <Typography.Text code>{detail.target}</Typography.Text> },
                {
                  key: 'status',
                  label: '状态',
                  children: <StatusTag value={detail.status} map={STATUS_META} />,
                },
                { key: 'duration', label: '耗时', children: formatDuration(detail.duration_ms) },
                {
                  key: 'exit_code',
                  label: '退出码',
                  children: detail.exit_code ?? '-',
                },
                { key: 'created_at', label: '创建时间', children: formatDateTime(detail.created_at) },
                { key: 'started_at', label: '开始时间', children: formatDateTime(detail.started_at) },
                { key: 'finished_at', label: '完成时间', children: formatDateTime(detail.finished_at) },
                ...(detail.action === 'capture'
                  ? [
                      {
                        key: 'capture_size',
                        label: '抓包大小',
                        children: formatCaptureSize(detail.capture_size),
                      },
                    ]
                  : []),
              ]}
            />
            {detail.failure_message && (
              <Alert type="error" showIcon message={detail.failure_message} />
            )}
            {detail.action === 'capture' && hasPackets && (
              <div>
                <Typography.Text strong>数据包</Typography.Text>
                <div style={{ margin: '4px 0 8px' }}>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    共 {capturePackets.length} 个数据包
                    {capturePackets.length >= CAPTURE_PACKET_LIMIT
                      ? '，已达解析上限，可能仅展示前 200 个，完整内容请下载 pcap'
                      : '（最多解析前 200 个，完整内容请下载 pcap）'}
                  </Typography.Text>
                </div>
                <Table<NetworkToolCapturePacket>
                  size="small"
                  rowKey="no"
                  columns={packetColumns}
                  dataSource={capturePackets}
                  scroll={{ x: 820 }}
                  pagination={{
                    pageSize: 10,
                    showSizeChanger: false,
                    showTotal: (t) => `共 ${t} 个`,
                  }}
                />
              </div>
            )}
            <div>
              <Typography.Text strong>任务参数</Typography.Text>
              <pre style={PRE_STYLE}>{JSON.stringify(detail.params ?? {}, null, 2)}</pre>
            </div>
            <div>
              <Typography.Text strong>执行输出</Typography.Text>
              <pre style={PRE_STYLE}>{detail.result_text || '（暂无输出）'}</pre>
            </div>
          </Space>
        )}
      </Drawer>
    </Space>
  )
}
