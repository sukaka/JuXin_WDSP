import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Badge,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  ReloadOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
  SyncOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import {
  XDP_ACCEL_LIMITS,
  xdpAccelApi,
  type XdpAccelSyncResult,
  type XdpAttachMode,
  type XdpInterfaceStatus,
} from '../../api/xdpAccel'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  formatPacketCount,
  getXdpHeadlineStatus,
  mapXdpAccelFieldErrorPath,
  normalizeXdpInterfaces,
  validateXdpInterfaces,
  validateXdpSocketPath,
  XDP_ATTACH_MODE_META,
  XDP_DAEMON_STATUS_META,
  XDP_RUNTIME_MODE_META,
} from '../../utils/xdpAccel'

interface XdpConfigFormValues {
  enabled: boolean
  attach_mode: XdpAttachMode
  interfaces: string[]
  sync_interval_seconds: number
  socket_path: string
  reason: string
}

const ATTACH_MODE_OPTIONS: { value: XdpAttachMode; label: string }[] = [
  {
    value: 'auto',
    label: `${XDP_ATTACH_MODE_META.auto.label}（auto）`,
  },
  {
    value: 'native',
    label: `${XDP_ATTACH_MODE_META.native.label}（native）`,
  },
  {
    value: 'generic',
    label: `${XDP_ATTACH_MODE_META.generic.label}（generic）`,
  },
]

const DEFAULT_FORM_VALUES: XdpConfigFormValues = {
  enabled: false,
  attach_mode: XDP_ACCEL_LIMITS.defaultAttachMode,
  interfaces: [],
  sync_interval_seconds: XDP_ACCEL_LIMITS.defaultSyncIntervalSec,
  socket_path: XDP_ACCEL_LIMITS.defaultSocketPath,
  reason: '',
}

interface SyncBannerState {
  type: 'success' | 'warning' | 'error'
  title: string
  description: string
}

function buildSyncBannerFromResult(res: XdpAccelSyncResult): SyncBannerState {
  const modeLabel = XDP_RUNTIME_MODE_META[res.mode]?.label ?? res.mode
  const parts = [
    `当前模式：${modeLabel}`,
    `已同步前缀：IPv4 ${res.synced_v4_cidrs} / IPv6 ${res.synced_v6_cidrs}`,
    `受保护地址自动排除：${res.excluded_protected_count}`,
  ]
  if (
    typeof res.control_plane_excluded_count === 'number' &&
    res.control_plane_excluded_count > 0
  ) {
    parts.push(`控制面过滤排除：${res.control_plane_excluded_count}`)
  }
  if (
    typeof res.invalid_cidrs_skipped === 'number' &&
    res.invalid_cidrs_skipped > 0
  ) {
    parts.push(`跳过无效条目：${res.invalid_cidrs_skipped}`)
  }
  if (res.attached_interfaces.length > 0) {
    parts.push(`已挂载网卡：${res.attached_interfaces.join('、')}`)
  }
  if (res.error) {
    parts.push(`诊断信息：${res.error}`)
  }

  if (res.synced) {
    return {
      type: 'success',
      title: res.kernel_attached
        ? '已成功同步全局黑名单至 XDP 内核映射表'
        : '同步已完成（当前已安全卸载 XDP 内核挂载）',
      description: parts.join('；'),
    }
  }
  return {
    type: 'warning',
    title: '同步未完成内核挂载（已自动回退至用户态防护）',
    description: parts.join('；'),
  }
}

export default function XdpAccelerationPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'xdp_accel.manage')
  const [form] = Form.useForm<XdpConfigFormValues>()
  const [syncBanner, setSyncBanner] = useState<SyncBannerState | null>(null)

  const enabledWatch = Form.useWatch('enabled', form) ?? false

  const configQuery = useQuery({
    queryKey: ['xdp-accel-config'],
    queryFn: () => xdpAccelApi.getConfig(),
  })

  const statusQuery = useQuery({
    queryKey: ['xdp-accel-status'],
    queryFn: () => xdpAccelApi.getStatus(),
  })

  useEffect(() => {
    const cfg = configQuery.data
    if (!cfg) return
    form.setFieldsValue({
      enabled: cfg.enabled,
      attach_mode: cfg.attach_mode,
      interfaces: cfg.interfaces,
      sync_interval_seconds: cfg.sync_interval_seconds,
      socket_path: cfg.socket_path,
      reason: '',
    })
  }, [configQuery.data, form])

  const invalidateAll = () => {
    void queryClient.invalidateQueries({ queryKey: ['xdp-accel-config'] })
    void queryClient.invalidateQueries({ queryKey: ['xdp-accel-status'] })
  }

  const saveMutation = useMutation({
    mutationFn: (values: XdpConfigFormValues) => {
      const normalizedInterfaces = normalizeXdpInterfaces(values.interfaces)
      const trimmedReason = (values.reason ?? '').trim()
      return xdpAccelApi.updateConfig({
        enabled: Boolean(values.enabled),
        attach_mode: values.attach_mode,
        interfaces: normalizedInterfaces,
        sync_interval_seconds: values.sync_interval_seconds,
        socket_path: values.socket_path.trim(),
        ...(trimmedReason ? { reason: trimmedReason } : {}),
      })
    },
    onSuccess: (res) => {
      if (res.sync_warning) {
        message.warning(`XDP 配置已保存，但实时同步告警：${res.sync_warning}`)
        setSyncBanner({
          type: 'warning',
          title: '配置已持久化，实时下发至守护进程产生告警',
          description: res.sync_warning,
        })
      } else if (res.sync_result) {
        message.success('XDP 加速配置已保存并完成同步')
        setSyncBanner(buildSyncBannerFromResult(res.sync_result))
      } else {
        message.success('XDP 加速配置已保存')
        setSyncBanner(null)
      }
      invalidateAll()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && Array.isArray(e.details)) {
        const details = e.details as { field?: string; message?: string }[]
        const fields: { name: (string | number)[]; errors: string[] }[] = []
        const unmapped: string[] = []
        for (const d of details) {
          if (!d.field) continue
          const errMsg = d.message ?? '取值不合法'
          const path = mapXdpAccelFieldErrorPath(d.field)
          if (path) {
            fields.push({ name: path, errors: [errMsg] })
          } else {
            unmapped.push(`${d.field}: ${errMsg}`)
          }
        }
        if (fields.length > 0) {
          form.setFields(fields as Parameters<typeof form.setFields>[0])
        }
        message.error(
          unmapped.length > 0
            ? `${e.message}（${unmapped.join('；')}）`
            : e.message || '保存配置失败，请检查输入项',
        )
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存 XDP 配置失败')
    },
  })

  const syncMutation = useMutation({
    mutationFn: () => xdpAccelApi.sync(),
    onSuccess: (res) => {
      const banner = buildSyncBannerFromResult(res)
      setSyncBanner(banner)
      if (res.synced) {
        message.success(banner.title)
      } else {
        message.warning(banner.title)
      }
      void queryClient.invalidateQueries({ queryKey: ['xdp-accel-status'] })
    },
    onError: (e: unknown) => {
      const errMsg =
        e instanceof ApiError
          ? e.message
          : '无法连接 XDP 守护进程，请确认服务状态后重试'
      message.error(`立即同步失败：${errMsg}`)
      setSyncBanner({
        type: 'error',
        title: '立即同步黑名单至 XDP 失败（用户态防护仍正常生效）',
        description: errMsg,
      })
      void queryClient.invalidateQueries({ queryKey: ['xdp-accel-status'] })
    },
  })

  const status = statusQuery.data
  const config = configQuery.data
  const headline = getXdpHeadlineStatus(status)

  const nicColumns: ColumnsType<XdpInterfaceStatus> = [
    {
      title: '网卡名',
      dataIndex: 'name',
      key: 'name',
      width: 180,
      render: (name: string) => (
        <Typography.Text code strong>
          {name || '-'}
        </Typography.Text>
      ),
    },
    {
      title: '挂载状态',
      dataIndex: 'attached',
      key: 'attached',
      width: 130,
      render: (attached: boolean) =>
        attached ? (
          <Tag color="green">已挂载</Tag>
        ) : (
          <Tag color="default">未挂载</Tag>
        ),
    },
    {
      title: '挂载模式',
      dataIndex: 'mode',
      key: 'mode',
      width: 210,
      render: (mode: string) => (
        <StatusTag value={mode} map={XDP_RUNTIME_MODE_META} />
      ),
    },
    {
      title: '诊断信息',
      dataIndex: 'error',
      key: 'error',
      render: (error?: string) =>
        error ? (
          <Typography.Text type="danger">{error}</Typography.Text>
        ) : (
          <Typography.Text type="secondary">-</Typography.Text>
        ),
    },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* 页面标题与安全边界说明（始终可见） */}
      <Card>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: 12,
            marginBottom: 16,
          }}
        >
          <div>
            <Space size={8} align="center">
              <ThunderboltOutlined style={{ fontSize: 20, color: '#1677ff' }} />
              <Typography.Title level={4} style={{ margin: 0 }}>
                内核 XDP 加速
              </Typography.Title>
            </Space>
            <Typography.Paragraph
              type="secondary"
              style={{ marginTop: 6, marginBottom: 0 }}
            >
              基于 eBPF/XDP 的物理网卡入口高速丢包引擎（xdpguard），在流量进入协议栈与用户态之前过滤全局黑名单与全局临时封禁。
            </Typography.Paragraph>
          </div>
          {!canManage && <Tag color="default">只读视图</Tag>}
        </div>

        <Alert
          type="info"
          showIcon
          icon={<SafetyCertificateOutlined />}
          title="XDP 内核高速丢包安全边界与自动降级说明"
          description={
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div>
                1. <strong>仅处理全局黑名单与全局临时封禁</strong>：XDP
                在物理业务网卡入口进入用户态之前，仅对全局生效的 IP
                黑名单和全局人工/自动临时封禁执行高速 <code>XDP_DROP</code>
                ；应用级规则与正常业务请求均经 <code>XDP_PASS</code>
                完整进入用户态 WAF 与 API 动态防护管线。
              </div>
              <div>
                2. <strong>双重隔离防误封</strong>：
                <strong>
                  protected_addresses、管理口、环回与链路本地地址被双重隔离永不写入
                  XDP 丢包表
                </strong>
                （控制面与内核守护进程双侧独立过滤，包含任一受保护 IP 的宽网段
                CIDR 亦自动剔除，且拒绝挂载 <code>lo</code> 及{' '}
                <code>docker*</code>/<code>br-*</code>/<code>veth*</code>{' '}
                等虚拟网口）。
              </div>
              <div>
                3. <strong>无特权环境自动 Fail-Open 回退</strong>
                ：在无特权容器、非 Linux 宿主机或 <code>xdpguard</code>{' '}
                未部署/离线环境下，系统自动回退至用户态防护，并如实展示降级或未部署状态，绝不影响正常业务访问。
              </div>
            </div>
          }
        />
      </Card>

      {/* 实时状态与遥测卡片 */}
      <Card
        title="运行状态与实时遥测"
        extra={
          <Space size={8} wrap>
            {status && (
              <>
                <Tag color={headline.color} style={{ marginInlineEnd: 0 }}>
                  <Badge
                    status={headline.badgeStatus}
                    text={
                      <span style={{ color: 'inherit' }}>{headline.label}</span>
                    }
                  />
                </Tag>
                <StatusTag
                  value={status.mode}
                  map={XDP_RUNTIME_MODE_META}
                />
              </>
            )}
            <Button
              size="small"
              icon={<ReloadOutlined />}
              loading={statusQuery.isFetching}
              onClick={() => void statusQuery.refetch()}
            >
              刷新状态
            </Button>
          </Space>
        }
      >
        {statusQuery.isLoading ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Spin size="small" />
            <Typography.Text type="secondary">
              正在通过本地 Unix Socket 探测 xdpguard 守护进程状态…
            </Typography.Text>
          </div>
        ) : statusQuery.isError ? (
          <QueryErrorAlert
            error={statusQuery.error}
            message="获取 XDP 实时状态失败"
          />
        ) : status ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {!status.available ? (
              <Alert
                type="error"
                showIcon
                title="XDP 守护进程未部署或当前不可达（已自动回退至用户态防护）"
                description={
                  <div>
                    探测 Socket 路径：
                    <Typography.Text code>{status.socket_path}</Typography.Text>
                    ；状态：
                    {XDP_DAEMON_STATUS_META[status.status]?.label ??
                      status.status}
                    {status.error ? `；诊断信息：${status.error}` : ''}
                    。系统不会伪装内核挂载状态，用户态黑名单与 WAF
                    防护持续正常工作。
                  </div>
                }
              />
            ) : !status.kernel_attached ? (
              <Alert
                type="warning"
                showIcon
                title="XDP 当前运行于用户态回退模式（未挂载内核网卡）"
                description={
                  <div>
                    守护进程在线（状态：
                    {XDP_DAEMON_STATUS_META[status.status]?.label ??
                      status.status}
                    ），当前处于
                    {XDP_RUNTIME_MODE_META[status.mode]?.label ?? status.mode}
                    {status.error ? `；诊断信息：${status.error}` : ''}
                    。请检查是否已在下方启用加速并配置合法物理业务网卡，或在裸机环境授予{' '}
                    <code>CAP_BPF</code> 与 <code>CAP_NET_ADMIN</code>。
                  </div>
                }
              />
            ) : (
              <Alert
                type="success"
                showIcon
                title="eBPF/XDP 内核级丢包已挂载生效"
                description={`当前运行模式：${XDP_RUNTIME_MODE_META[status.mode]?.label ?? status.mode}；已挂载网卡 ${status.interfaces.filter((i) => i.attached).length} 个；Socket：${status.socket_path}。`}
              />
            )}

            <Row gutter={[16, 16]}>
              <Col xs={24} sm={12} md={8} lg={4}>
                <Card size="small">
                  <Tooltip
                    title={`精确丢包数：${status.dropped_v4_packets.toLocaleString('en-US')}`}
                  >
                    <div>
                      <Statistic
                        title="IPv4 内核丢包数"
                        value={formatPacketCount(status.dropped_v4_packets)}
                      />
                    </div>
                  </Tooltip>
                </Card>
              </Col>
              <Col xs={24} sm={12} md={8} lg={4}>
                <Card size="small">
                  <Tooltip
                    title={`精确丢包数：${status.dropped_v6_packets.toLocaleString('en-US')}`}
                  >
                    <div>
                      <Statistic
                        title="IPv6 内核丢包数"
                        value={formatPacketCount(status.dropped_v6_packets)}
                      />
                    </div>
                  </Tooltip>
                </Card>
              </Col>
              <Col xs={24} sm={12} md={8} lg={5}>
                <Card size="small">
                  <Statistic
                    title="已同步黑名单前缀 (v4/v6)"
                    value={`${status.synced_v4_cidrs} / ${status.synced_v6_cidrs}`}
                  />
                </Card>
              </Col>
              <Col xs={24} sm={12} md={8} lg={5}>
                <Card size="small">
                  <Statistic
                    title="受保护地址自动排除数"
                    value={status.excluded_protected_count}
                  />
                </Card>
              </Col>
              <Col xs={24} sm={12} md={16} lg={6}>
                <Card size="small">
                  <Statistic
                    title="最近同步时间"
                    value={
                      status.last_sync_at
                        ? formatDateTime(status.last_sync_at)
                        : '尚未同步'
                    }
                    styles={{ content: { fontSize: 16 } }}
                  />
                </Card>
              </Col>
            </Row>

            <Descriptions
              size="small"
              bordered
              column={{ xs: 1, sm: 2, lg: 4 }}
            >
              <Descriptions.Item label="守护进程状态">
                <StatusTag
                  value={status.status}
                  map={XDP_DAEMON_STATUS_META}
                />
              </Descriptions.Item>
              <Descriptions.Item label="请求挂载模式">
                <StatusTag
                  value={status.attach_mode_requested}
                  map={XDP_ATTACH_MODE_META}
                />
              </Descriptions.Item>
              <Descriptions.Item label="XDP 放行包数（XDP_PASS）">
                <Tooltip
                  title={`精确放行包数：${status.passed_packets.toLocaleString('en-US')}`}
                >
                  <span>{formatPacketCount(status.passed_packets)}</span>
                </Tooltip>
              </Descriptions.Item>
              <Descriptions.Item label="探测 Unix Socket">
                <Typography.Text code>{status.socket_path}</Typography.Text>
              </Descriptions.Item>
            </Descriptions>

            <div>
              <Typography.Text
                strong
                style={{ display: 'block', marginBottom: 8 }}
              >
                网卡挂载明细
              </Typography.Text>
              <Table<XdpInterfaceStatus>
                size="small"
                rowKey="name"
                columns={nicColumns}
                dataSource={status.interfaces}
                pagination={false}
                locale={{
                  emptyText: '当前无已挂载网卡记录',
                }}
              />
            </div>
          </div>
        ) : null}
      </Card>

      {/* 配置表单卡片 */}
      <Card
        title="XDP 加速配置"
        extra={
          config ? (
            <Space size={8} wrap>
              <Tag style={{ marginInlineEnd: 0 }}>版本 v{config.version}</Tag>
              {config.updated_at && (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  更新时间：{formatDateTime(config.updated_at)}
                </Typography.Text>
              )}
            </Space>
          ) : null
        }
      >
        {configQuery.isLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 32 }}>
            <Spin />
          </div>
        ) : configQuery.isError ? (
          <QueryErrorAlert
            error={configQuery.error}
            message="加载 XDP 加速配置失败"
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {syncBanner && (
              <Alert
                type={syncBanner.type}
                showIcon
                closable
                onClose={() => setSyncBanner(null)}
                title={syncBanner.title}
                description={syncBanner.description}
              />
            )}

            <Form<XdpConfigFormValues>
              form={form}
              layout="vertical"
              initialValues={DEFAULT_FORM_VALUES}
              disabled={!canManage}
              onFinish={(values) => saveMutation.mutate(values)}
            >
              <Row gutter={16}>
                <Col xs={24} md={8}>
                  <Form.Item
                    label="启用 XDP 内核加速"
                    name="enabled"
                    valuePropName="checked"
                    extra="关闭后将自动卸载全部网卡的 XDP 程序并安全回退用户态防护。"
                  >
                    <Switch
                      checkedChildren="已启用"
                      unCheckedChildren="已关闭"
                      onChange={() => {
                        void form
                          .validateFields(['interfaces'])
                          .catch(() => undefined)
                      }}
                    />
                  </Form.Item>
                </Col>
                <Col xs={24} md={8}>
                  <Form.Item
                    label="挂载模式"
                    name="attach_mode"
                    rules={[{ required: true, message: '请选择挂载模式' }]}
                    extra="推荐 auto：优先尝试驱动级 Native XDP，驱动不支持时自动回退至内核 Generic 模式。"
                  >
                    <Select options={ATTACH_MODE_OPTIONS} />
                  </Form.Item>
                </Col>
                <Col xs={24} md={8}>
                  <Form.Item
                    label="同步周期 (秒)"
                    name="sync_interval_seconds"
                    rules={[
                      { required: true, message: '请输入同步周期' },
                      {
                        type: 'number',
                        min: XDP_ACCEL_LIMITS.minSyncIntervalSec,
                        max: XDP_ACCEL_LIMITS.maxSyncIntervalSec,
                        message: `同步周期须在 ${XDP_ACCEL_LIMITS.minSyncIntervalSec} ~ ${XDP_ACCEL_LIMITS.maxSyncIntervalSec} 秒之间`,
                      },
                    ]}
                    extra={`后台周期将全局 IP 黑名单与临时封禁同步至 XDP（范围 ${XDP_ACCEL_LIMITS.minSyncIntervalSec}~${XDP_ACCEL_LIMITS.maxSyncIntervalSec} 秒）。`}
                  >
                    <InputNumber
                      min={XDP_ACCEL_LIMITS.minSyncIntervalSec}
                      max={XDP_ACCEL_LIMITS.maxSyncIntervalSec}
                      precision={0}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
              </Row>

              <Form.Item
                label="物理业务网卡列表"
                name="interfaces"
                dependencies={['enabled']}
                validateTrigger={['onChange', 'onBlur']}
                rules={[
                  {
                    validator: async (_, value: string[] | undefined) => {
                      const err = validateXdpInterfaces(
                        value,
                        Boolean(form.getFieldValue('enabled')),
                      )
                      if (err) {
                        throw new Error(err)
                      }
                    },
                  },
                ]}
                extra={`输入物理业务网卡名后按回车添加（如 eth0、ens192、enp3s0f0，最多 ${XDP_ACCEL_LIMITS.maxInterfaces} 个）；自动拒绝 lo 及 docker*/br-*/veth*/virbr*/cni*/flannel*/cali*/tun*/tap*/wg* 虚拟网口。`}
              >
                <Select
                  mode="tags"
                  tokenSeparators={[',', ' ']}
                  placeholder="输入物理业务网卡名称（如 eth0、ens192）并回车"
                  open={false}
                  suffixIcon={null}
                />
              </Form.Item>

              {enabledWatch && (
                <Typography.Paragraph
                  type="secondary"
                  style={{ marginTop: -8, marginBottom: 16, fontSize: 12 }}
                >
                  已开启 XDP 加速：至少需配置 1 个物理业务网卡；保存后控制面会立即尝试推送全量黑名单与受保护地址排除列表至守护进程。
                </Typography.Paragraph>
              )}

              <Form.Item
                label="Unix Socket 路径"
                name="socket_path"
                validateTrigger={['onChange', 'onBlur']}
                rules={[
                  {
                    validator: async (_, value: string | undefined) => {
                      const err = validateXdpSocketPath(value)
                      if (err) {
                        throw new Error(err)
                      }
                    },
                  },
                ]}
                extra={`仅允许 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 目录下的本地 Unix Socket 路径（默认 ${XDP_ACCEL_LIMITS.defaultSocketPath}），严禁 TCP/HTTP 地址。`}
              >
                <Input
                  maxLength={XDP_ACCEL_LIMITS.maxSocketPathLen}
                  placeholder={XDP_ACCEL_LIMITS.defaultSocketPath}
                />
              </Form.Item>

              {canManage && (
                <Form.Item
                  label="变更原因"
                  name="reason"
                  rules={[
                    {
                      max: XDP_ACCEL_LIMITS.maxReasonLen,
                      message: `变更原因不能超过 ${XDP_ACCEL_LIMITS.maxReasonLen} 字符`,
                    },
                  ]}
                >
                  <Input.TextArea
                    rows={2}
                    maxLength={XDP_ACCEL_LIMITS.maxReasonLen}
                    showCount
                    placeholder="选填：记录本次调整 XDP 内核加速配置的变更原因（写入操作审计）"
                  />
                </Form.Item>
              )}

              {canManage && (
                <Form.Item style={{ marginBottom: 0 }}>
                  <Space size={12} wrap>
                    <Button
                      type="primary"
                      htmlType="submit"
                      icon={<SaveOutlined />}
                      loading={saveMutation.isPending}
                    >
                      保存配置
                    </Button>
                    <Button
                      icon={<SyncOutlined />}
                      loading={syncMutation.isPending}
                      onClick={() => syncMutation.mutate()}
                    >
                      立即同步黑名单至 XDP
                    </Button>
                  </Space>
                </Form.Item>
              )}
            </Form>
          </div>
        )}
      </Card>
    </div>
  )
}
