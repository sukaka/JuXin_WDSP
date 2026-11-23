import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import SmartTable from '../../components/SmartTable'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { ApiError } from '../../api/client'
import {
  notificationChannelsApi,
  type NotificationChannelBody,
} from '../../api/notificationChannels'
import { settingsApi } from '../../api/settings'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type {
  NotificationChannel,
  NotificationChannelType,
  NotificationSeverity,
} from '../../types'

/** 渠道类型中文映射 */
const CHANNEL_TYPE_META: Record<string, { color: string; label: string }> = {
  wecom: { color: 'green', label: '企业微信' },
  feishu: { color: 'blue', label: '飞书' },
  smtp: { color: 'purple', label: '邮件' },
  syslog: { color: 'default', label: 'syslog' },
  sms: { color: 'orange', label: '短信' },
}

const CHANNEL_TYPE_OPTIONS: { value: NotificationChannelType; label: string }[] = [
  { value: 'wecom', label: '企业微信' },
  { value: 'feishu', label: '飞书' },
  { value: 'smtp', label: '邮件（SMTP）' },
  { value: 'syslog', label: 'syslog' },
  { value: 'sms', label: '短信' },
]

/** 通知级别中文映射 */
const NOTIFY_SEVERITY_META: Record<string, { color: string; label: string }> = {
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
  CRITICAL: { color: '#7f1d1d', label: '严重' },
}

const SMTP_SECURITY_OPTIONS = [
  { value: 'none', label: '无加密' },
  { value: 'starttls', label: 'STARTTLS' },
  { value: 'ssl', label: 'SSL/TLS' },
]

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const PHONE_RE = /^1[3-9]\d{9}$/

interface ChannelFormValues {
  name: string
  type: NotificationChannelType
  min_severity: NotificationSeverity
  categories?: string[]
  // wecom / feishu
  webhook_url?: string
  mention_all?: boolean
  secret?: string
  // smtp
  host?: string
  port?: number
  security?: 'none' | 'starttls' | 'ssl'
  username?: string
  password?: string
  from?: string
  to?: string[]
  // sms
  gateway_url?: string
  app_key?: string
  app_secret?: string
  template_id?: string
  phones?: string[]
}

/** 按渠道类型提取 config；空值不提交，密值掩码 ******** 原样透传表示不修改原值 */
function buildConfig(values: ChannelFormValues): Record<string, unknown> {
  const pick = (entries: [string, unknown][]) => {
    const config: Record<string, unknown> = {}
    for (const [key, value] of entries) {
      if (value === undefined || value === '') continue
      config[key] = value
    }
    return config
  }
  switch (values.type) {
    case 'wecom':
      return pick([
        ['webhook_url', values.webhook_url],
        ['mention_all', values.mention_all ?? false],
      ])
    case 'feishu':
      return pick([
        ['webhook_url', values.webhook_url],
        ['secret', values.secret],
      ])
    case 'smtp':
      return pick([
        ['host', values.host],
        ['port', values.port],
        ['security', values.security],
        ['username', values.username],
        ['password', values.password],
        ['from', values.from],
        ['to', values.to],
      ])
    case 'syslog':
      return {}
    case 'sms':
      return pick([
        ['gateway_url', values.gateway_url],
        ['app_key', values.app_key],
        ['app_secret', values.app_secret],
        ['template_id', values.template_id],
        ['phones', values.phones],
      ])
  }
}

/* ---------- 风暴抑制参数（走系统设置 notify 分组） ---------- */

interface SuppressionDef {
  key: string
  label: string
  description: string
  def: string
  min?: number
  max?: number
  boolean?: boolean
}

const SUPPRESSION_DEFS: SuppressionDef[] = [
  {
    key: 'notify_rate_limit_per_minute',
    label: '速率限制（条/分钟）',
    description: '每渠道每分钟最多发送的告警通知条数，超出部分按聚合窗口合并摘要',
    def: '10',
    min: 1,
    max: 1000,
  },
  {
    key: 'notify_mute_minutes',
    label: '免打扰（分钟）',
    description: '同一告警在 N 分钟内不重复通知',
    def: '30',
    min: 0,
    max: 1440,
  },
  {
    key: 'notify_group_window_seconds',
    label: '聚合窗口（秒）',
    description: '超出速率限制的告警合并为摘要通知的时间窗口',
    def: '60',
    min: 0,
    max: 3600,
  },
  {
    key: 'notify_resolved',
    label: '恢复通知',
    description: '告警恢复时也向订阅渠道发送通知',
    def: 'false',
    boolean: true,
  },
]

function coerceSuppressionValue(def: SuppressionDef, raw: string): number | boolean {
  if (def.boolean) return raw === 'true'
  return Number(raw)
}

function SuppressionPanel({ canUpdate }: { canUpdate: boolean }) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const listQuery = useQuery({
    queryKey: ['settings', 'notify'],
    queryFn: () => settingsApi.list('notify'),
  })
  const [drafts, setDrafts] = useState<Record<string, string>>({})
  const [initialized, setInitialized] = useState(false)

  useEffect(() => {
    if (!listQuery.data || initialized) return
    const items = listQuery.data.items ?? []
    const next: Record<string, string> = {}
    for (const def of SUPPRESSION_DEFS) {
      const raw = items.find((i) => i.setting_key === def.key)?.setting_value
      next[def.key] = raw !== undefined && raw !== null ? String(raw) : def.def
    }
    setDrafts(next)
    setInitialized(true)
  }, [listQuery.data, initialized])

  const saveMutation = useMutation({
    mutationFn: async () => {
      const items = listQuery.data?.items ?? []
      await Promise.all(
        SUPPRESSION_DEFS.map((def) =>
          settingsApi.update({
            setting_group: 'notify',
            setting_key: def.key,
            setting_value: coerceSuppressionValue(def, drafts[def.key] ?? def.def),
            version: items.find((i) => i.setting_key === def.key)?.version ?? 0,
          }),
        ),
      )
    },
    onSuccess: () => {
      message.success('抑制参数已保存')
      void queryClient.invalidateQueries({ queryKey: ['settings', 'notify'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const handleSave = () => {
    for (const def of SUPPRESSION_DEFS) {
      if (def.boolean) continue
      const raw = (drafts[def.key] ?? def.def).trim()
      const n = Number(raw)
      if (raw === '' || !Number.isInteger(n)) {
        message.error(`${def.label}需为有效整数`)
        return
      }
      if ((def.min !== undefined && n < def.min) || (def.max !== undefined && n > def.max)) {
        message.error(`${def.label}需在 ${def.min ?? '-∞'}~${def.max ?? '+∞'} 之间`)
        return
      }
    }
    saveMutation.mutate()
  }

  if (listQuery.isError) {
    return <QueryErrorAlert error={listQuery.error} message="加载抑制参数失败" />
  }

  return (
    <Space direction="vertical" size={12} style={{ display: 'flex' }}>
      {SUPPRESSION_DEFS.map((def) => (
        <Space key={def.key} wrap>
          <Typography.Text style={{ width: 180, display: 'inline-block' }}>
            {def.label}
          </Typography.Text>
          {def.boolean ? (
            <Switch
              checked={(drafts[def.key] ?? def.def) === 'true'}
              disabled={!canUpdate}
              onChange={(checked) =>
                setDrafts((d) => ({ ...d, [def.key]: checked ? 'true' : 'false' }))
              }
            />
          ) : (
            <InputNumber
              value={(drafts[def.key] ?? def.def) === '' ? null : Number(drafts[def.key] ?? def.def)}
              min={def.min}
              max={def.max}
              precision={0}
              disabled={!canUpdate}
              onChange={(v) => setDrafts((d) => ({ ...d, [def.key]: v === null ? '' : String(v) }))}
              style={{ width: 160 }}
            />
          )}
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {def.description}
          </Typography.Text>
        </Space>
      ))}
      {canUpdate && (
        <Button
          type="primary"
          style={{ alignSelf: 'flex-start' }}
          loading={saveMutation.isPending}
          onClick={handleSave}
        >
          保存
        </Button>
      )}
    </Space>
  )
}

/** 告警通知：通知渠道管理 + 风暴抑制参数（notification.read / notification.update / notification.test） */
export default function AlertNotificationsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'notification.update')
  const canTest = hasPermission(permissions, 'notification.test')

  /* ---------- 查询 ---------- */
  const metaQuery = useQuery({ queryKey: ['notification-meta'], queryFn: notificationChannelsApi.meta })
  const channelsQuery = useQuery({
    queryKey: ['notification-channels'],
    queryFn: notificationChannelsApi.list,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<NotificationChannel>({
    remove: (id) => notificationChannelsApi.remove(id),
    invalidateKeys: [['notification-channels']],
    entityName: '通知渠道',
    canDelete: canUpdate,
  })

  /* ---------- 弹窗状态 ---------- */
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<NotificationChannel | null>(null)
  const [detailRecord, setDetailRecord] = useState<NotificationChannel | null>(null)
  const [form] = Form.useForm<ChannelFormValues>()
  const formType = Form.useWatch('type', form)

  const validateWebhookUrl = (_: unknown, value: string | undefined) => {
    const raw = value ?? ''
    if (!raw.trim()) return Promise.resolve()
    if (editing !== null && raw === '********') return Promise.resolve()
    try {
      const parsed = new URL(raw.trim())
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return Promise.resolve()
      }
    } catch {
      // ignore invalid URL parse errors
    }
    return Promise.reject(new Error('Webhook 地址格式不正确'))
  }

  const invalidateChannels = () =>
    queryClient.invalidateQueries({ queryKey: ['notification-channels'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  /* ---------- 写操作 ---------- */
  const saveMutation = useMutation({
    mutationFn: (values: ChannelFormValues) => {
      const body: NotificationChannelBody = {
        name: values.name,
        type: values.type,
        enabled: editing ? editing.enabled : true,
        min_severity: values.min_severity,
        categories: values.categories ?? [],
        config: buildConfig(values),
      }
      return editing
        ? notificationChannelsApi.update(editing.id, body)
        : notificationChannelsApi.create(body)
    },
    onSuccess: () => {
      message.success(editing ? '渠道已更新' : '渠道已创建')
      setModalOpen(false)
      setEditing(null)
      form.resetFields()
      void invalidateChannels()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => notificationChannelsApi.remove(id),
    onSuccess: (data) => {
      message.success(data.message || '渠道已删除')
      void invalidateChannels()
    },
    onError,
  })

  const testMutation = useMutation({
    mutationFn: (id: string) => notificationChannelsApi.test(id),
    onSuccess: (data) => {
      message.success(data.message || '测试消息已发送')
    },
    onError,
  })

  const toggleMutation = useMutation({
    mutationFn: (record: NotificationChannel) =>
      // config 原样回传：密值掩码 ******** 表示不修改原值
      notificationChannelsApi.update(record.id, {
        name: record.name,
        type: record.type,
        enabled: !record.enabled,
        min_severity: record.min_severity,
        categories: record.categories,
        config: record.config,
      }),
    onSuccess: () => {
      message.success('启用状态已更新')
      void invalidateChannels()
    },
    onError,
  })

  /* ---------- 弹窗打开 ---------- */
  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    setModalOpen(true)
  }

  const openEdit = (record: NotificationChannel) => {
    setEditing(record)
    form.resetFields()
    const c = record.config
    form.setFieldsValue({
      name: record.name,
      type: record.type,
      min_severity: record.min_severity,
      categories: record.categories,
      webhook_url: typeof c.webhook_url === 'string' ? c.webhook_url : undefined,
      mention_all: c.mention_all === true,
      secret: typeof c.secret === 'string' ? c.secret : undefined,
      host: typeof c.host === 'string' ? c.host : undefined,
      port: typeof c.port === 'number' ? c.port : undefined,
      security:
        c.security === 'none' || c.security === 'starttls' || c.security === 'ssl'
          ? c.security
          : undefined,
      username: typeof c.username === 'string' ? c.username : undefined,
      password: typeof c.password === 'string' ? c.password : undefined,
      from: typeof c.from === 'string' ? c.from : undefined,
      to: Array.isArray(c.to) ? (c.to as string[]) : undefined,
      gateway_url: typeof c.gateway_url === 'string' ? c.gateway_url : undefined,
      app_key: typeof c.app_key === 'string' ? c.app_key : undefined,
      app_secret: typeof c.app_secret === 'string' ? c.app_secret : undefined,
      template_id: typeof c.template_id === 'string' ? c.template_id : undefined,
      phones: Array.isArray(c.phones) ? (c.phones as string[]) : undefined,
    })
    setModalOpen(true)
  }

  /* ---------- 选项与映射 ---------- */
  const categoryNameMap = new Map(
    (metaQuery.data?.categories ?? []).map((c) => [c.code, c.name]),
  )
  const categoryOptions = (metaQuery.data?.categories ?? []).map((c) => ({
    value: c.code,
    label: c.name,
  }))
  const severityOptions = (
    metaQuery.data?.severities ?? ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
  ).map((s) => ({ value: s, label: NOTIFY_SEVERITY_META[s]?.label ?? s }))

  /* ---------- 渠道表格 ---------- */
  const columns: ColumnsType<NotificationChannel> = [
    { title: '名称', dataIndex: 'name', width: 160, ellipsis: true },
    {
      title: '类型',
      dataIndex: 'type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={CHANNEL_TYPE_META} />,
    },
    {
      title: '订阅级别',
      dataIndex: 'min_severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={NOTIFY_SEVERITY_META} />,
    },
    {
      title: '订阅类别',
      dataIndex: 'categories',
      width: 240,
      render: (codes: string[]) => {
        if (!codes || codes.length === 0) return <Tag>全部类别</Tag>
        const text = codes.map((c) => categoryNameMap.get(c) ?? c).join('，')
        return (
          <Tooltip title={text} placement="topLeft">
            <Typography.Text
              style={{
                display: 'block',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {text}
            </Typography.Text>
          </Tooltip>
        )
      },
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean, record) => (
        <Switch
          checked={v}
          disabled={!canUpdate}
          loading={toggleMutation.isPending && toggleMutation.variables?.id === record.id}
          onChange={() => toggleMutation.mutate(record)}
        />
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      fixed: 'right',
      render: (_, record) =>
        canTest || canUpdate ? (
          <Space size={0}>
            {canTest && (
              <Button
                type="link"
                size="small"
                loading={testMutation.isPending && testMutation.variables === record.id}
                onClick={() => testMutation.mutate(record.id)}
              >
                测试
              </Button>
            )}
            {canUpdate && (
              <>
                <Button type="link" size="small" onClick={() => openEdit(record)}>
                  编辑
                </Button>
                <Popconfirm
                  title={`确定删除渠道「${record.name}」吗？`}
                  onConfirm={() => deleteMutation.mutate(record.id)}
                >
                  <Button type="link" size="small" danger>
                    删除
                  </Button>
                </Popconfirm>
              </>
            )}
          </Space>
        ) : (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            仅查看
          </Typography.Text>
        ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Alert
        type="info"
        showIcon
        message="告警通知在系统告警新建时触发，按渠道订阅的最低级别与类别，推送至企业微信、飞书、邮件或 syslog。"
      />
      <Card
        title="渠道管理"
        extra={
          canUpdate && (
            <Space>
              {batchDeleteButton}
              <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
                新增渠道
              </Button>
            </Space>
          )
        }
      >
        {channelsQuery.isError ? (
          <QueryErrorAlert error={channelsQuery.error} message="加载通知渠道失败" />
        ) : (
          <SmartTable<NotificationChannel>
            storageKey="alert-notifications"
            rowKey="id"
            rowSelection={rowSelection}
            loading={channelsQuery.isLoading}
            columns={columns}
            dataSource={channelsQuery.data}
            scroll={{ x: 1080 }}
            onRow={(record) => ({
              onDoubleClick: () => setDetailRecord(record),
              style: { cursor: 'pointer' },
            })}
            pagination={false}
          />
        )}
      </Card>

      <Card title="风暴抑制参数">
        <SuppressionPanel canUpdate={canUpdate} />
      </Card>

      <Modal
        title={editing ? '编辑渠道' : '新增渠道'}
        open={modalOpen}
        width={640}
        onCancel={() => {
          setModalOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        confirmLoading={saveMutation.isPending}
        destroyOnHidden
      >
        <Form<ChannelFormValues>
          form={form}
          layout="vertical"
          initialValues={{
            type: 'wecom',
            min_severity: 'MEDIUM',
            categories: [],
            mention_all: false,
            security: 'starttls',
          }}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Form.Item
            name="name"
            label="名称"
            rules={[
              { required: true, message: '请输入名称' },
              { max: 100, message: '不超过 100 个字符' },
            ]}
          >
            <Input placeholder="如：运维值班群机器人" />
          </Form.Item>
          <Form.Item name="type" label="类型" rules={[{ required: true, message: '请选择类型' }]}>
            <Select
              options={CHANNEL_TYPE_OPTIONS}
              placeholder="选择渠道类型"
              disabled={editing !== null}
            />
          </Form.Item>
          <Form.Item
            name="min_severity"
            label="最低级别"
            rules={[{ required: true, message: '请选择最低级别' }]}
            extra="仅向该渠道发送达到此级别的告警"
          >
            <Select options={severityOptions} />
          </Form.Item>
          <Form.Item name="categories" label="订阅类别" extra="不勾选表示订阅全部类别">
            <Checkbox.Group options={categoryOptions} />
          </Form.Item>

          {formType === 'wecom' && (
            <>
              <Form.Item
                name="webhook_url"
                label="Webhook 地址"
                rules={[
                  { required: true, message: '请输入 Webhook 地址' },
                  { validator: validateWebhookUrl },
                ]}
                extra={editing ? '保持 ******** 不变表示不修改原值' : undefined}
              >
                <Input
                  placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."
                  autoComplete="off"
                />
              </Form.Item>
              <Form.Item name="mention_all" label="@所有人" valuePropName="checked">
                <Switch />
              </Form.Item>
            </>
          )}
          {formType === 'feishu' && (
            <>
              <Form.Item
                name="webhook_url"
                label="Webhook 地址"
                rules={[
                  { required: true, message: '请输入 Webhook 地址' },
                  { validator: validateWebhookUrl },
                ]}
                extra={editing ? '保持 ******** 不变表示不修改原值' : undefined}
              >
                <Input
                  placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..."
                  autoComplete="off"
                />
              </Form.Item>
              <Form.Item
                name="secret"
                label="签名密钥（可选）"
                extra={editing ? '保持 ******** 不变表示不修改原值' : undefined}
              >
                <Input.Password placeholder="飞书机器人签名校验密钥" autoComplete="new-password" />
              </Form.Item>
            </>
          )}
          {formType === 'smtp' && (
            <>
              <Form.Item
                name="host"
                label="SMTP 服务器"
                rules={[{ required: true, message: '请输入 SMTP 服务器' }]}
              >
                <Input placeholder="如 smtp.example.com" autoComplete="off" />
              </Form.Item>
              <Form.Item
                name="port"
                label="端口"
                rules={[{ required: true, message: '请输入端口' }]}
              >
                <InputNumber min={1} max={65535} style={{ width: '100%' }} placeholder="1-65535" />
              </Form.Item>
              <Form.Item
                name="security"
                label="加密方式"
                rules={[{ required: true, message: '请选择加密方式' }]}
              >
                <Select options={SMTP_SECURITY_OPTIONS} />
              </Form.Item>
              <Form.Item name="username" label="用户名">
                <Input placeholder="SMTP 认证用户名（可选）" autoComplete="off" />
              </Form.Item>
              <Form.Item
                name="password"
                label="密码"
                extra={editing ? '保持 ******** 不变表示不修改原值' : undefined}
              >
                <Input.Password placeholder="SMTP 认证密码（可选）" autoComplete="new-password" />
              </Form.Item>
              <Form.Item
                name="from"
                label="发件人"
                rules={[
                  { required: true, message: '请输入发件人地址' },
                  { type: 'email', message: '发件人邮箱格式不正确' },
                ]}
              >
                <Input placeholder="如 waf-alert@example.com" autoComplete="off" />
              </Form.Item>
              <Form.Item
                name="to"
                label="收件人"
                rules={[
                  { required: true, message: '请输入收件人邮箱' },
                  {
                    validator: (_, value: string[] | undefined) => {
                      const invalid = (value ?? []).filter((v) => !EMAIL_RE.test(v))
                      return invalid.length > 0
                        ? Promise.reject(new Error(`收件人邮箱格式不正确：${invalid.join('，')}`))
                        : Promise.resolve()
                    },
                  },
                ]}
                extra="输入邮箱后回车添加，可添加多个"
              >
                <Select
                  mode="tags"
                  open={false}
                  placeholder="如 ops@example.com"
                  tokenSeparators={[',', ' ', ';']}
                />
              </Form.Item>
            </>
          )}
          {formType === 'syslog' && (
            <Alert
              type="info"
              showIcon
              message="syslog 渠道沿用系统设置「日志设置」组的 syslog 配置，无需额外参数。"
            />
          )}
          {formType === 'sms' && (
            <>
              <Form.Item
                name="gateway_url"
                label="网关地址"
                rules={[
                  { required: true, message: '请输入短信网关地址' },
                  { type: 'url', message: '网关地址格式不正确' },
                  {
                    pattern: /^https?:\/\//i,
                    message: '网关地址需以 http:// 或 https:// 开头',
                  },
                ]}
              >
                <Input placeholder="https://sms-gateway.example.com/send" autoComplete="off" />
              </Form.Item>
              <Form.Item
                name="app_key"
                label="App Key"
                rules={[{ required: true, message: '请输入 App Key' }]}
              >
                <Input placeholder="短信网关分配的 App Key" autoComplete="off" />
              </Form.Item>
              <Form.Item
                name="app_secret"
                label="App Secret"
                extra={editing ? '保持 ******** 不变表示不修改原值' : undefined}
              >
                <Input.Password
                  placeholder="短信网关签名密钥（可选）"
                  autoComplete="new-password"
                />
              </Form.Item>
              <Form.Item
                name="template_id"
                label="模板 ID"
                rules={[{ required: true, message: '请输入模板 ID' }]}
              >
                <Input placeholder="短信模板 ID" autoComplete="off" />
              </Form.Item>
              <Form.Item
                name="phones"
                label="手机号列表"
                rules={[
                  { required: true, message: '请输入至少 1 个手机号' },
                  {
                    validator: (_, value: string[] | undefined) => {
                      if (!value || value.length === 0) {
                        return Promise.reject(new Error('请输入至少 1 个手机号'))
                      }
                      const invalid = value.filter((v) => !PHONE_RE.test(v))
                      return invalid.length > 0
                        ? Promise.reject(new Error(`手机号格式不正确：${invalid.join('，')}`))
                        : Promise.resolve()
                    },
                  },
                ]}
                extra="输入手机号后回车添加，可添加多个"
              >
                <Select
                  mode="tags"
                  open={false}
                  placeholder="如 13800138000"
                  tokenSeparators={[',', ' ', ';']}
                />
              </Form.Item>
              <Typography.Paragraph
                type="secondary"
                style={{ fontSize: 12, marginTop: -8 }}
              >
                通用 HTTP 网关协议（POST JSON：app_key/template_id/phones/params；配置 app_secret
                时带 X-App-Key 与 X-Sign 签名头），对接具体厂商网关需按其协议适配。
              </Typography.Paragraph>
            </>
          )}
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="通知渠道详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Space>
  )
}
