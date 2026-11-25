import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Drawer,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Radio,
  Row,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CheckCircleFilled,
  MinusCircleOutlined,
  PlusOutlined,
  SaveOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { headerConfigApi, pathRoutesApi } from '../../../api/applications'
import type {
  PathRouteBody,
  UpdatePathRouteBody,
} from '../../../api/applications'
import RecordDetailDrawer from '../../../components/RecordDetailDrawer'
import SmartTable from '../../../components/SmartTable'
import useBatchDelete from '../../../hooks/useBatchDelete'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import type { AppHeaderConfig, AppPathRoute } from '../../../types'
import { InlineNote, SectionHeader } from './DetailTabPrimitives'
import './detailTab.css'

/** 与数据库迁移默认值一致的初始配置（后端 configured=false 时前端按此展示） */
const DEFAULT_CONFIG: AppHeaderConfig = {
  server_action: 'keep',
  server_value: '',
  x_author_action: 'keep',
  x_author_value: '',
  x_powered_by_action: 'keep',
  x_powered_by_value: '',
  x_frame_options: 'default',
  x_frame_options_url: '',
  x_xss_protection: false,
  vary_user_agent: false,
  hsts_enabled: false,
  hsts_max_age: 31536000,
  csp_mode: 'off',
  csp_value: '',
  response_buffering: false,
  xff_overwrite: true,
  host_strip_port: false,
  accept_encoding_off: false,
  redirect_port_rewrite: false,
  custom_request_rules: [],
  custom_response_rules: [],
}

const HEADER_ACTION_OPTIONS = [
  { value: 'keep', label: '保持原样' },
  { value: 'hide', label: '隐藏' },
  { value: 'replace', label: '替换为自定义值' },
]

const X_FRAME_OPTIONS = [
  { value: 'default', label: '默认（DENY）' },
  { value: 'inherit', label: '透传源站' },
  { value: 'deny', label: 'DENY' },
  { value: 'sameorigin', label: 'SAMEORIGIN' },
  { value: 'allow_from', label: 'ALLOW-FROM（指定来源）' },
]

const CSP_MODE_OPTIONS = [
  { value: 'off', label: '关闭' },
  { value: 'preset', label: '预设基础档' },
  { value: 'custom', label: '自定义' },
]

const RULE_METHOD_OPTIONS = [
  { value: 'set', label: '覆盖' },
  { value: 'add', label: '新增' },
  { value: 'delete', label: '删除' },
]

/** 与后端一致的 host 前端校验：IP 或域名，不含协议/路径/端口 */
function validateHost(value: string): string | null {
  const v = value.trim().toLowerCase()
  if (!v) return '请输入主机地址'
  if (v.includes('://') || v.includes('/') || v.includes(':'))
    return '主机地址不含协议、路径或端口'
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
  if (ipv4.test(v)) {
    const ok = v.split('.').every((n) => Number(n) <= 255)
    return ok ? null : 'IP 地址格式不正确'
  }
  const label = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
  if (!v.split('.').every((l) => label.test(l))) return '主机名格式不正确'
  return null
}

function formatHstsDuration(seconds: number | undefined): string | null {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0)
    return null
  if (seconds >= 86400) {
    const days = Math.round((seconds / 86400) * 10) / 10
    return `约 ${days} 天`
  }
  if (seconds >= 3600) {
    return `约 ${Math.round(seconds / 3600)} 小时`
  }
  return `${seconds} 秒`
}

interface PathRouteFormValues {
  path_prefix: string
  upstream_scheme: 'http' | 'https'
  upstream_host: string
  upstream_port: number
  strip_prefix: boolean
  priority: number
  /** 表单内用布尔表示：true = ENABLED */
  enabled: boolean
  description: string
}

const ROUTE_DEFAULT_VALUES: PathRouteFormValues = {
  path_prefix: '',
  upstream_scheme: 'http',
  upstream_host: '',
  upstream_port: 80,
  strip_prefix: false,
  priority: 100,
  enabled: true,
  description: '',
}

const PROXY_SWITCH_ITEMS: {
  name: keyof AppHeaderConfig
  label: string
  description: string
}[] = [
  {
    name: 'response_buffering',
    label: '响应缓冲',
    description: '开启后缓冲源站响应再返回客户端',
  },
  {
    name: 'xff_overwrite',
    label: 'X-Forwarded-For 上一跳覆盖',
    description: '以直接对端地址覆盖 XFF 链路头',
  },
  {
    name: 'host_strip_port',
    label: 'Host 不包含端口',
    description: '转发回源时去掉 Host 头中的端口号',
  },
  {
    name: 'accept_encoding_off',
    label: 'Accept-Encoding 关闭',
    description: '向源站关闭压缩协商（identity）',
  },
  {
    name: 'redirect_port_rewrite',
    label: '302重定向端口改写',
    description: '将响应 Location 端口改写为接入端口',
  },
]

export default function HeaderProxyTab({ appId }: { appId: string }) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'applications.update')

  // ---------- 头合规 + 代理配置（同一表单，一起保存） ----------
  const [headerForm] = Form.useForm<AppHeaderConfig>()
  const [configVersion, setConfigVersion] = useState(1)
  const xAuthorAction = Form.useWatch('x_author_action', headerForm)
  const xFrameOptions = Form.useWatch('x_frame_options', headerForm)
  const hstsEnabled = Form.useWatch('hsts_enabled', headerForm)
  const hstsMaxAge = Form.useWatch('hsts_max_age', headerForm)
  const xssEnabled = Form.useWatch('x_xss_protection', headerForm)
  const varyUaEnabled = Form.useWatch('vary_user_agent', headerForm)
  const cspMode = Form.useWatch('csp_mode', headerForm)
  const customReqRules = Form.useWatch('custom_request_rules', headerForm) ?? []
  const customRespRules =
    Form.useWatch('custom_response_rules', headerForm) ?? []

  const configQuery = useQuery({
    queryKey: ['header-config', appId],
    queryFn: () => headerConfigApi.get(appId),
  })

  useEffect(() => {
    const data = configQuery.data
    if (!data) return
    setConfigVersion(data.version ?? 1)
    headerForm.setFieldsValue({
      ...DEFAULT_CONFIG,
      ...data.config,
      hsts_max_age:
        data.config?.hsts_max_age && data.config.hsts_max_age > 0
          ? data.config.hsts_max_age
          : DEFAULT_CONFIG.hsts_max_age,
      // Go nil slice 会序列化为 null，统一归一化为空数组
      custom_request_rules: data.config?.custom_request_rules ?? [],
      custom_response_rules: data.config?.custom_response_rules ?? [],
    })
  }, [configQuery.data, headerForm])

  const invalidateConfig = () =>
    void queryClient.invalidateQueries({ queryKey: ['header-config', appId] })

  const saveConfigMutation = useMutation({
    mutationFn: (body: AppHeaderConfig) =>
      headerConfigApi.update(appId, { ...body, version: configVersion }),
    onSuccess: (data) => {
      if (data?.version) setConfigVersion(data.version)
      message.success('保存成功')
      invalidateConfig()
    },
    onError: (e) => {
      if (
        e instanceof ApiError &&
        (e.status === 409 || e.code === 'RESOURCE_CONFLICT')
      ) {
        message.warning('配置已被他人修改，请刷新后重试')
        invalidateConfig()
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const onSaveConfig = (values: AppHeaderConfig) => {
    const storedMaxAge = headerForm.getFieldValue('hsts_max_age') as
      | number
      | undefined
    const loadedMaxAge = configQuery.data?.config?.hsts_max_age
    const resolvedMaxAge =
      values.hsts_max_age && values.hsts_max_age > 0
        ? values.hsts_max_age
        : storedMaxAge && storedMaxAge > 0
          ? storedMaxAge
          : loadedMaxAge && loadedMaxAge > 0
            ? loadedMaxAge
            : DEFAULT_CONFIG.hsts_max_age

    saveConfigMutation.mutate({
      ...values,
      server_action: 'hide',
      server_value: '',
      x_author_value:
        values.x_author_action === 'replace'
          ? (values.x_author_value ?? '')
          : '',
      x_powered_by_action: 'hide',
      x_powered_by_value: '',
      x_frame_options_url:
        values.x_frame_options === 'allow_from'
          ? (values.x_frame_options_url ?? '')
          : '',
      hsts_max_age: resolvedMaxAge,
      csp_value: values.csp_mode === 'custom' ? (values.csp_value ?? '') : '',
      custom_request_rules: (values.custom_request_rules ?? []).map((r) => ({
        ...r,
        value: r.method === 'delete' ? '' : (r.value ?? ''),
      })),
      custom_response_rules: (values.custom_response_rules ?? []).map((r) => ({
        ...r,
        value: r.method === 'delete' ? '' : (r.value ?? ''),
      })),
    })
  }

  const renderRuleList = (
    listName: 'custom_request_rules' | 'custom_response_rules',
    title: string,
    count: number,
    emptyHint: string,
  ) => (
    <div style={{ marginTop: 18 }}>
      <SectionHeader
        title={title}
        badge={<Tag style={{ marginInlineEnd: 0 }}>{count} 条</Tag>}
      />
      <Form.List name={listName}>
        {(fields, { add, remove }) => (
          <div className="jz-detail-rule-box">
            {fields.length > 0 ? (
              <>
                <Row gutter={12} className="jz-detail-rule-header">
                  <Col xs={24} md={7}>
                    头名称
                  </Col>
                  <Col xs={24} md={5}>
                    修改方式
                  </Col>
                  <Col xs={24} md={10}>
                    头值内容
                  </Col>
                  <Col xs={24} md={2} style={{ textAlign: 'right' }} />
                </Row>
                {fields.map((field) => (
                  <Row
                    key={field.key}
                    gutter={[12, 8]}
                    align="middle"
                    className="jz-detail-rule-row"
                  >
                    <Col xs={24} md={7}>
                      <Form.Item
                        name={[field.name, 'name']}
                        style={{ marginBottom: 0 }}
                        rules={[
                          { required: true, message: '请输入头名称' },
                          {
                            pattern: /^[A-Za-z0-9-]+$/,
                            message: '头名称只能包含字母、数字、短横线',
                          },
                        ]}
                      >
                        <Input
                          placeholder="头名称，如 X-Request-Id"
                          autoComplete="off"
                        />
                      </Form.Item>
                    </Col>
                    <Col xs={24} md={5}>
                      <Form.Item
                        name={[field.name, 'method']}
                        style={{ marginBottom: 0 }}
                        rules={[{ required: true }]}
                      >
                        <Select
                          options={RULE_METHOD_OPTIONS}
                          placeholder="修改方式"
                          style={{ width: '100%' }}
                        />
                      </Form.Item>
                    </Col>
                    <Col xs={20} md={10}>
                      <Form.Item
                        noStyle
                        shouldUpdate={(
                          prev: AppHeaderConfig,
                          cur: AppHeaderConfig,
                        ) =>
                          prev[listName]?.[field.name]?.method !==
                          cur[listName]?.[field.name]?.method
                        }
                      >
                        {({ getFieldValue }) => {
                          const isDelete =
                            getFieldValue([listName, field.name, 'method']) ===
                            'delete'
                          return (
                            <Form.Item
                              name={[field.name, 'value']}
                              style={{ marginBottom: 0 }}
                              rules={[
                                ({ getFieldValue: readField }) => ({
                                  validator(_, v: string) {
                                    const method = readField([
                                      listName,
                                      field.name,
                                      'method',
                                    ]) as string
                                    if (method === 'delete')
                                      return Promise.resolve()
                                    if (!v || !v.trim())
                                      return Promise.reject(
                                        new Error('请输入内容'),
                                      )
                                    return Promise.resolve()
                                  },
                                }),
                              ]}
                            >
                              <Input
                                disabled={isDelete}
                                placeholder={
                                  isDelete
                                    ? '删除头时无需填写内容'
                                    : '内容（删除时无需填写）'
                                }
                                autoComplete="off"
                              />
                            </Form.Item>
                          )
                        }}
                      </Form.Item>
                    </Col>
                    <Col xs={4} md={2} style={{ textAlign: 'right' }}>
                      <Tooltip title="删除此头修改规则">
                        <Button
                          type="text"
                          danger
                          icon={<MinusCircleOutlined />}
                          aria-label="删除此头修改规则"
                          onClick={() => remove(field.name)}
                        />
                      </Tooltip>
                    </Col>
                  </Row>
                ))}
              </>
            ) : (
              <div className="jz-detail-rule-empty">{emptyHint}</div>
            )}
            <Button
              block
              type="dashed"
              icon={<PlusOutlined />}
              style={{ marginTop: fields.length > 0 ? 10 : 0 }}
              onClick={() => add({ name: '', method: 'set', value: '' })}
            >
              添加规则
            </Button>
          </div>
        )}
      </Form.List>
    </div>
  )

  // ---------- 路径转发配置 ----------
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<AppPathRoute | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<AppPathRoute | null>(null)
  const [routeForm] = Form.useForm<PathRouteFormValues>()

  const routesQuery = useQuery({
    queryKey: ['path-routes', appId, page, pageSize],
    queryFn: () => pathRoutesApi.list(appId, { page, page_size: pageSize }),
  })

  const invalidateRoutes = () =>
    void queryClient.invalidateQueries({ queryKey: ['path-routes', appId] })

  const onRouteError = (e: unknown) => {
    if (
      e instanceof ApiError &&
      (e.status === 409 || e.code === 'RESOURCE_CONFLICT')
    ) {
      message.warning('数据已被他人修改，请刷新后重试')
      invalidateRoutes()
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveRouteMutation = useMutation({
    mutationFn: ({
      routeId,
      version,
      body,
    }: {
      routeId: string | null
      version?: number
      body: PathRouteBody
    }) =>
      routeId
        ? pathRoutesApi.update(appId, routeId, {
            ...body,
            version: version ?? 0,
          } satisfies UpdatePathRouteBody)
        : pathRoutesApi.create(appId, body),
    onSuccess: () => {
      setCreateOpen(false)
      setEditing(null)
      routeForm.resetFields()
      message.success('保存成功')
      invalidateRoutes()
    },
    onError: onRouteError,
  })

  const toggleRouteMutation = useMutation({
    mutationFn: (record: AppPathRoute) =>
      pathRoutesApi.update(appId, record.id, {
        path_prefix: record.path_prefix,
        upstream_scheme: record.upstream_scheme,
        upstream_host: record.upstream_host,
        upstream_port: record.upstream_port,
        strip_prefix: record.strip_prefix,
        priority: record.priority,
        status: record.status === 'ENABLED' ? 'DISABLED' : 'ENABLED',
        description: record.description ?? '',
        version: record.version,
      }),
    onSuccess: () => {
      message.success('操作成功')
      invalidateRoutes()
    },
    onError: onRouteError,
  })

  const removeRouteMutation = useMutation({
    mutationFn: (routeId: string) => pathRoutesApi.remove(appId, routeId),
    onSuccess: () => {
      message.success('删除成功')
      invalidateRoutes()
    },
    onError: onRouteError,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<AppPathRoute>({
    remove: (routeId) => pathRoutesApi.remove(appId, routeId),
    invalidateKeys: [['path-routes']],
    entityName: '路径路由',
    canDelete: canUpdate,
  })

  const openEditRoute = (record: AppPathRoute) => {
    setEditing(record)
    routeForm.setFieldsValue({
      path_prefix: record.path_prefix,
      upstream_scheme: record.upstream_scheme,
      upstream_host: record.upstream_host,
      upstream_port: record.upstream_port,
      strip_prefix: record.strip_prefix,
      priority: record.priority,
      enabled: record.status === 'ENABLED',
      description: record.description,
    })
  }

  const toRouteBody = (values: PathRouteFormValues): PathRouteBody => ({
    path_prefix: values.path_prefix.trim(),
    upstream_scheme: values.upstream_scheme,
    upstream_host: values.upstream_host.trim(),
    upstream_port: values.upstream_port,
    strip_prefix: values.strip_prefix ?? false,
    priority: values.priority ?? 100,
    status: values.enabled ? 'ENABLED' : 'DISABLED',
    description: values.description ?? '',
  })

  const routeColumns: ColumnsType<AppPathRoute> = [
    {
      title: '路径前缀',
      dataIndex: 'path_prefix',
      render: (v: string) => (
        <Tag
          color="geekblue"
          style={{
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
            marginInlineEnd: 0,
          }}
        >
          {v}
        </Tag>
      ),
    },
    {
      title: '源站',
      key: 'upstream',
      render: (_, r) => (
        <span
          style={{
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
            fontSize: 13,
          }}
        >
          {r.upstream_scheme}://{r.upstream_host}:{r.upstream_port}
        </span>
      ),
    },
    {
      title: '剥离前缀',
      dataIndex: 'strip_prefix',
      width: 96,
      render: (v: boolean) => (v ? <Tag color="blue">是</Tag> : <Tag>否</Tag>),
    },
    {
      title: '优先级',
      dataIndex: 'priority',
      width: 84,
      render: (v: number) => (
        <span
          style={{
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
          }}
        >
          {v}
        </span>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) =>
        v === 'ENABLED' ? <Tag color="green">启用</Tag> : <Tag>停用</Tag>,
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
      width: 170,
      render: (_, record) =>
        canUpdate ? (
          <Space size={4}>
            <Button
              type="link"
              size="small"
              onClick={() => openEditRoute(record)}
            >
              编辑
            </Button>
            <Button
              type="link"
              size="small"
              onClick={() => toggleRouteMutation.mutate(record)}
            >
              {record.status === 'ENABLED' ? '停用' : '启用'}
            </Button>
            <Popconfirm
              title="删除确认"
              description={`确定删除路径转发「${record.path_prefix}」吗？`}
              okButtonProps={{ danger: true }}
              onConfirm={() => removeRouteMutation.mutate(record.id)}
            >
              <Button type="link" size="small" danger>
                删除
              </Button>
            </Popconfirm>
          </Space>
        ) : (
          <span>-</span>
        ),
    },
  ]

  const routeDrawerOpen = createOpen || editing !== null
  const hstsDurationHint = formatHstsDuration(hstsMaxAge)
  const routeTotal = routesQuery.data?.total ?? 0

  return (
    <div className="jz-detail-tab">
      <Form<AppHeaderConfig>
        form={headerForm}
        layout="vertical"
        initialValues={DEFAULT_CONFIG}
        disabled={!canUpdate}
        onFinish={onSaveConfig}
      >
        <Space orientation="vertical" size={16} style={{ display: 'flex' }}>
          <Card
            className="jz-detail-card"
            title="HTTP头合规"
            extra={
              configQuery.data?.configured ? (
                <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                  版本 v{configVersion}
                </Tag>
              ) : (
                <Tag style={{ marginInlineEnd: 0 }}>默认基线</Tag>
              )
            }
          >
            {configQuery.isLoading ? (
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'center',
                  padding: 36,
                }}
              >
                <Spin />
              </div>
            ) : configQuery.isError ? (
              <Alert
                type="error"
                showIcon
                title="加载头合规配置失败"
                description={
                  configQuery.error instanceof ApiError
                    ? configQuery.error.message
                    : undefined
                }
              />
            ) : (
              <>
                <InlineNote tooltip="Server、Via、X-Powered-By、ASP.NET、MySQL、PostgreSQL、Redis/Valkey、ClickHouse 等版本头均由网关最终删除，自定义响应规则也不能恢复。">
                  <strong>中间件和数据库版本信息始终隐藏</strong>
                  ：网关内核已强制加固以下三项安全基线，始终生效且不可关闭。
                </InlineNote>

                <div className="jz-detail-baseline-strip">
                  <div className="jz-detail-baseline-item">
                    <div className="jz-detail-baseline-meta">
                      <span className="jz-detail-baseline-label">
                        <CheckCircleFilled
                          style={{ color: '#16a34a', marginRight: 6 }}
                        />
                        Server / Via 响应头
                      </span>
                      <span className="jz-detail-baseline-hint">
                        隐藏网关及代理服务器指纹
                      </span>
                    </div>
                    <Tag color="green" style={{ marginInlineEnd: 0 }}>
                      始终隐藏
                    </Tag>
                  </div>

                  <div className="jz-detail-baseline-item">
                    <div className="jz-detail-baseline-meta">
                      <span className="jz-detail-baseline-label">
                        <CheckCircleFilled
                          style={{ color: '#16a34a', marginRight: 6 }}
                        />
                        X-Powered-By / 数据库版本头
                      </span>
                      <span className="jz-detail-baseline-hint">
                        覆盖框架与数据库响应版本头
                      </span>
                    </div>
                    <Tag color="green" style={{ marginInlineEnd: 0 }}>
                      始终隐藏
                    </Tag>
                  </div>

                  <div className="jz-detail-baseline-item">
                    <div className="jz-detail-baseline-meta">
                      <span className="jz-detail-baseline-label">
                        <CheckCircleFilled
                          style={{ color: '#16a34a', marginRight: 6 }}
                        />
                        下划线请求头
                      </span>
                      <span className="jz-detail-baseline-hint">
                        Caddy 2.11+ 内核入口强制丢弃（GHSA-f59h-q822-g45g）
                      </span>
                    </div>
                    <Tooltip title="由 Caddy 内核安全补丁 GHSA-f59h-q822-g45g 强制实施，先于所有防护模块执行，不可关闭">
                      <Tag color="green" style={{ marginInlineEnd: 0 }}>
                        始终拦截
                      </Tag>
                    </Tooltip>
                  </div>
                </div>

                <SectionHeader
                  title="安全响应头策略"
                  description="控制浏览器嵌入、内容安全策略及自定义作者标识头。"
                />
                <Row gutter={[16, 0]}>
                  <Col xs={24} md={8}>
                    <Form.Item name="x_author_action" label="X-Author 响应头">
                      <Select options={HEADER_ACTION_OPTIONS} />
                    </Form.Item>
                  </Col>
                  {xAuthorAction === 'replace' && (
                    <Col xs={24} md={8}>
                      <Form.Item
                        name="x_author_value"
                        label="X-Author 自定义值"
                        rules={[{ required: true, message: '请输入自定义值' }]}
                      >
                        <Input placeholder="自定义值" autoComplete="off" />
                      </Form.Item>
                    </Col>
                  )}
                  <Col xs={24} md={8}>
                    <Form.Item name="x_frame_options" label="X-Frame-Options">
                      <Select options={X_FRAME_OPTIONS} />
                    </Form.Item>
                  </Col>
                  {xFrameOptions === 'allow_from' && (
                    <Col xs={24} md={12}>
                      <Form.Item
                        name="x_frame_options_url"
                        label="允许来源 URL"
                        rules={[
                          { required: true, message: '请输入允许来源 URL' },
                          { type: 'url', message: 'URL 格式不正确' },
                        ]}
                      >
                        <Input
                          placeholder="https://example.com"
                          autoComplete="off"
                        />
                      </Form.Item>
                    </Col>
                  )}
                  <Col xs={24} md={8}>
                    <Form.Item name="csp_mode" label="Content-Security-Policy">
                      <Select options={CSP_MODE_OPTIONS} />
                    </Form.Item>
                  </Col>
                </Row>

                {cspMode === 'custom' && (
                  <Form.Item
                    name="csp_value"
                    label="CSP 策略内容"
                    rules={[{ required: true, message: '请输入 CSP 策略内容' }]}
                  >
                    <Input.TextArea
                      rows={3}
                      className="jz-detail-code-textarea"
                      placeholder="如 default-src 'self'; script-src 'self' https://cdn.example.com"
                    />
                  </Form.Item>
                )}

                <SectionHeader
                  spaced
                  title="浏览器传输与缓存安全开关"
                  description="按需启用强制 HTTPS 传输（HSTS）及浏览器兼容响应头。"
                />
                <Row gutter={[12, 12]}>
                  <Col xs={24} md={8}>
                    <div
                      className={
                        hstsEnabled
                          ? 'jz-detail-switch-tile jz-detail-switch-tile--active'
                          : 'jz-detail-switch-tile'
                      }
                    >
                      <Form.Item
                        name="hsts_enabled"
                        className="jz-detail-switch-form-item"
                        label={
                          <>
                            <span>HSTS</span>
                            <span className="jz-detail-switch-desc">
                              下发 Strict-Transport-Security 强制 HTTPS
                            </span>
                          </>
                        }
                        valuePropName="checked"
                      >
                        <Switch />
                      </Form.Item>
                      {hstsEnabled && (
                        <div className="jz-detail-switch-subpanel">
                          <Form.Item
                            name="hsts_max_age"
                            label="max-age（秒）"
                            style={{ marginBottom: 0 }}
                            extra={hstsDurationHint}
                            rules={[
                              { required: true, message: '请输入 max-age' },
                              {
                                type: 'number',
                                min: 1,
                                message: 'max-age 须大于 0',
                              },
                            ]}
                          >
                            <InputNumber
                              min={1}
                              max={63072000}
                              step={3600}
                              style={{ width: '100%' }}
                            />
                          </Form.Item>
                        </div>
                      )}
                    </div>
                  </Col>

                  <Col xs={24} md={8}>
                    <div
                      className={
                        xssEnabled
                          ? 'jz-detail-switch-tile jz-detail-switch-tile--active'
                          : 'jz-detail-switch-tile'
                      }
                    >
                      <Form.Item
                        name="x_xss_protection"
                        className="jz-detail-switch-form-item"
                        label={
                          <>
                            <span>X-Xss-Protection</span>
                            <span className="jz-detail-switch-desc">
                              为旧版浏览器附加反射型 XSS 过滤头
                            </span>
                          </>
                        }
                        valuePropName="checked"
                      >
                        <Switch />
                      </Form.Item>
                    </div>
                  </Col>

                  <Col xs={24} md={8}>
                    <div
                      className={
                        varyUaEnabled
                          ? 'jz-detail-switch-tile jz-detail-switch-tile--active'
                          : 'jz-detail-switch-tile'
                      }
                    >
                      <Form.Item
                        name="vary_user_agent"
                        className="jz-detail-switch-form-item"
                        label={
                          <>
                            <span>Vary: User-Agent</span>
                            <span className="jz-detail-switch-desc">
                              通知中间缓存按终端 User-Agent 区分副本
                            </span>
                          </>
                        }
                        valuePropName="checked"
                      >
                        <Switch />
                      </Form.Item>
                    </div>
                  </Col>
                </Row>
              </>
            )}
          </Card>

          <Card className="jz-detail-card" title="HTTP代理配置">
            <SectionHeader
              title="代理转发行为开关"
              description="控制反向代理回源与响应写回过程中的缓冲、透传头与重定向细节。"
            />
            <Row gutter={[12, 12]}>
              {PROXY_SWITCH_ITEMS.map((item) => (
                <Col key={item.name} xs={24} sm={12} lg={8}>
                  <div className="jz-detail-switch-tile">
                    <Form.Item
                      name={item.name}
                      className="jz-detail-switch-form-item"
                      label={
                        <>
                          <span>{item.label}</span>
                          <span className="jz-detail-switch-desc">
                            {item.description}
                          </span>
                        </>
                      }
                      valuePropName="checked"
                    >
                      <Switch />
                    </Form.Item>
                  </div>
                </Col>
              ))}
            </Row>

            {renderRuleList(
              'custom_request_rules',
              '自定义请求头修改',
              customReqRules.length,
              '暂无自定义请求头修改规则；可在转发至源站前新增、覆盖或删除指定请求头',
            )}
            {renderRuleList(
              'custom_response_rules',
              '自定义返回头修改',
              customRespRules.length,
              '暂无自定义返回头修改规则；可在返回客户端前新增、覆盖或删除指定响应头',
            )}

            {canUpdate && (
              <div className="jz-detail-action-bar">
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  以上「HTTP头合规」与「HTTP代理配置」将一并保存，发布配置后在网关生效（下方路径转发规则独立保存）。
                </Typography.Text>
                <Button
                  type="primary"
                  icon={<SaveOutlined />}
                  htmlType="submit"
                  loading={saveConfigMutation.isPending}
                >
                  保存配置
                </Button>
              </div>
            )}
          </Card>
        </Space>
      </Form>

      <Card
        className="jz-detail-card"
        title={
          <Space size={8}>
            <span>路径转发配置</span>
            <Tag style={{ marginInlineEnd: 0 }}>{routeTotal} 条</Tag>
          </Space>
        }
        extra={
          <Space>
            {batchDeleteButton}
            {canUpdate && (
              <Button
                type="primary"
                icon={<PlusOutlined />}
                onClick={() => {
                  setEditing(null)
                  routeForm.resetFields()
                  setCreateOpen(true)
                }}
              >
                新增转发规则
              </Button>
            )}
          </Space>
        }
      >
        <InlineNote compact>
          按路径前缀将特定流量分流至独立源站；增删改即时入库，经配置发布后生效。双击任意行可查看完整详情。
        </InlineNote>
        {routesQuery.isError ? (
          <Alert
            type="error"
            showIcon
            title="加载路径转发列表失败"
            description={
              routesQuery.error instanceof ApiError
                ? routesQuery.error.message
                : undefined
            }
          />
        ) : (
          <SmartTable<AppPathRoute>
            storageKey="app-path-routes"
            rowKey="id"
            rowSelection={rowSelection}
            loading={routesQuery.isLoading}
            columns={routeColumns}
            dataSource={routesQuery.data?.items}
            scroll={{ x: 900 }}
            onRow={(record) => ({
              onDoubleClick: () => setDetailRecord(record),
              style: { cursor: 'pointer' },
            })}
            pagination={{
              current: page,
              pageSize,
              total: routeTotal,
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
        title={
          editing ? `编辑路径转发：${editing.path_prefix}` : '新增路径转发'
        }
        open={routeDrawerOpen}
        onClose={() => {
          setCreateOpen(false)
          setEditing(null)
        }}
        size={480}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button
              onClick={() => {
                setCreateOpen(false)
                setEditing(null)
              }}
            >
              取消
            </Button>
            <Button
              type="primary"
              loading={saveRouteMutation.isPending}
              onClick={() => routeForm.submit()}
            >
              保存
            </Button>
          </Space>
        }
      >
        <Form<PathRouteFormValues>
          form={routeForm}
          layout="vertical"
          initialValues={ROUTE_DEFAULT_VALUES}
          onFinish={(values) =>
            saveRouteMutation.mutate({
              routeId: editing?.id ?? null,
              version: editing?.version,
              body: toRouteBody(values),
            })
          }
        >
          <SectionHeader title="路径匹配" />
          <Form.Item
            name="path_prefix"
            label="转发路径"
            extra="以 / 开头，不带参数"
            rules={[
              { required: true, message: '请输入转发路径' },
              {
                validator: (_, v: string) => {
                  if (!v) return Promise.resolve()
                  if (!v.startsWith('/'))
                    return Promise.reject(new Error('转发路径需以 / 开头'))
                  if (v.includes('?') || v.includes('#'))
                    return Promise.reject(new Error('转发路径不带参数'))
                  return Promise.resolve()
                },
              },
            ]}
          >
            <Input placeholder="如 /api/v1" autoComplete="off" />
          </Form.Item>

          <SectionHeader title="目标源站" spaced />
          <Row gutter={12}>
            <Col span={7}>
              <Form.Item
                name="upstream_scheme"
                label="源站协议"
                rules={[{ required: true }]}
              >
                <Select
                  options={[
                    { value: 'http', label: 'HTTP' },
                    { value: 'https', label: 'HTTPS' },
                  ]}
                  onChange={(v: string) => {
                    const cur = routeForm.getFieldValue(
                      'upstream_port',
                    ) as number
                    if (v === 'https' && cur === 80)
                      routeForm.setFieldValue('upstream_port', 443)
                    if (v === 'http' && cur === 443)
                      routeForm.setFieldValue('upstream_port', 80)
                  }}
                />
              </Form.Item>
            </Col>
            <Col span={11}>
              <Form.Item
                name="upstream_host"
                label="源站主机"
                rules={[
                  { required: true, message: '请输入主机地址' },
                  {
                    validator: (_, v: string) => {
                      if (!v) return Promise.resolve()
                      const err = validateHost(v)
                      return err
                        ? Promise.reject(new Error(err))
                        : Promise.resolve()
                    },
                  },
                ]}
              >
                <Input placeholder="IP 或域名" autoComplete="off" />
              </Form.Item>
            </Col>
            <Col span={6}>
              <Form.Item
                name="upstream_port"
                label="端口"
                rules={[{ required: true, message: '请输入端口' }]}
              >
                <InputNumber min={1} max={65535} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
          </Row>

          <SectionHeader title="转发选项" spaced />
          <Form.Item
            name="strip_prefix"
            label="保留转发路径"
            extra="选择「否」时，转发到源站前剥离匹配的路径前缀"
          >
            <Radio.Group
              options={[
                { value: false, label: '是（不剥离）' },
                { value: true, label: '否（剥离前缀）' },
              ]}
            />
          </Form.Item>
          <Row gutter={12}>
            <Col span={12}>
              <Form.Item
                name="priority"
                label="优先级"
                extra="数值小者优先；同优先级长前缀优先"
                rules={[{ required: true, message: '请输入优先级' }]}
              >
                <InputNumber min={0} max={100000} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="enabled" label="状态" valuePropName="checked">
                <Switch checkedChildren="启用" unCheckedChildren="停用" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="description" label="描述">
            <Input
              placeholder="用途说明（可选）"
              maxLength={255}
              autoComplete="off"
            />
          </Form.Item>
        </Form>
      </Drawer>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="路径转发详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </div>
  )
}
