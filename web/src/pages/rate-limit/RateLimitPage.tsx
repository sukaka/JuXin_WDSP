import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Divider,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { CloudUploadOutlined, ExperimentOutlined, PlusOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { rateLimitPoliciesApi } from '../../api/rateLimitPolicies'
import type { RateLimitPolicyBody } from '../../api/rateLimitPolicies'
import { applicationsApi } from '../../api/applications'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { PublishTaskProgress } from '../config-publish/ConfigPublishPage'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import {
  RATE_LIMIT_ACTION_META,
  RATE_LIMIT_ALGORITHM_META,
  RATE_LIMIT_DIMENSION_META,
  RATE_LIMIT_SCOPE_META,
  RATE_LIMIT_STATUS_META,
  RATE_LIMIT_URI_MATCH_META,
  isValidIPLiteral,
} from '../../utils/stage5'
import type { RateLimitPolicyItem, RateLimitTestResult } from '../../types'

interface Filters {
  scope_type?: string
  status?: string
  action?: string
  keyword?: string
}

interface PolicyFormValues {
  name: string
  description?: string
  scope_type: string
  application_id?: string
  uri_match_type: string
  uri_pattern?: string
  dimension: string
  algorithm: string
  requests_limit: number
  window_seconds: number
  burst_capacity?: number
  action: string
  block_duration_seconds?: number
  observe_only?: boolean
  priority: number
  effective_range?: [dayjs.Dayjs | null, dayjs.Dayjs | null]
}

interface TestFormValues {
  requests: number
  client_ips?: string[]
  uri?: string
}

const optionsOf = (meta: Record<string, { label: string }>) =>
  Object.entries(meta).map(([value, m]) => ({ value, label: m.label }))

export default function RateLimitPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'rate_limits.manage')
  const canPublish = hasPermission(permissions, 'rate_limits.publish')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<RateLimitPolicyItem | null>(null)
  const [testing, setTesting] = useState<RateLimitPolicyItem | null>(null)
  const [testResult, setTestResult] = useState<RateLimitTestResult | null>(null)
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null)
  const [form] = Form.useForm<PolicyFormValues>()
  const [testForm] = Form.useForm<TestFormValues>()

  const listQuery = useQuery({
    queryKey: ['rate-limit-policies', filters, page, pageSize],
    queryFn: () => rateLimitPoliciesApi.list({ ...filters, page, page_size: pageSize }),
  })

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-rate-limit'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: formOpen,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['rate-limit-policies'] })
  const onError = (e: unknown) => {
    if (e instanceof ApiError && Array.isArray(e.details)) {
      // 后端字段级校验错误（ValidationError.details = [{field, message}]）
      const msgs = (e.details as { field?: string; message?: string }[])
        .map((d) => `${d.field ?? ''}: ${d.message ?? ''}`)
        .join('；')
      message.error(msgs || e.message)
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) => {
      const [from, until] = values.effective_range ?? [null, null]
      const body: RateLimitPolicyBody = {
        name: values.name,
        description: values.description ?? '',
        scope_type: values.scope_type,
        application_id: values.scope_type === 'GLOBAL' ? null : values.application_id,
        uri_match_type: values.uri_match_type,
        uri_pattern: values.uri_match_type === 'ALL' ? '' : (values.uri_pattern ?? ''),
        dimension: values.dimension,
        algorithm: values.algorithm,
        requests_limit: values.requests_limit,
        window_seconds: values.window_seconds,
        burst_capacity: values.burst_capacity ?? 0,
        action: values.action,
        block_duration_seconds: values.action === 'TEMP_BLOCK' ? (values.block_duration_seconds ?? 0) : 0,
        observe_only: values.observe_only ?? false,
        priority: values.priority,
        effective_from: from ? from.toISOString() : null,
        effective_until: until ? until.toISOString() : null,
      }
      return editing
        ? rateLimitPoliciesApi.update(editing.id, { ...body, version: editing.version })
        : rateLimitPoliciesApi.create(body)
    },
    onSuccess: () => {
      message.success(editing ? '策略已更新' : '策略已创建')
      setFormOpen(false)
      setEditing(null)
      form.resetFields()
      void invalidate()
    },
    onError,
  })

  const statusMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'enable' | 'disable' }) =>
      action === 'enable' ? rateLimitPoliciesApi.enable(id) : rateLimitPoliciesApi.disable(id),
    onSuccess: () => {
      message.success('操作成功')
      void invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => rateLimitPoliciesApi.remove(id),
    onSuccess: () => {
      message.success('策略已删除')
      void invalidate()
    },
    onError,
  })

  const testMutation = useMutation({
    mutationFn: (values: TestFormValues) =>
      rateLimitPoliciesApi.test((testing as RateLimitPolicyItem).id, {
        requests: values.requests,
        client_ips: values.client_ips ?? [],
        uri: values.uri ?? '',
      }),
    onSuccess: (data) => setTestResult(data),
    onError: (e) => {
      setTestResult(null)
      onError(e)
    },
  })

  const publishMutation = useMutation({
    mutationFn: () => rateLimitPoliciesApi.publish(crypto.randomUUID()),
    onSuccess: (task) => {
      setActiveTaskId(task.id)
      if (task.status === 'SUCCESS') message.success('发布成功')
      else if (task.status === 'FAILED') message.error('发布失败，请查看任务详情')
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '发布失败'),
  })

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    setFormOpen(true)
  }

  const openEdit = (record: RateLimitPolicyItem) => {
    setEditing(record)
    form.setFieldsValue({
      name: record.name,
      description: record.description || undefined,
      scope_type: record.scope_type,
      application_id: record.application_id ?? undefined,
      uri_match_type: record.uri_match_type,
      uri_pattern: record.uri_pattern || undefined,
      dimension: record.dimension,
      algorithm: record.algorithm,
      requests_limit: record.requests_limit,
      window_seconds: record.window_seconds,
      burst_capacity: record.burst_capacity,
      action: record.action,
      block_duration_seconds: record.block_duration_seconds || undefined,
      observe_only: record.observe_only,
      priority: record.priority,
      effective_range: [
        record.effective_from ? dayjs(record.effective_from) : null,
        record.effective_until ? dayjs(record.effective_until) : null,
      ],
    })
    setFormOpen(true)
  }

  const confirmDelete = (record: RateLimitPolicyItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除CC策略「${record.name}」吗？删除后对应限速保护立即失效。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const confirmPublish = () => {
    modal.confirm({
      title: '高风险操作确认',
      content: '发布将把当前 CC 防护策略配置下发到防护网关并立即生效。确定执行发布吗？',
      okText: '确认发布',
      okButtonProps: { danger: true },
      onOk: () => publishMutation.mutate(),
    })
  }

  const columns: ColumnsType<RateLimitPolicyItem> = [
    { title: '名称', dataIndex: 'name', width: 170, ellipsis: true },
    {
      title: '范围',
      dataIndex: 'scope_type',
      width: 100,
      render: (v: string, record) => (
        <Space size={4}>
          <StatusTag value={v} map={RATE_LIMIT_SCOPE_META} />
          {record.uri_match_type !== 'ALL' && (
            <Tag>{RATE_LIMIT_URI_MATCH_META[record.uri_match_type]?.label ?? record.uri_match_type}</Tag>
          )}
        </Space>
      ),
    },
    {
      title: '维度',
      dataIndex: 'dimension',
      width: 140,
      render: (v: string) => <StatusTag value={v} map={RATE_LIMIT_DIMENSION_META} />,
    },
    {
      title: '算法',
      dataIndex: 'algorithm',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={RATE_LIMIT_ALGORITHM_META} />,
    },
    {
      title: '限制（次数/窗口/突发）',
      key: 'limit',
      width: 170,
      render: (_, record) => (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {record.requests_limit} 次 / {record.window_seconds} 秒 /{' '}
          {record.burst_capacity > 0 ? record.burst_capacity : record.requests_limit}
        </Typography.Text>
      ),
    },
    {
      title: '动作',
      dataIndex: 'action',
      width: 110,
      render: (v: string, record) => (
        <Space size={4}>
          <StatusTag value={v} map={RATE_LIMIT_ACTION_META} />
          {record.observe_only && <Tag color="blue">仅观察</Tag>}
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={RATE_LIMIT_STATUS_META} />,
    },
    { title: '优先级', dataIndex: 'priority', width: 80, align: 'right' },
    {
      title: '操作',
      key: 'actions',
      width: 200,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button
            type="link"
            size="small"
            onClick={() => {
              setTesting(record)
              setTestResult(null)
              testForm.resetFields()
            }}
          >
            测试
          </Button>
          {canManage && (
            <>
              <Button type="link" size="small" onClick={() => openEdit(record)}>
                编辑
              </Button>
              {record.status === 'ACTIVE' ? (
                <Button
                  type="link"
                  size="small"
                  onClick={() => statusMutation.mutate({ id: record.id, action: 'disable' })}
                >
                  停用
                </Button>
              ) : (
                <Button
                  type="link"
                  size="small"
                  onClick={() => statusMutation.mutate({ id: record.id, action: 'enable' })}
                >
                  启用
                </Button>
              )}
              <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
                删除
              </Button>
            </>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Card
      title="频率与 CC 防护"
      extra={
        <Space>
          {canPublish && (
            <Button
              icon={<CloudUploadOutlined />}
              loading={publishMutation.isPending}
              onClick={confirmPublish}
            >
              发布
            </Button>
          )}
          {canManage && (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              新建策略
            </Button>
          )}
        </Space>
      }
    >
      {activeTaskId && <PublishTaskProgress taskId={activeTaskId} />}
      <Space style={{ marginBottom: 16, marginTop: activeTaskId ? 16 : 0 }} wrap>
        <Select
          placeholder="作用范围"
          allowClear
          style={{ width: 130 }}
          options={optionsOf(RATE_LIMIT_SCOPE_META)}
          onChange={(v) => {
            setFilters((f) => ({ ...f, scope_type: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="动作"
          allowClear
          style={{ width: 130 }}
          options={optionsOf(RATE_LIMIT_ACTION_META)}
          onChange={(v) => {
            setFilters((f) => ({ ...f, action: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 120 }}
          options={optionsOf(RATE_LIMIT_STATUS_META)}
          onChange={(v) => {
            setFilters((f) => ({ ...f, status: v }))
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="策略名称"
          allowClear
          style={{ width: 180 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, keyword: v || undefined }))
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载CC策略失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<RateLimitPolicyItem>
          storageKey="rate-limit"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1350 }}
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
        />
      )}

      <Drawer
        title={editing ? '编辑CC策略' : '新建CC策略'}
        open={formOpen}
        onClose={() => {
          setFormOpen(false)
          setEditing(null)
        }}
        width={600}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setFormOpen(false)}>取消</Button>
            <Button type="primary" loading={saveMutation.isPending} onClick={() => form.submit()}>
              {editing ? '保存' : '创建'}
            </Button>
          </Space>
        }
      >
        <Form<PolicyFormValues>
          form={form}
          layout="vertical"
          initialValues={{
            scope_type: 'GLOBAL',
            uri_match_type: 'ALL',
            dimension: 'CLIENT_IP',
            algorithm: 'TOKEN_BUCKET',
            requests_limit: 100,
            window_seconds: 60,
            burst_capacity: 0,
            action: 'REJECT',
            observe_only: false,
            priority: 100,
          }}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Divider titlePlacement="start" plain>
            基本信息
          </Divider>
          <Form.Item
            name="name"
            label="策略名称"
            rules={[
              { required: true, message: '请输入策略名称' },
              { max: 200, message: '不超过 200 个字符' },
            ]}
          >
            <Input placeholder="如：登录接口防爆破" />
          </Form.Item>
          <Form.Item name="description" label="描述" rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} placeholder="策略用途说明（可选）" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="priority" label="优先级（数值小者优先）" style={{ width: '50%', marginRight: 8 }} rules={[{ required: true, message: '请输入优先级' }]}>
              <InputNumber min={0} max={10000} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="observe_only" label="仅观察（不阻断）" style={{ width: '50%' }} valuePropName="checked">
              <Switch checkedChildren="是" unCheckedChildren="否" />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="effective_range" label="生效 / 失效时间（留空长期生效）">
            <DatePicker.RangePicker showTime style={{ width: '100%' }} />
          </Form.Item>

          <Divider titlePlacement="start" plain>
            匹配范围
          </Divider>
          <Form.Item name="scope_type" label="作用范围" rules={[{ required: true }]}>
            <Select options={optionsOf(RATE_LIMIT_SCOPE_META)} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.scope_type !== cur.scope_type}>
            {({ getFieldValue }) =>
              getFieldValue('scope_type') !== 'GLOBAL' && (
                <Form.Item
                  name="application_id"
                  label="目标应用"
                  rules={[{ required: true, message: '应用/路径范围必须选择应用' }]}
                >
                  <Select
                    showSearch
                    optionFilterProp="label"
                    placeholder="选择应用"
                    loading={appsQuery.isLoading}
                    options={(appsQuery.data?.items ?? []).map((a) => ({
                      value: a.id,
                      label: `${a.name}（${a.code}）`,
                    }))}
                  />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item name="uri_match_type" label="路径匹配方式" rules={[{ required: true }]}>
            <Select options={optionsOf(RATE_LIMIT_URI_MATCH_META)} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.uri_match_type !== cur.uri_match_type}>
            {({ getFieldValue }) => {
              const mt = getFieldValue('uri_match_type')
              if (mt === 'ALL') return null
              return (
                <>
                  {mt === 'REGEX' && (
                    <Alert
                      type="warning"
                      showIcon
                      style={{ marginBottom: 16 }}
                      message="正则匹配基于 RE2 引擎（线性时间，天然防 ReDoS），不支持回溯引用与环视语法"
                    />
                  )}
                  <Form.Item
                    name="uri_pattern"
                    label="路径匹配模式"
                    rules={[
                      { required: true, message: '请填写路径匹配模式' },
                      { max: 256, message: '不超过 256 个字符' },
                      ...(mt === 'EXACT' || mt === 'PREFIX'
                        ? [{ pattern: /^\//, message: '必须以 / 开头' }]
                        : []),
                    ]}
                  >
                    <Input
                      placeholder={mt === 'REGEX' ? '^/api/v\\d+/login$' : '/api/login'}
                      autoComplete="off"
                    />
                  </Form.Item>
                </>
              )
            }}
          </Form.Item>

          <Divider titlePlacement="start" plain>
            限速参数
          </Divider>
          <Form.Item name="dimension" label="统计维度" rules={[{ required: true }]}>
            <Select options={optionsOf(RATE_LIMIT_DIMENSION_META)} />
          </Form.Item>
          <Form.Item name="algorithm" label="限速算法" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'TOKEN_BUCKET', label: '令牌桶（匀速补充，允许突发）' },
                { value: 'SLIDING_WINDOW', label: '滑动窗口（双窗口加权近似）' },
              ]}
            />
          </Form.Item>
          <Space.Compact block>
            <Form.Item
              name="requests_limit"
              label="请求数阈值"
              style={{ width: '33%', marginRight: 8 }}
              rules={[{ required: true, message: '请输入请求数阈值' }]}
            >
              <InputNumber min={1} max={1000000} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              name="window_seconds"
              label="统计窗口（秒）"
              style={{ width: '33%', marginRight: 8 }}
              rules={[{ required: true, message: '请输入统计窗口' }]}
            >
              <InputNumber min={1} max={86400} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="burst_capacity" label="突发容量（0=取阈值）" style={{ width: '34%' }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
          </Space.Compact>

          <Divider titlePlacement="start" plain>
            触发动作
          </Divider>
          <Form.Item name="action" label="超阈值动作" rules={[{ required: true }]}>
            <Select options={optionsOf(RATE_LIMIT_ACTION_META)} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.action !== cur.action}>
            {({ getFieldValue }) =>
              getFieldValue('action') === 'TEMP_BLOCK' && (
                <Form.Item
                  name="block_duration_seconds"
                  label="临时封禁时长（秒）"
                  rules={[{ required: true, message: '临时封禁必须设置封禁时长' }]}
                  extra="最短 60 秒，最长 30 天（2592000 秒）；超阈值客户端将被临时封禁"
                >
                  <InputNumber min={60} max={2592000} style={{ width: '100%' }} />
                </Form.Item>
              )
            }
          </Form.Item>
        </Form>
      </Drawer>

      <Modal
        title={`模拟测试「${testing?.name ?? ''}」`}
        open={testing !== null}
        onCancel={() => {
          setTesting(null)
          setTestResult(null)
        }}
        footer={null}
        width={640}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          干跑模拟：按策略参数在服务端演算，不触达真实网关流量。
        </Typography.Paragraph>
        <Form<TestFormValues>
          form={testForm}
          layout="vertical"
          initialValues={{ requests: 100 }}
          onFinish={(values) => testMutation.mutate(values)}
        >
          <Form.Item
            name="requests"
            label="模拟请求数（1-10000）"
            rules={[{ required: true, message: '请输入模拟请求数' }]}
          >
            <InputNumber min={1} max={10000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="client_ips"
            label="模拟客户端 IP（可选，最多 10 个）"
            rules={[
              {
                validator: (_, v: string[] | undefined) => {
                  const ips = v ?? []
                  if (ips.length > 10) return Promise.reject(new Error('最多 10 个模拟客户端IP'))
                  const invalid = ips.filter((ip) => !isValidIPLiteral(ip))
                  return invalid.length > 0
                    ? Promise.reject(new Error(`无效的IP：${invalid.join('、')}`))
                    : Promise.resolve()
                },
              },
            ]}
          >
            <Select mode="tags" open={false} placeholder="输入 IP 后回车；留空表示单一来源" />
          </Form.Item>
          <Form.Item
            name="uri"
            label="模拟 URI（可选）"
            rules={[{ pattern: /^\//, message: '必须以 / 开头' }]}
          >
            <Input placeholder="/api/login" autoComplete="off" />
          </Form.Item>
          <Button type="primary" htmlType="submit" icon={<ExperimentOutlined />} loading={testMutation.isPending}>
            开始模拟
          </Button>
        </Form>

        {testResult && (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginTop: 16 }}>
              <Descriptions.Item label="模拟请求数">{testResult.requests}</Descriptions.Item>
              <Descriptions.Item label="算法">
                {RATE_LIMIT_ALGORITHM_META[testResult.algorithm]?.label ?? testResult.algorithm}
              </Descriptions.Item>
              <Descriptions.Item label="放行">
                <Typography.Text type="success">{testResult.allowed}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="拒绝">
                <Typography.Text type={testResult.rejected > 0 ? 'danger' : undefined}>
                  {testResult.rejected}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="首次拒绝于第">
                {testResult.first_reject_at > 0 ? `第 ${testResult.first_reject_at} 个请求` : '无拒绝'}
              </Descriptions.Item>
              <Descriptions.Item label="重试等待">
                {testResult.retry_after_seconds > 0 ? `${testResult.retry_after_seconds} 秒` : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="统计维度说明" span={2}>
                {testResult.dimension_note || '-'}
              </Descriptions.Item>
            </Descriptions>
          </>
        )}
      </Modal>
    </Card>
  )
}
