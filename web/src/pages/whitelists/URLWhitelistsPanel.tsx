import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  DatePicker,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { CloudUploadOutlined, PlusOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import { urlWhitelistsApi } from '../../api/urlWhitelists'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { PublishTaskProgress } from '../config-publish/ConfigPublishPage'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { generateIdempotencyKey } from '../../utils/idempotency'
import { hasPermission } from '../../utils/permission'
import {
  ACCESS_RULE_SCOPE_META,
  ACCESS_RULE_SOURCE_META,
  ACCESS_RULE_STATUS_META,
  ACCESS_RULE_VALIDITY_META,
  AC_EVENT_ACTION_META,
  AC_EVENT_TYPE_META,
  URL_WHITELIST_MATCH_META,
} from '../../utils/stage5'
import type { AccessControlEventItem, URLWhitelistRuleItem } from '../../types'

interface Filters {
  scope_type?: string
  match_type?: string
  status?: string
  source_type?: string
  keyword?: string
}

const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

const UNTIL_PRESETS: { value: string; label: string; seconds?: number }[] = [
  { value: '15m', label: '15 分钟', seconds: 15 * 60 },
  { value: '1h', label: '1 小时', seconds: 60 * 60 },
  { value: '4h', label: '4 小时', seconds: 4 * 60 * 60 },
  { value: '1d', label: '1 天', seconds: 24 * 60 * 60 },
  { value: '7d', label: '7 天', seconds: 7 * 24 * 60 * 60 },
  { value: '30d', label: '30 天', seconds: 30 * 24 * 60 * 60 },
  { value: 'CUSTOM', label: '自定义' },
]

function resolveEffectiveUntil(
  preset: string | undefined,
  custom: dayjs.Dayjs | null | undefined,
): string | null {
  if (!preset) return null
  if (preset === 'CUSTOM') return custom ? custom.toISOString() : null
  const p = UNTIL_PRESETS.find((x) => x.value === preset)
  return p?.seconds ? dayjs().add(p.seconds, 'second').toISOString() : null
}

interface URLRuleFormValues {
  name: string
  scope_type: 'GLOBAL' | 'APPLICATION'
  application_id?: string
  match_type: 'EXACT' | 'PREFIX' | 'REGEX'
  uri_pattern: string
  methods?: string[]
  priority?: number
  validity_type: 'PERMANENT' | 'TEMPORARY'
  effective_from?: dayjs.Dayjs | null
  until_preset?: string
  until_custom?: dayjs.Dayjs | null
  reason?: string
}

interface ExtendFormValues {
  until_preset: string
  until_custom?: dayjs.Dayjs | null
}

function validateURIPattern(matchType: string | undefined, value: string): string | null {
  const s = value.trim()
  if (!s) return '请输入 URL 路径或正则'
  if (s.length > 512) return '长度不能超过 512 字符'
  if (matchType === 'REGEX') return null
  if (!s.startsWith('/')) return '精确/前缀匹配路径必须以 / 开头'
  if (/[?#\s]/.test(s)) return '精确/前缀匹配路径不得包含查询参数（?）、锚点（#）或空格'
  if (s.split('/').some((seg) => seg === '.' || seg === '..')) {
    return 'URL 路径不得包含相对路径段 . 或 ..'
  }
  return null
}

export default function URLWhitelistsPanel() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'access_rules.manage')
  const canPublish = hasPermission(permissions, 'access_rules.publish')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<URLWhitelistRuleItem | null>(null)
  const [extending, setExtending] = useState<URLWhitelistRuleItem | null>(null)
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null)
  const [detailRecord, setDetailRecord] = useState<URLWhitelistRuleItem | null>(null)
  const [eventsRule, setEventsRule] = useState<URLWhitelistRuleItem | null>(null)
  const [eventsPage, setEventsPage] = useState(1)
  const [eventsPageSize, setEventsPageSize] = useState(20)
  const [form] = Form.useForm<URLRuleFormValues>()
  const [extendForm] = Form.useForm<ExtendFormValues>()

  const listQuery = useQuery({
    queryKey: ['url-whitelists', filters, page, pageSize],
    queryFn: () => urlWhitelistsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const ruleEventsQuery = useQuery({
    queryKey: ['url-whitelist-events', eventsRule?.id, eventsPage, eventsPageSize],
    queryFn: () =>
      urlWhitelistsApi.listEvents(eventsRule!.id, { page: eventsPage, page_size: eventsPageSize }),
    enabled: eventsRule !== null,
  })

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-url-whitelist'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: formOpen,
  })

  const appOptions = (appsQuery.data?.items ?? []).map((a) => ({
    value: a.id,
    label: `${a.name}（${a.code}）`,
  }))

  const { rowSelection, batchDeleteButton } = useBatchDelete<URLWhitelistRuleItem>({
    remove: (id) => urlWhitelistsApi.remove(id),
    invalidateKeys: [['url-whitelists']],
    entityName: 'URL 白名单规则',
    canDelete: canManage,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['url-whitelists'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveMutation = useMutation({
    mutationFn: (values: URLRuleFormValues) => {
      const effectiveUntil =
        values.validity_type === 'TEMPORARY'
          ? resolveEffectiveUntil(values.until_preset, values.until_custom)
          : null
      if (values.validity_type === 'TEMPORARY' && !effectiveUntil) {
        return Promise.reject(new ApiError('临时规则必须设置失效时间', 'INVALID', 0))
      }
      if (editing) {
        return urlWhitelistsApi.update(editing.id, {
          name: values.name,
          match_type: values.match_type,
          uri_pattern: values.uri_pattern,
          methods: values.methods ?? [],
          priority: values.priority,
          validity_type: values.validity_type,
          effective_from: values.effective_from ? values.effective_from.toISOString() : null,
          effective_until: effectiveUntil,
          reason: values.reason ?? '',
          version: editing.version,
        })
      }
      return urlWhitelistsApi.create({
        name: values.name,
        scope_type: values.scope_type,
        application_id: values.scope_type === 'APPLICATION' ? values.application_id : null,
        match_type: values.match_type,
        uri_pattern: values.uri_pattern,
        methods: values.methods ?? [],
        priority: values.priority,
        validity_type: values.validity_type,
        effective_from: values.effective_from ? values.effective_from.toISOString() : null,
        effective_until: effectiveUntil,
        reason: values.reason ?? '',
      })
    },
    onSuccess: () => {
      message.success(editing ? 'URL 白名单规则已更新' : 'URL 白名单规则已创建')
      setFormOpen(false)
      setEditing(null)
      form.resetFields()
      void invalidate()
    },
    onError,
  })

  const actionMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'enable' | 'disable' | 'release' }) => {
      switch (action) {
        case 'enable':
          return urlWhitelistsApi.enable(id)
        case 'disable':
          return urlWhitelistsApi.disable(id)
        case 'release':
          return urlWhitelistsApi.release(id)
      }
    },
    onSuccess: () => {
      message.success('操作成功')
      void invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => urlWhitelistsApi.remove(id),
    onSuccess: () => {
      message.success('URL 白名单规则已删除')
      void invalidate()
    },
    onError,
  })

  const extendMutation = useMutation({
    mutationFn: ({ id, until }: { id: string; until: string }) => urlWhitelistsApi.extend(id, until),
    onSuccess: () => {
      message.success('规则已延期')
      setExtending(null)
      extendForm.resetFields()
      void invalidate()
    },
    onError,
  })

  const publishMutation = useMutation({
    mutationFn: () => urlWhitelistsApi.publish(generateIdempotencyKey()),
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

  const openEdit = (record: URLWhitelistRuleItem) => {
    setEditing(record)
    form.setFieldsValue({
      name: record.name,
      scope_type: record.scope_type,
      application_id: record.application_id ?? undefined,
      match_type: record.match_type,
      uri_pattern: record.uri_pattern,
      methods: record.methods ?? [],
      priority: record.priority,
      validity_type: record.validity_type,
      effective_from: record.effective_from ? dayjs(record.effective_from) : null,
      until_preset: 'CUSTOM',
      until_custom: record.effective_until ? dayjs(record.effective_until) : null,
      reason: record.reason || undefined,
    })
    setFormOpen(true)
  }

  const confirmAction = (record: URLWhitelistRuleItem, action: 'enable' | 'disable' | 'release') => {
    const contentMap: Record<typeof action, string> = {
      enable: `确定启用 URL 白名单规则「${record.name}」吗？启用后需发布才在网关生效。`,
      disable: `确定停用 URL 白名单规则「${record.name}」吗？停用后该规则不再参与放行判定。`,
      release: `确定提前结束临时 URL 白名单「${record.name}」（${record.uri_pattern}）吗？`,
    }
    modal.confirm({
      title: '操作确认',
      content: contentMap[action],
      onOk: () => actionMutation.mutate({ id: record.id, action }),
    })
  }

  const confirmDelete = (record: URLWhitelistRuleItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除 URL 白名单规则「${record.name}」（${record.uri_pattern}）吗？`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const confirmPublish = () => {
    modal.confirm({
      title: '高风险操作确认',
      content: '发布将把当前访问控制（含 IP 黑白名单、URL 白名单与 CC 策略）配置下发到防护网关并立即生效。确定执行发布吗？',
      okText: '确认发布',
      okButtonProps: { danger: true },
      onOk: () => publishMutation.mutate(),
    })
  }

  const columns: ColumnsType<URLWhitelistRuleItem> = [
    { title: '名称', dataIndex: 'name', width: 160, ellipsis: true },
    {
      title: '匹配方式',
      dataIndex: 'match_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={URL_WHITELIST_MATCH_META} />,
    },
    {
      title: 'URL 路径 / 正则',
      dataIndex: 'uri_pattern',
      width: 240,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v} placement="topLeft">
          <Typography.Text code>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '限定方法',
      dataIndex: 'methods',
      width: 130,
      render: (ms: string[]) =>
        ms && ms.length > 0 ? (
          <Space size={4} wrap>
            {ms.map((m) => (
              <Tag key={m}>{m}</Tag>
            ))}
          </Space>
        ) : (
          <Typography.Text type="secondary">全部方法</Typography.Text>
        ),
    },
    {
      title: '范围',
      dataIndex: 'scope_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={ACCESS_RULE_SCOPE_META} />,
    },
    { title: '优先级', dataIndex: 'priority', width: 80 },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ACCESS_RULE_STATUS_META} />,
    },
    {
      title: '有效期',
      key: 'validity',
      width: 190,
      render: (_, record) => (
        <Space size={4}>
          <StatusTag value={record.validity_type} map={ACCESS_RULE_VALIDITY_META} />
          {record.validity_type === 'TEMPORARY' && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {formatDateTime(record.effective_until)} 止
            </Typography.Text>
          )}
        </Space>
      ),
    },
    { title: '命中数', dataIndex: 'hit_count', width: 80 },
    {
      title: '来源',
      dataIndex: 'source_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={ACCESS_RULE_SOURCE_META} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 260,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          <Button
            type="link"
            size="small"
            onClick={() => {
              setEventsRule(record)
              setEventsPage(1)
            }}
          >
            关联事件
          </Button>
          {canManage && (
            <>
              <Button type="link" size="small" onClick={() => openEdit(record)}>
                编辑
              </Button>
              {record.status === 'ACTIVE' ? (
                <Button type="link" size="small" onClick={() => confirmAction(record, 'disable')}>
                  停用
                </Button>
              ) : (
                record.status !== 'EXPIRED' && (
                  <Button type="link" size="small" onClick={() => confirmAction(record, 'enable')}>
                    启用
                  </Button>
                )
              )}
              {record.validity_type === 'TEMPORARY' && record.status !== 'EXPIRED' && (
                <>
                  <Button
                    type="link"
                    size="small"
                    onClick={() => {
                      setExtending(record)
                      extendForm.resetFields()
                    }}
                  >
                    延期
                  </Button>
                  <Button type="link" size="small" onClick={() => confirmAction(record, 'release')}>
                    结束
                  </Button>
                </>
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
    <>
      {activeTaskId && <PublishTaskProgress taskId={activeTaskId} />}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 12,
          flexWrap: 'wrap',
          marginBottom: 16,
          marginTop: activeTaskId ? 16 : 0,
        }}
      >
        <Space wrap>
          <Select
            placeholder="生效范围"
            allowClear
            style={{ width: 120 }}
            options={Object.entries(ACCESS_RULE_SCOPE_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, scope_type: v }))
              setPage(1)
            }}
          />
          <Select
            placeholder="匹配方式"
            allowClear
            style={{ width: 120 }}
            options={Object.entries(URL_WHITELIST_MATCH_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, match_type: v }))
              setPage(1)
            }}
          />
          <Select
            placeholder="状态"
            allowClear
            style={{ width: 120 }}
            options={Object.entries(ACCESS_RULE_STATUS_META)
              .filter(([v]) => v !== 'DELETED')
              .map(([value, meta]) => ({ value, label: meta.label }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, status: v }))
              setPage(1)
            }}
          />
          <Select
            placeholder="来源"
            allowClear
            style={{ width: 130 }}
            options={['MANUAL', 'SECURITY_EVENT'].map((value) => ({
              value,
              label: ACCESS_RULE_SOURCE_META[value]?.label ?? value,
            }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, source_type: v }))
              setPage(1)
            }}
          />
          <Input.Search
            placeholder="名称 / URL 路径"
            allowClear
            style={{ width: 220 }}
            onSearch={(v) => {
              setFilters((f) => ({ ...f, keyword: v || undefined }))
              setPage(1)
            }}
          />
          {batchDeleteButton}
        </Space>
        <Space wrap>
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
              新建 URL 白名单
            </Button>
          )}
        </Space>
      </div>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载 URL 白名单失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<URLWhitelistRuleItem>
          storageKey="url-whitelist-rules"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1620 }}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
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
        title={editing ? '编辑 URL 白名单规则' : '新建 URL 白名单规则'}
        open={formOpen}
        onClose={() => {
          setFormOpen(false)
          setEditing(null)
        }}
        width={560}
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
        <Form<URLRuleFormValues>
          form={form}
          layout="vertical"
          initialValues={{
            scope_type: 'GLOBAL',
            match_type: 'EXACT',
            validity_type: 'PERMANENT',
            priority: 100,
            methods: [],
          }}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Form.Item
            name="name"
            label="规则名称"
            rules={[
              { required: true, message: '请输入规则名称' },
              { max: 200, message: '不超过 200 个字符' },
            ]}
          >
            <Input placeholder="如：健康检查接口放行" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item
              name="scope_type"
              label="生效范围"
              style={{ width: '50%', marginRight: 8 }}
              rules={[{ required: true }]}
            >
              <Select
                disabled={!!editing}
                options={Object.entries(ACCESS_RULE_SCOPE_META).map(([value, meta]) => ({
                  value,
                  label: meta.label,
                }))}
              />
            </Form.Item>
            <Form.Item
              name="match_type"
              label="匹配方式"
              style={{ width: '50%' }}
              rules={[{ required: true }]}
            >
              <Select
                options={Object.entries(URL_WHITELIST_MATCH_META).map(([value, meta]) => ({
                  value,
                  label: meta.label,
                }))}
              />
            </Form.Item>
          </Space.Compact>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.scope_type !== cur.scope_type}>
            {({ getFieldValue }) =>
              getFieldValue('scope_type') === 'APPLICATION' && (
                <Form.Item
                  name="application_id"
                  label="目标应用"
                  rules={[{ required: true, message: '应用级规则必须选择应用' }]}
                >
                  <Select
                    showSearch
                    optionFilterProp="label"
                    placeholder="选择应用"
                    disabled={!!editing}
                    loading={appsQuery.isLoading}
                    options={appOptions}
                  />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item
            name="uri_pattern"
            label="URL 路径 / 正则"
            dependencies={['match_type']}
            rules={[
              { required: true, message: '请输入 URL 路径或正则' },
              ({ getFieldValue }) => ({
                validator: (_, value: string) => {
                  const err = validateURIPattern(getFieldValue('match_type'), value ?? '')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              }),
            ]}
            extra="精确/前缀匹配须以 / 开头且不含查询参数；前缀匹配按路径段边界生效（如 /api 不误放 /api-admin）"
          >
            <Input placeholder="如 /healthz、/api/public 或 ^/webhooks/[0-9]+/notify$" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="methods"
            label="限定 HTTP 方法（留空匹配全部方法）"
          >
            <Select
              mode="multiple"
              allowClear
              placeholder="留空表示不限制方法"
              options={HTTP_METHODS.map((m) => ({ value: m, label: m }))}
            />
          </Form.Item>
          <Form.Item name="priority" label="优先级（数值小者优先）">
            <InputNumber min={0} max={10000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="validity_type" label="有效期类型" rules={[{ required: true }]}>
            <Radio.Group
              options={Object.entries(ACCESS_RULE_VALIDITY_META).map(([value, meta]) => ({
                value,
                label: meta.label,
              }))}
              optionType="button"
            />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.validity_type !== cur.validity_type}>
            {({ getFieldValue }) =>
              getFieldValue('validity_type') === 'TEMPORARY' && (
                <>
                  <Form.Item
                    name="until_preset"
                    label="失效时间"
                    rules={[{ required: true, message: '请选择失效时间' }]}
                  >
                    <Select
                      placeholder="选择失效时长"
                      options={UNTIL_PRESETS.map((p) => ({ value: p.value, label: p.label }))}
                    />
                  </Form.Item>
                  <Form.Item noStyle shouldUpdate={(prev, cur) => prev.until_preset !== cur.until_preset}>
                    {({ getFieldValue: get2 }) =>
                      get2('until_preset') === 'CUSTOM' && (
                        <Form.Item
                          name="until_custom"
                          label="自定义失效时间"
                          rules={[{ required: true, message: '请选择自定义失效时间' }]}
                        >
                          <DatePicker
                            showTime
                            style={{ width: '100%' }}
                            disabledDate={(d) => d.isBefore(dayjs().startOf('day'))}
                          />
                        </Form.Item>
                      )
                    }
                  </Form.Item>
                </>
              )
            }
          </Form.Item>
          <Form.Item name="effective_from" label="生效时间（留空立即生效）">
            <DatePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="reason" label="放行原因" rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} placeholder="设置该白名单的原因（审计要求，可选）" />
          </Form.Item>
        </Form>
      </Drawer>

      <Modal
        title={`延期临时规则「${extending?.name ?? ''}」`}
        open={extending !== null}
        onCancel={() => setExtending(null)}
        onOk={() => extendForm.submit()}
        confirmLoading={extendMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          当前失效时间：{formatDateTime(extending?.effective_until)}；新失效时间自当前时刻起算，必须晚于当前时间。
        </Typography.Paragraph>
        <Form<ExtendFormValues>
          form={extendForm}
          layout="vertical"
          onFinish={(values) => {
            const until = resolveEffectiveUntil(values.until_preset, values.until_custom)
            if (!until) {
              message.error('请选择新的失效时间')
              return
            }
            if (extending) extendMutation.mutate({ id: extending.id, until })
          }}
        >
          <Form.Item
            name="until_preset"
            label="新的失效时间"
            rules={[{ required: true, message: '请选择失效时间' }]}
          >
            <Select options={UNTIL_PRESETS.map((p) => ({ value: p.value, label: p.label }))} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.until_preset !== cur.until_preset}>
            {({ getFieldValue }) =>
              getFieldValue('until_preset') === 'CUSTOM' && (
                <Form.Item
                  name="until_custom"
                  label="自定义失效时间"
                  rules={[{ required: true, message: '请选择自定义失效时间' }]}
                >
                  <DatePicker
                    showTime
                    style={{ width: '100%' }}
                    disabledDate={(d) => d.isBefore(dayjs().startOf('day'))}
                  />
                </Form.Item>
              )
            }
          </Form.Item>
        </Form>
      </Modal>

      <Drawer
        title={`关联事件${eventsRule ? `：${eventsRule.name}（${eventsRule.uri_pattern}）` : ''}`}
        open={eventsRule !== null}
        onClose={() => setEventsRule(null)}
        width={900}
        destroyOnHidden
      >
        {ruleEventsQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载规则关联事件失败"
            description={ruleEventsQuery.error instanceof ApiError ? ruleEventsQuery.error.message : undefined}
          />
        ) : (
          <SmartTable<AccessControlEventItem>
            storageKey="url-whitelist-rule-events"
            rowKey="id"
            loading={ruleEventsQuery.isLoading}
            dataSource={ruleEventsQuery.data?.items}
            scroll={{ x: 860 }}
            columns={[
              {
                title: '时间',
                dataIndex: 'occurred_at',
                width: 165,
                render: (v: string) => formatDateTime(v),
              },
              {
                title: '事件类型',
                dataIndex: 'event_type',
                width: 150,
                render: (v: string) => <StatusTag value={v} map={AC_EVENT_TYPE_META} />,
              },
              {
                title: '客户端IP',
                dataIndex: 'client_ip',
                width: 130,
                render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
              },
              {
                title: '应用',
                dataIndex: 'application_code',
                width: 120,
                ellipsis: true,
                render: (v: string) => v || '全局',
              },
              { title: '路径', dataIndex: 'request_path', ellipsis: true, render: (v: string) => v || '-' },
              {
                title: '动作',
                dataIndex: 'action',
                width: 90,
                render: (v: string) => <StatusTag value={v} map={AC_EVENT_ACTION_META} />,
              },
            ]}
            pagination={{
              current: eventsPage,
              pageSize: eventsPageSize,
              total: ruleEventsQuery.data?.total ?? 0,
              showSizeChanger: true,
              showTotal: (t) => `共 ${t} 条`,
              onChange: (p, ps) => {
                setEventsPage(p)
                setEventsPageSize(ps)
              },
            }}
          />
        )}
      </Drawer>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="URL 白名单规则详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
