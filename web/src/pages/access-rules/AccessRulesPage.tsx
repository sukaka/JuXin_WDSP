import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
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
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CloudUploadOutlined,
  DownloadOutlined,
  ImportOutlined,
  PlusOutlined,
} from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { accessRulesApi } from '../../api/accessRules'
import type { ImportAccessRulesBody } from '../../api/accessRules'
import { applicationsApi } from '../../api/applications'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { PublishTaskProgress } from '../config-publish/ConfigPublishPage'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  ACCESS_RULE_SCOPE_META,
  ACCESS_RULE_SOURCE_META,
  ACCESS_RULE_STATUS_META,
  ACCESS_RULE_TYPE_META,
  ACCESS_RULE_VALIDITY_META,
  AC_EVENT_ACTION_META,
  AC_EVENT_TYPE_META,
  validateIPOrCIDR,
} from '../../utils/stage5'
import type { AccessControlEventItem, AccessRuleImportResult, AccessRuleItem } from '../../types'

interface Filters {
  rule_type?: string
  scope_type?: string
  status?: string
  source_type?: string
  keyword?: string
}

/** 临时有效期预设（秒），CUSTOM 表示自定义时间 */
const UNTIL_PRESETS: { value: string; label: string; seconds?: number }[] = [
  { value: '15m', label: '15 分钟', seconds: 15 * 60 },
  { value: '1h', label: '1 小时', seconds: 60 * 60 },
  { value: '4h', label: '4 小时', seconds: 4 * 60 * 60 },
  { value: '1d', label: '1 天', seconds: 24 * 60 * 60 },
  { value: '7d', label: '7 天', seconds: 7 * 24 * 60 * 60 },
  { value: '30d', label: '30 天', seconds: 30 * 24 * 60 * 60 },
  { value: 'CUSTOM', label: '自定义' },
]

/** 按预设/自定义计算失效时间 ISO 字符串 */
function resolveEffectiveUntil(preset: string | undefined, custom: dayjs.Dayjs | null | undefined): string | null {
  if (!preset) return null
  if (preset === 'CUSTOM') return custom ? custom.toISOString() : null
  const p = UNTIL_PRESETS.find((x) => x.value === preset)
  return p?.seconds ? dayjs().add(p.seconds, 'second').toISOString() : null
}

interface RuleFormValues {
  name: string
  rule_type: string
  scope_type: string
  application_id?: string
  address: string
  priority?: number
  validity_type: string
  effective_from?: dayjs.Dayjs | null
  until_preset?: string
  until_custom?: dayjs.Dayjs | null
  reason?: string
}

interface ExtendFormValues {
  until_preset: string
  until_custom?: dayjs.Dayjs | null
}

interface ImportFormValues {
  format: 'csv' | 'text'
  mode: 'ALL_OR_NOTHING' | 'SKIP_ERRORS'
  rule_type: string
  scope_type: string
  application_id?: string
  effective_until?: dayjs.Dayjs | null
  reason?: string
  content: string
}

/** 有效期单元格：类型 + 到期时间 */
function ValidityCell({ record }: { record: AccessRuleItem }) {
  return (
    <Space size={4}>
      <StatusTag value={record.validity_type} map={ACCESS_RULE_VALIDITY_META} />
      {record.validity_type === 'TEMPORARY' && (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {formatDateTime(record.effective_until)} 止
        </Typography.Text>
      )}
    </Space>
  )
}

export default function AccessRulesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'access_rules.manage')
  const canImport = hasPermission(permissions, 'access_rules.import')
  const canPublish = hasPermission(permissions, 'access_rules.publish')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<AccessRuleItem | null>(null)
  const [extending, setExtending] = useState<AccessRuleItem | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [preview, setPreview] = useState<AccessRuleImportResult | null>(null)
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null)
  const [detailRecord, setDetailRecord] = useState<AccessRuleItem | null>(null)
  const [eventsRule, setEventsRule] = useState<AccessRuleItem | null>(null)
  const [eventsPage, setEventsPage] = useState(1)
  const [eventsPageSize, setEventsPageSize] = useState(20)
  const [form] = Form.useForm<RuleFormValues>()
  const [extendForm] = Form.useForm<ExtendFormValues>()
  const [importForm] = Form.useForm<ImportFormValues>()

  const listQuery = useQuery({
    queryKey: ['access-rules', filters, page, pageSize],
    queryFn: () => accessRulesApi.list({ ...filters, page, page_size: pageSize }),
  })

  // 规则关联事件（§8.5）：抽屉内按规则 ID 过滤访问控制事件
  const ruleEventsQuery = useQuery({
    queryKey: ['access-rule-events', eventsRule?.id, eventsPage, eventsPageSize],
    queryFn: () => accessRulesApi.listEvents(eventsRule!.id, { page: eventsPage, page_size: eventsPageSize }),
    enabled: eventsRule !== null,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<AccessRuleItem>({
    remove: (id) => accessRulesApi.remove(id),
    invalidateKeys: [['access-rules']],
    entityName: '黑白名单规则',
    canDelete: canManage,
  })

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-access-rule'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: formOpen || importOpen,
  })

  const appOptions = (appsQuery.data?.items ?? []).map((a) => ({
    value: a.id,
    label: `${a.name}（${a.code}）`,
  }))

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['access-rules'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveMutation = useMutation({
    mutationFn: (values: RuleFormValues) => {
      const effectiveUntil =
        values.validity_type === 'TEMPORARY'
          ? resolveEffectiveUntil(values.until_preset, values.until_custom)
          : null
      if (values.validity_type === 'TEMPORARY' && !effectiveUntil) {
        return Promise.reject(new ApiError('临时规则必须设置失效时间', 'INVALID', 0))
      }
      if (editing) {
        return accessRulesApi.update(editing.id, {
          name: values.name,
          address: values.address,
          priority: values.priority,
          validity_type: values.validity_type,
          effective_from: values.effective_from ? values.effective_from.toISOString() : null,
          effective_until: effectiveUntil,
          reason: values.reason ?? '',
          version: editing.version,
        })
      }
      return accessRulesApi.create({
        name: values.name,
        rule_type: values.rule_type,
        scope_type: values.scope_type,
        application_id: values.scope_type === 'APPLICATION' ? values.application_id : null,
        address: values.address,
        priority: values.priority,
        validity_type: values.validity_type,
        effective_from: values.effective_from ? values.effective_from.toISOString() : null,
        effective_until: effectiveUntil,
        reason: values.reason ?? '',
      })
    },
    onSuccess: () => {
      message.success(editing ? '规则已更新' : '规则已创建')
      setFormOpen(false)
      setEditing(null)
      form.resetFields()
      void invalidate()
    },
    onError,
  })

  const actionMutation = useMutation({
    mutationFn: ({
      id,
      action,
    }: {
      id: string
      action: 'enable' | 'disable' | 'release' | 'copy'
    }): Promise<unknown> => {
      switch (action) {
        case 'enable':
          return accessRulesApi.enable(id)
        case 'disable':
          return accessRulesApi.disable(id)
        case 'release':
          return accessRulesApi.release(id)
        case 'copy':
          return accessRulesApi.copy(id)
      }
    },
    onSuccess: (_data, vars) => {
      message.success(vars.action === 'copy' ? '规则副本已创建' : '操作成功')
      void invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => accessRulesApi.remove(id),
    onSuccess: () => {
      message.success('规则已删除')
      void invalidate()
    },
    onError,
  })

  const extendMutation = useMutation({
    mutationFn: ({ id, until }: { id: string; until: string }) => accessRulesApi.extend(id, until),
    onSuccess: () => {
      message.success('规则已延期')
      setExtending(null)
      extendForm.resetFields()
      void invalidate()
    },
    onError,
  })

  const importMutation = useMutation({
    mutationFn: (body: ImportAccessRulesBody) => accessRulesApi.import(body),
    onSuccess: (data, vars) => {
      if (vars.dry_run) {
        setPreview(data)
      } else {
        message.success(`导入完成：成功 ${data.imported ?? 0} 条（草稿状态，需启用后才生效），失败 ${data.invalid} 条`)
        setImportOpen(false)
        setPreview(null)
        importForm.resetFields()
        void invalidate()
      }
    },
    onError,
  })

  const publishMutation = useMutation({
    mutationFn: () => accessRulesApi.publish(crypto.randomUUID()),
    onSuccess: (task) => {
      setActiveTaskId(task.id)
      if (task.status === 'SUCCESS') message.success('发布成功')
      else if (task.status === 'FAILED') message.error('发布失败，请查看任务详情')
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '发布失败'),
  })

  const buildImportBody = (values: ImportFormValues, dryRun: boolean): ImportAccessRulesBody => ({
    content: values.content,
    format: values.format,
    mode: values.mode,
    rule_type: values.rule_type,
    scope_type: values.scope_type,
    application_id: values.scope_type === 'APPLICATION' ? values.application_id : null,
    effective_until: values.effective_until ? values.effective_until.toISOString() : null,
    reason: values.reason ?? '',
    dry_run: dryRun,
  })

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    setFormOpen(true)
  }

  const openEdit = (record: AccessRuleItem) => {
    setEditing(record)
    form.setFieldsValue({
      name: record.name,
      rule_type: record.rule_type,
      scope_type: record.scope_type,
      application_id: record.application_id ?? undefined,
      address: record.address,
      priority: record.priority,
      validity_type: record.validity_type,
      effective_from: record.effective_from ? dayjs(record.effective_from) : null,
      until_preset: 'CUSTOM',
      until_custom: record.effective_until ? dayjs(record.effective_until) : null,
      reason: record.reason || undefined,
    })
    setFormOpen(true)
  }

  /** 行内操作统一二次确认 */
  const confirmAction = (
    record: AccessRuleItem,
    action: 'enable' | 'disable' | 'release' | 'copy',
  ) => {
    const typeLabel = ACCESS_RULE_TYPE_META[record.rule_type]?.label ?? record.rule_type
    const contentMap: Record<typeof action, string> = {
      enable: `确定启用${typeLabel}规则「${record.name}」吗？启用后立即参与访问控制判定。${
        record.status === 'DRAFT' ? '（当前为导入/AI 生成的草稿，启用后进入生效状态）' : ''
      }`,
      disable: `确定停用${typeLabel}规则「${record.name}」吗？停用后该规则不再生效。`,
      release: `确定解封临时规则「${record.name}」（${record.address}）吗？解封后该地址的访问限制立即解除。`,
      copy: `确定复制规则「${record.name}」吗？将创建一条同配置的手工规则副本。`,
    }
    modal.confirm({
      title: '操作确认',
      content: contentMap[action],
      onOk: () => actionMutation.mutate({ id: record.id, action }),
    })
  }

  const confirmDelete = (record: AccessRuleItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除规则「${record.name}」（${record.address}）吗？删除后对应地址的访问控制立即失效。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const confirmPublish = () => {
    modal.confirm({
      title: '高风险操作确认',
      content: '发布将把当前访问控制（可信代理/黑白名单/CC策略）配置下发到防护网关并立即生效。确定执行发布吗？',
      okText: '确认发布',
      okButtonProps: { danger: true },
      onOk: () => publishMutation.mutate(),
    })
  }

  const columns: ColumnsType<AccessRuleItem> = [
    { title: '名称', dataIndex: 'name', width: 160, ellipsis: true },
    {
      title: '类型',
      dataIndex: 'rule_type',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ACCESS_RULE_TYPE_META} />,
    },
    {
      title: '范围',
      dataIndex: 'scope_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={ACCESS_RULE_SCOPE_META} />,
    },
    {
      title: '地址',
      dataIndex: 'address',
      width: 150,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
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
      width: 200,
      render: (_, record) => <ValidityCell record={record} />,
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
      width: 320,
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
                    解封
                  </Button>
                </>
              )}
              <Button type="link" size="small" onClick={() => confirmAction(record, 'copy')}>
                复制
              </Button>
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
      title="IP 黑白名单"
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
          <Button
            icon={<DownloadOutlined />}
            onClick={() =>
              window.open(
                accessRulesApi.exportUrl({
                  rule_type: filters.rule_type,
                  scope_type: filters.scope_type,
                  status: filters.status,
                  source_type: filters.source_type,
                  keyword: filters.keyword,
                }),
                '_blank',
              )
            }
          >
            导出
          </Button>
          {canImport && (
            <Button
              icon={<ImportOutlined />}
              onClick={() => {
                setPreview(null)
                importForm.resetFields()
                setImportOpen(true)
              }}
            >
              导入
            </Button>
          )}
          {canManage && (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              新建规则
            </Button>
          )}
        </Space>
      }
    >
      {activeTaskId && <PublishTaskProgress taskId={activeTaskId} />}
      <Space style={{ marginBottom: 16, marginTop: activeTaskId ? 16 : 0 }} wrap>
        <Select
          placeholder="规则类型"
          allowClear
          style={{ width: 120 }}
          options={Object.entries(ACCESS_RULE_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, rule_type: v }))
            setPage(1)
          }}
        />
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
          options={Object.entries(ACCESS_RULE_SOURCE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, source_type: v }))
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="名称 / 地址"
          allowClear
          style={{ width: 200 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, keyword: v || undefined }))
            setPage(1)
          }}
        />
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载黑白名单失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<AccessRuleItem>
          storageKey="access-rules"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1500 }}
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
        title={editing ? '编辑规则' : '新建规则'}
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
        <Form<RuleFormValues>
          form={form}
          layout="vertical"
          initialValues={{ rule_type: 'DENY', scope_type: 'GLOBAL', validity_type: 'PERMANENT', priority: 100 }}
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
            <Input placeholder="如：封禁恶意扫描源" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="rule_type" label="规则类型" style={{ width: '50%', marginRight: 8 }} rules={[{ required: true }]}>
              <Select
                disabled={!!editing}
                options={Object.entries(ACCESS_RULE_TYPE_META).map(([value, meta]) => ({
                  value,
                  label: meta.label,
                }))}
              />
            </Form.Item>
            <Form.Item name="scope_type" label="生效范围" style={{ width: '50%' }} rules={[{ required: true }]}>
              <Select
                disabled={!!editing}
                options={Object.entries(ACCESS_RULE_SCOPE_META).map(([value, meta]) => ({
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
            name="address"
            label="地址（单 IP 或 CIDR）"
            rules={[
              { required: true, message: '请输入地址' },
              {
                validator: (_, v: string) => {
                  const err = validateIPOrCIDR(v ?? '')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
            extra="禁止域名、协议前缀、端口与通配符；黑名单地址命中保护地址时将被后端拒绝"
          >
            <Input placeholder="如 203.0.113.66 或 198.51.100.0/24" autoComplete="off" />
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
          <Form.Item name="reason" label="原因说明" rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} placeholder="设置该规则的原因（审计要求，可选）" />
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

      <Modal
        title="批量导入规则"
        open={importOpen}
        onCancel={() => {
          setImportOpen(false)
          setPreview(null)
        }}
        footer={null}
        width={820}
        destroyOnHidden
      >
        <Form<ImportFormValues>
          form={importForm}
          layout="vertical"
          initialValues={{ format: 'csv', rule_type: 'DENY', scope_type: 'GLOBAL' }}
        >
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message="导入成功的规则为「草稿」状态，不随发布生效，需在列表中逐条启用后才参与访问控制判定"
          />
          <Space.Compact block>
            <Form.Item name="format" label="格式" style={{ width: '24%', marginRight: 8 }} rules={[{ required: true }]}>
              <Select
                options={[
                  { value: 'csv', label: '表格文件（含表头）' },
                  { value: 'text', label: '纯文本（每行一个地址）' },
                ]}
              />
            </Form.Item>
            <Form.Item name="rule_type" label="默认规则类型" style={{ width: '24%', marginRight: 8 }} rules={[{ required: true }]}>
              <Select
                options={Object.entries(ACCESS_RULE_TYPE_META).map(([value, meta]) => ({
                  value,
                  label: meta.label,
                }))}
              />
            </Form.Item>
            <Form.Item name="scope_type" label="默认生效范围" style={{ width: '24%', marginRight: 8 }} rules={[{ required: true }]}>
              <Select
                options={Object.entries(ACCESS_RULE_SCOPE_META).map(([value, meta]) => ({
                  value,
                  label: meta.label,
                }))}
              />
            </Form.Item>
            <Form.Item name="effective_until" label="统一失效时间（可选）" style={{ width: '28%' }}>
              <DatePicker showTime style={{ width: '100%' }} />
            </Form.Item>
          </Space.Compact>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.scope_type !== cur.scope_type}>
            {({ getFieldValue }) =>
              getFieldValue('scope_type') === 'APPLICATION' && (
                <Form.Item
                  name="application_id"
                  label="默认目标应用"
                  rules={[{ required: true, message: '应用级导入必须选择应用' }]}
                >
                  <Select
                    showSearch
                    optionFilterProp="label"
                    placeholder="选择应用"
                    loading={appsQuery.isLoading}
                    options={appOptions}
                  />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item
            name="mode"
            label="导入模式（必选）"
            rules={[{ required: true, message: '必须选择导入模式' }]}
            extra="全部成功才提交：任一行错误则整体不导入；跳过错误行：合法行逐条导入，失败行跳过"
          >
            <Radio.Group
              options={[
                { value: 'ALL_OR_NOTHING', label: '全部成功才提交' },
                { value: 'SKIP_ERRORS', label: '跳过错误行' },
              ]}
            />
          </Form.Item>
          <Form.Item
            name="content"
            label="导入内容（≤ 1MB，≤ 10000 行）"
            rules={[{ required: true, message: '请粘贴导入内容' }]}
            extra="CSV 表头须含 address 列，支持列：address,rule_type,scope_type,application_code,effective_until,reason"
          >
            <Input.TextArea
              rows={8}
              placeholder={'address,rule_type,scope_type\n203.0.113.66,DENY,GLOBAL\n198.51.100.0/24,DENY,GLOBAL'}
              style={{ fontFamily: 'monospace' }}
            />
          </Form.Item>
          <Space>
            <Button
              loading={importMutation.isPending && importMutation.variables?.dry_run === true}
              onClick={() =>
                importForm.validateFields().then((values) => {
                  setPreview(null)
                  importMutation.mutate(buildImportBody(values as ImportFormValues, true))
                })
              }
            >
              校验预览
            </Button>
            <Button
              type="primary"
              disabled={!preview}
              loading={importMutation.isPending && importMutation.variables?.dry_run === false}
              onClick={() =>
                importForm.validateFields().then((values) => {
                  const doImport = () => importMutation.mutate(buildImportBody(values as ImportFormValues, false))
                  if (preview && preview.invalid > 0) {
                    modal.confirm({
                      title: '存在错误行',
                      content: `预览发现 ${preview.invalid} 行错误。${
                        (values as ImportFormValues).mode === 'ALL_OR_NOTHING'
                          ? '按「全部成功才提交」模式，本次导入将整体失败。'
                          : '按「跳过错误行」模式，错误行将被跳过。'
                      }仍要导入吗？`,
                      onOk: doImport,
                    })
                  } else {
                    doImport()
                  }
                })
              }
            >
              确认导入
            </Button>
          </Space>
        </Form>

        {preview && (
          <Alert
            style={{ marginTop: 16 }}
            type={preview.invalid > 0 ? 'warning' : 'success'}
            showIcon
            message={`预览结果：共 ${preview.total} 行，合法 ${preview.valid} 行，错误 ${preview.invalid} 行`}
            description={
              preview.errors.length > 0 ? (
                <SmartTable
                  storageKey="access-rules-import-preview"
                  style={{ marginTop: 8 }}
                  rowKey="line"
                  size="small"
                  pagination={{ pageSize: 5 }}
                  dataSource={preview.errors}
                  columns={[
                    { title: '行号', dataIndex: 'line', width: 70 },
                    { title: '内容', dataIndex: 'content', width: 200, ellipsis: true },
                    { title: '错误', dataIndex: 'error', ellipsis: true },
                    {
                      title: '错误码',
                      dataIndex: 'code',
                      width: 130,
                      render: (v: string) => {
                        const meta: Record<string, { color: string; label: string }> = {
                          PROTECTED: { color: 'red', label: '受保护地址' },
                          INVALID: { color: 'orange', label: '格式非法' },
                          DUPLICATE: { color: 'orange', label: '重复' },
                          CONFLICT: { color: 'orange', label: '冲突' },
                        }
                        const m = meta[v]
                        return <Tag color={m?.color ?? 'orange'}>{m?.label ?? v}</Tag>
                      },
                    },
                  ]}
                />
              ) : undefined
            }
          />
        )}
      </Modal>

      <Drawer
        title={`关联事件${eventsRule ? `：${eventsRule.name}（${eventsRule.address}）` : ''}`}
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
            storageKey="access-rule-events"
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
        title="规则详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
