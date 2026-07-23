import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined, WarningOutlined } from '@ant-design/icons'
import type dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import { protectionPoliciesApi } from '../../api/protectionPolicies'
import { exceptionsApi } from '../../api/exceptions'
import type { CreateExceptionBody } from '../../api/exceptions'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  ATTACK_TYPE_OPTIONS,
  EXCEPTION_ACTION_META,
  EXCEPTION_SCOPE_META,
  EXCEPTION_STATUS_META,
  isBroadExceptionDraft,
} from '../../utils/stage4'
import type { ExceptionItem } from '../../types'

interface Filters {
  scope_type?: string
  status?: string
}

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => ({
  value: m,
  label: m,
}))

const ACTION_OPTIONS = Object.entries(EXCEPTION_ACTION_META).map(([value, meta]) => ({
  value,
  label: `${value} ${meta.label}`,
}))

const IP_CIDR_PATTERN =
  /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?$/

interface ExceptionFormValues {
  name: string
  description?: string
  scope_type: string
  application_id?: string
  policy_id?: string
  domain?: string
  uri_exact?: string
  uri_prefix?: string
  uri_regex?: string
  methods?: string[]
  source_ips?: string[]
  param_names?: string[]
  cookie_names?: string[]
  header_names?: string[]
  rule_ids?: string[]
  rule_tags?: string[]
  attack_types?: string[]
  content_types?: string[]
  exception_action: CreateExceptionBody['exception_action']
  action_target?: string
  is_temporary?: boolean
  effective_range?: [dayjs.Dayjs | null, dayjs.Dayjs | null]
  reason?: string
  risk_acknowledged?: boolean
}

/** 行数据是否属于宽泛例外（镜像后端判定，用于列表风险提示） */
function rowIsBroad(record: ExceptionItem): boolean {
  return isBroadExceptionDraft({
    scope_type: record.scope_type,
    application_id: record.application_id,
    domain: record.domain,
    uri_exact: record.uri_exact,
    uri_prefix: record.uri_prefix,
    source_ips: record.source_ips ?? [],
    param_names: record.param_names ?? [],
    cookie_names: record.cookie_names ?? [],
    header_names: record.header_names ?? [],
    rule_ids: record.rule_ids ?? [],
    rule_tags: record.rule_tags ?? [],
    attack_types: record.attack_types ?? [],
  })
}

export default function ExceptionsPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'exceptions.manage')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [form] = Form.useForm<ExceptionFormValues>()

  // 监听表单字段，实时判定宽泛例外
  const watched = Form.useWatch([], form) as ExceptionFormValues | undefined
  const isBroad = useMemo(
    () =>
      isBroadExceptionDraft({
        scope_type: watched?.scope_type,
        application_id: watched?.application_id || null,
        domain: watched?.domain,
        uri_exact: watched?.uri_exact,
        uri_prefix: watched?.uri_prefix,
        source_ips: watched?.source_ips,
        param_names: watched?.param_names,
        cookie_names: watched?.cookie_names,
        header_names: watched?.header_names,
        rule_ids: (watched?.rule_ids ?? [])
          .map((s) => Number(s))
          .filter((n) => Number.isInteger(n) && n > 0),
        rule_tags: watched?.rule_tags,
        attack_types: watched?.attack_types,
      }),
    [watched],
  )

  const listQuery = useQuery({
    queryKey: ['exceptions', filters, page, pageSize],
    queryFn: () => exceptionsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['exception', detailId],
    queryFn: () => exceptionsApi.get(detailId as string),
    enabled: detailId !== null,
  })

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-exception'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: createOpen,
  })

  const policiesQuery = useQuery({
    queryKey: ['protection-policies', 'all-for-exception'],
    queryFn: () => protectionPoliciesApi.list({ page: 1, page_size: 100 }),
    enabled: createOpen,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['exceptions'] })

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (body: CreateExceptionBody) => exceptionsApi.create(body),
    onSuccess: (data) => {
      setCreateOpen(false)
      form.resetFields()
      if (data.is_broad) {
        message.warning('宽泛例外已创建，请密切关注其影响范围')
      } else {
        message.success('例外策略创建成功')
      }
      void invalidate()
    },
    onError,
  })

  const statusMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'enable' | 'disable' }) =>
      action === 'enable' ? exceptionsApi.enable(id) : exceptionsApi.disable(id),
    onSuccess: () => {
      message.success('操作成功')
      void invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => exceptionsApi.remove(id),
    onSuccess: () => {
      message.success('例外已删除')
      void invalidate()
    },
    onError,
  })

  const confirmDelete = (record: ExceptionItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除例外策略「${record.name}」吗？删除后对应规则的豁免将失效。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const submitCreate = (values: ExceptionFormValues) => {
    const ruleIds = (values.rule_ids ?? []).map((s) => Number(s))
    if (ruleIds.some((n) => !Number.isInteger(n) || n <= 0)) {
      message.error('规则ID必须为正整数')
      return
    }
    const [from, until] = values.effective_range ?? [null, null]
    createMutation.mutate({
      name: values.name,
      description: values.description ?? '',
      scope_type: values.scope_type,
      application_id: values.scope_type === 'APPLICATION' ? values.application_id || null : null,
      policy_id: values.scope_type === 'POLICY' ? values.policy_id || null : null,
      domain: values.domain ?? '',
      uri_exact: values.uri_exact ?? '',
      uri_prefix: values.uri_prefix ?? '',
      uri_regex: values.uri_regex ?? '',
      methods: values.methods ?? [],
      source_ips: values.source_ips ?? [],
      param_names: values.param_names ?? [],
      cookie_names: values.cookie_names ?? [],
      header_names: values.header_names ?? [],
      rule_ids: ruleIds,
      rule_tags: values.rule_tags ?? [],
      attack_types: values.attack_types ?? [],
      content_types: values.content_types ?? [],
      exception_action: values.exception_action,
      action_target: values.action_target ?? '',
      is_temporary: values.is_temporary ?? false,
      effective_from: from ? from.toISOString() : null,
      effective_until: until ? until.toISOString() : null,
      risk_acknowledged: values.risk_acknowledged ?? false,
      reason: values.reason ?? '',
    })
  }

  const columns: ColumnsType<ExceptionItem> = [
    {
      title: '名称',
      dataIndex: 'name',
      width: 200,
      ellipsis: true,
      render: (v: string, record) => <a onClick={() => setDetailId(record.id)}>{v}</a>,
    },
    {
      title: '范围',
      dataIndex: 'scope_type',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={EXCEPTION_SCOPE_META} />,
    },
    {
      title: '类型',
      key: 'kind',
      width: 130,
      render: (_, record) => (
        <Space size={4}>
          {record.is_temporary ? <Tag color="gold">临时</Tag> : <Tag>精确</Tag>}
          {rowIsBroad(record) && (
            <Tag icon={<WarningOutlined />} color="red">
              宽泛
            </Tag>
          )}
        </Space>
      ),
    },
    {
      title: '动作',
      dataIndex: 'exception_action',
      width: 190,
      render: (v: string) => <StatusTag value={v} map={EXCEPTION_ACTION_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={EXCEPTION_STATUS_META} />,
    },
    {
      title: '生效时间',
      dataIndex: 'effective_from',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '失效时间',
      dataIndex: 'effective_until',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
            详情
          </Button>
          {canManage && record.status !== 'EXPIRED' && (
            <>
              {record.status === 'ENABLED' ? (
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

  const detail = detailQuery.data
  const exc = detail?.exception

  const scopeOptions = Object.entries(EXCEPTION_SCOPE_META).map(([value, meta]) => ({
    value,
    label: meta.label,
  }))

  const listSection = (label: string, values?: (string | number)[] | null) => (
    <Descriptions.Item label={label} span={2}>
      {values && values.length > 0 ? (
        <Space wrap>
          {values.map((v) => (
            <Tag key={String(v)}>{String(v)}</Tag>
          ))}
        </Space>
      ) : (
        '-'
      )}
    </Descriptions.Item>
  )

  return (
    <Card
      title="例外策略"
      extra={
        canManage && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建例外
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="范围类型"
          allowClear
          style={{ width: 140 }}
          options={scopeOptions}
          onChange={(v) => {
            setFilters((f) => ({ ...f, scope_type: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 130 }}
          options={Object.entries(EXCEPTION_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, status: v }))
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载例外策略失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<ExceptionItem>
          storageKey="exceptions"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1250 }}
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

      <Modal
        title="新建例外策略"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={createMutation.isPending}
        width={720}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ scope_type: 'APPLICATION', exception_action: 'REMOVE_RULE', is_temporary: false }}
          onFinish={submitCreate}
        >
          <Form.Item
            name="name"
            label="例外名称"
            rules={[
              { required: true, message: '请输入例外名称' },
              { max: 128, message: '不超过 128 个字符' },
            ]}
          >
            <Input placeholder="如：管理后台导出接口误报豁免" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} placeholder="例外用途说明（可选）" />
          </Form.Item>
          <Form.Item name="scope_type" label="范围类型" rules={[{ required: true }]}>
            <Select options={scopeOptions} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.scope_type !== cur.scope_type}>
            {({ getFieldValue }) => {
              const scope = getFieldValue('scope_type')
              if (scope === 'APPLICATION') {
                return (
                  <Form.Item name="application_id" label="目标应用">
                    <Select
                      allowClear
                      showSearch
                      optionFilterProp="label"
                      placeholder="选择应用（留空则对该范围全部应用生效）"
                      loading={appsQuery.isLoading}
                      options={(appsQuery.data?.items ?? []).map((a) => ({
                        value: a.id,
                        label: `${a.name}（${a.code}）`,
                      }))}
                    />
                  </Form.Item>
                )
              }
              if (scope === 'POLICY') {
                return (
                  <Form.Item name="policy_id" label="目标防护策略">
                    <Select
                      allowClear
                      showSearch
                      optionFilterProp="label"
                      placeholder="选择防护策略"
                      loading={policiesQuery.isLoading}
                      options={(policiesQuery.data?.items ?? []).map((p) => ({
                        value: p.id,
                        label: `${p.name}（${p.code}）`,
                      }))}
                    />
                  </Form.Item>
                )
              }
              return null
            }}
          </Form.Item>
          <Form.Item name="domain" label="域名" rules={[{ max: 255 }]}>
            <Input placeholder="如 api.example.com（可选）" autoComplete="off" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="uri_exact" label="路径精确匹配" style={{ width: '33%', marginRight: 8 }}>
              <Input placeholder="/api/export" autoComplete="off" />
            </Form.Item>
            <Form.Item name="uri_prefix" label="路径前缀匹配" style={{ width: '33%', marginRight: 8 }}>
              <Input placeholder="/api/" autoComplete="off" />
            </Form.Item>
            <Form.Item name="uri_regex" label="路径正则匹配" style={{ width: '33%' }}>
              <Input placeholder="^/api/v\d+/export$" autoComplete="off" />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="methods" label="HTTP 方法">
            <Select mode="multiple" options={METHOD_OPTIONS} placeholder="留空表示全部方法" />
          </Form.Item>
          <Form.Item
            name="source_ips"
            label="来源 IP / CIDR"
            rules={[
              {
                validator: (_, v: string[] | undefined) => {
                  const invalid = (v ?? []).filter((ip) => !IP_CIDR_PATTERN.test(ip))
                  return invalid.length > 0
                    ? Promise.reject(new Error(`无效的IP或CIDR：${invalid.join('、')}`))
                    : Promise.resolve()
                },
              },
            ]}
          >
            <Select mode="tags" open={false} placeholder="输入 IP 或 CIDR 后回车，如 10.0.0.0/8" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="param_names" label="参数名" style={{ width: '33%', marginRight: 8 }}>
              <Select mode="tags" open={false} placeholder="回车添加" />
            </Form.Item>
            <Form.Item name="cookie_names" label="Cookie 名称" style={{ width: '33%', marginRight: 8 }}>
              <Select mode="tags" open={false} placeholder="回车添加" />
            </Form.Item>
            <Form.Item name="header_names" label="请求头名" style={{ width: '33%' }}>
              <Select mode="tags" open={false} placeholder="回车添加" />
            </Form.Item>
          </Space.Compact>
          <Space.Compact block>
            <Form.Item name="rule_ids" label="规则ID" style={{ width: '33%', marginRight: 8 }}>
              <Select mode="tags" open={false} placeholder="如 942100，回车添加" />
            </Form.Item>
            <Form.Item name="rule_tags" label="规则标签" style={{ width: '33%', marginRight: 8 }}>
              <Select mode="tags" open={false} placeholder="如 attack-sqli" />
            </Form.Item>
            <Form.Item name="attack_types" label="攻击类型" style={{ width: '33%' }}>
              <Select mode="multiple" options={ATTACK_TYPE_OPTIONS} placeholder="选择攻击类型" />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="content_types" label="内容类型">
            <Select mode="tags" open={false} placeholder="如 application/json，回车添加" />
          </Form.Item>
          <Form.Item name="exception_action" label="例外动作" rules={[{ required: true }]}>
            <Select options={ACTION_OPTIONS} />
          </Form.Item>
          <Form.Item name="action_target" label="动作目标">
            <Input placeholder="调整评分时填写说明（可选）" autoComplete="off" />
          </Form.Item>
          <Form.Item name="is_temporary" label="临时例外" valuePropName="checked">
            <Switch checkedChildren="是" unCheckedChildren="否" />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.is_temporary !== cur.is_temporary}>
            {({ getFieldValue }) => (
              <Form.Item
                name="effective_range"
                label="生效 / 失效时间"
                rules={
                  getFieldValue('is_temporary')
                    ? [
                        { required: true, message: '临时例外必须设置生效与失效时间' },
                        {
                          validator: (_, v: [dayjs.Dayjs | null, dayjs.Dayjs | null] | undefined) =>
                            v?.[1]
                              ? Promise.resolve()
                              : Promise.reject(new Error('临时例外必须设置失效时间')),
                        },
                      ]
                    : undefined
                }
              >
                <DatePicker.RangePicker showTime style={{ width: '100%' }} />
              </Form.Item>
            )}
          </Form.Item>
          <Form.Item
            name="reason"
            label="例外原因"
            rules={[{ required: true, message: '请说明设置例外的原因（审计要求）' }]}
          >
            <Input.TextArea rows={2} placeholder="说明误报原因与评估结论" />
          </Form.Item>
          {isBroad && (
            <Alert
              type="error"
              showIcon
              icon={<WarningOutlined />}
              style={{ marginBottom: 16 }}
              message="高风险：当前配置属于宽泛例外"
              description="未限定具体 URI / 参数 / 规则ID / 来源IP 等条件，且作用于全部 SQLi/XSS/命令注入 攻击类型或全局范围，可能导致防护大面积失效。请补充限定条件；确需创建的，必须勾选下方风险确认。"
            />
          )}
          {isBroad && (
            <Form.Item
              name="risk_acknowledged"
              valuePropName="checked"
              rules={[
                {
                  validator: (_, v: boolean) =>
                    v
                      ? Promise.resolve()
                      : Promise.reject(new Error('宽泛例外必须确认风险后才能创建')),
                },
              ]}
            >
              <Checkbox>
                我已知晓该宽泛例外的风险，并承担相应责任（后端将校验，未确认会被拒绝）
              </Checkbox>
            </Form.Item>
          )}
        </Form>
      </Modal>

      <Drawer
        title="例外详情"
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={640}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载例外详情失败"
            description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          />
        ) : exc ? (
          <>
            {detail?.is_broad && (
              <Alert
                type="error"
                showIcon
                icon={<WarningOutlined />}
                style={{ marginBottom: 16 }}
                message="该例外为宽泛例外（高风险）"
                description="未设置具体限定条件，影响范围大，请定期复核并及时停用。"
              />
            )}
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="名称" span={2}>
                {exc.name}
              </Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>
                {exc.description || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="范围类型">
                <StatusTag value={exc.scope_type} map={EXCEPTION_SCOPE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={exc.status} map={EXCEPTION_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="应用ID">{exc.application_id ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="策略ID">{exc.policy_id ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="域名" span={2}>
                {exc.domain || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="路径精确">{exc.uri_exact || '-'}</Descriptions.Item>
              <Descriptions.Item label="路径前缀">{exc.uri_prefix || '-'}</Descriptions.Item>
              <Descriptions.Item label="路径正则" span={2}>
                {exc.uri_regex || '-'}
              </Descriptions.Item>
              {listSection('HTTP 方法', exc.methods)}
              {listSection('来源 IP', exc.source_ips)}
              {listSection('参数名', exc.param_names)}
              {listSection('Cookie 名', exc.cookie_names)}
              {listSection('请求头名', exc.header_names)}
              {listSection('规则ID', exc.rule_ids)}
              {listSection('规则标签', exc.rule_tags)}
              {listSection('攻击类型', exc.attack_types)}
              {listSection('Content-Type', exc.content_types)}
              <Descriptions.Item label="例外动作">
                <StatusTag value={exc.exception_action} map={EXCEPTION_ACTION_META} />
              </Descriptions.Item>
              <Descriptions.Item label="动作目标">{exc.action_target || '-'}</Descriptions.Item>
              <Descriptions.Item label="临时例外">
                {exc.is_temporary ? <Tag color="gold">是</Tag> : '否'}
              </Descriptions.Item>
              <Descriptions.Item label="风险确认">
                {exc.risk_acknowledged ? <Tag color="red">已确认</Tag> : '否'}
              </Descriptions.Item>
              <Descriptions.Item label="生效时间">{formatDateTime(exc.effective_from)}</Descriptions.Item>
              <Descriptions.Item label="失效时间">{formatDateTime(exc.effective_until)}</Descriptions.Item>
              <Descriptions.Item label="例外原因" span={2}>
                {exc.reason || '-'}
              </Descriptions.Item>
            </Descriptions>
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
