import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
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
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined, WarningOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import { protectionPoliciesApi } from '../../api/protectionPolicies'
import { exceptionsApi } from '../../api/exceptions'
import type { CreateExceptionBody } from '../../api/exceptions'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  deriveExceptionStatus,
  EXCEPTION_DERIVED_STATUS_META,
  getExceptionEnableBlockers,
  isActionSupportedForNewEnable,
} from '../../utils/exceptionStatus'
import {
  ATTACK_TYPE_OPTIONS,
  EXCEPTION_ACTION_META,
  EXCEPTION_SCOPE_META,
  EXCEPTION_STATUS_META,
  isBroadExceptionDraft,
} from '../../utils/stage4'
import type { ApiExceptionRuleRef, ExceptionItem, ExceptionTargetEngine } from '../../types'
import ExceptionPreviewPanel from './ExceptionPreviewPanel'

interface Filters {
  scope_type?: string
  status?: string
}

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => ({
  value: m,
  label: m,
}))

/** API 例外受支持 detector 注册表（S4 §3 首批，Finding.RuleID 稳定） */
const API_DETECTOR_OPTIONS = [
  { value: 'api_schema', label: 'api_schema（schema 违例）' },
  { value: 'api_parser', label: 'api_parser（参数/解析观测）' },
]

/**
 * 动作选项按目标引擎过滤（P0-04 S4 §3 动作矩阵）：
 * WAF：历史动作 LOG_ONLY / ADJUST_SCORE 显示为「不支持新启用」禁用项；
 * API：仅 OBSERVE_RULE。
 */
function buildActionOptions(
  engine: ExceptionTargetEngine,
): { value: string; label: ReactNode; disabled?: boolean }[] {
  if (engine === 'API') {
    return [
      {
        value: 'OBSERVE_RULE',
        label: `OBSERVE_RULE ${EXCEPTION_ACTION_META.OBSERVE_RULE.label}`,
      },
    ]
  }
  return Object.entries(EXCEPTION_ACTION_META)
    .filter(([value]) => value !== 'OBSERVE_RULE')
    .map(([value, meta]) => {
      const unsupported = !isActionSupportedForNewEnable('WAF', value)
      return {
        value,
        disabled: unsupported,
        label: unsupported ? (
          <Tooltip title="不支持新启用：禁止整请求仅观察/调分替代语义，请改用精确目标排除（REMOVE_VAR_DETECTION）">
            <span>{`${value} ${meta.label}（不支持新启用）`}</span>
          </Tooltip>
        ) : (
          `${value} ${meta.label}`
        ),
      }
    })
}

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
  target_engine?: ExceptionTargetEngine
  api_rule_refs?: ApiExceptionRuleRef[]
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
  const [editRecord, setEditRecord] = useState<ExceptionItem | null>(null)
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

  // 目标引擎驱动的动作选项（P0-04 S4 §3 动作矩阵）
  const watchedEngine: ExceptionTargetEngine = watched?.target_engine ?? 'WAF'
  const actionOptions = useMemo(() => buildActionOptions(watchedEngine), [watchedEngine])

  const listQuery = useQuery({
    queryKey: ['exceptions', filters, page, pageSize],
    queryFn: () => exceptionsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ExceptionItem>({
    remove: (id) => exceptionsApi.remove(id),
    invalidateKeys: [['exceptions']],
    entityName: '例外策略',
    canDelete: canManage,
  })

  const detailQuery = useQuery({
    queryKey: ['exception', detailId],
    queryFn: () => exceptionsApi.get(detailId as string),
    enabled: detailId !== null,
  })

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-exception'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: createOpen || editRecord !== null,
  })

  const policiesQuery = useQuery({
    queryKey: ['protection-policies', 'all-for-exception'],
    queryFn: () => protectionPoliciesApi.list({ page: 1, page_size: 100 }),
    enabled: createOpen || editRecord !== null,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['exceptions'] })

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const closeEditor = () => {
    setCreateOpen(false)
    setEditRecord(null)
    form.resetFields()
  }

  const createMutation = useMutation({
    mutationFn: (body: CreateExceptionBody) => exceptionsApi.create(body),
    onSuccess: (data) => {
      closeEditor()
      if (data.is_broad) {
        message.warning('宽泛例外已创建，请密切关注其影响范围')
      } else {
        message.success('例外策略创建成功')
      }
      void invalidate()
    },
    onError,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: CreateExceptionBody & { version: number } }) =>
      exceptionsApi.update(id, body),
    onSuccess: () => {
      message.success('例外草稿已保存；校验状态与编译指纹以服务端重算为准')
      closeEditor()
      void invalidate()
      void queryClient.invalidateQueries({ queryKey: ['exception'] })
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

  const buildBody = (values: ExceptionFormValues): CreateExceptionBody => {
    const ruleIds = (values.rule_ids ?? []).map((s) => Number(s))
    const [from, until] = values.effective_range ?? [null, null]
    const engine: ExceptionTargetEngine = values.target_engine ?? 'WAF'
    return {
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
      rule_ids: engine === 'API' ? [] : ruleIds,
      rule_tags: engine === 'API' ? [] : (values.rule_tags ?? []),
      attack_types: values.attack_types ?? [],
      content_types: values.content_types ?? [],
      exception_action: values.exception_action,
      action_target: values.action_target ?? '',
      is_temporary: values.is_temporary ?? false,
      effective_from: from ? from.toISOString() : null,
      effective_until: until ? until.toISOString() : null,
      risk_acknowledged: values.risk_acknowledged ?? false,
      reason: values.reason ?? '',
      target_engine: engine,
      api_rule_refs:
        engine === 'API'
          ? (values.api_rule_refs ?? []).map((r) => ({
              detector_id: r.detector_id,
              rule_id: r.rule_id,
              model_version: r.model_version || null,
            }))
          : [],
    }
  }

  const submitForm = (values: ExceptionFormValues) => {
    const ruleIds = (values.rule_ids ?? []).map((s) => Number(s))
    if (ruleIds.some((n) => !Number.isInteger(n) || n <= 0)) {
      message.error('规则ID必须为正整数')
      return
    }
    const body = buildBody(values)
    if (editRecord) {
      updateMutation.mutate({ id: editRecord.id, body: { ...body, version: editRecord.version } })
    } else {
      createMutation.mutate(body)
    }
  }

  /** 打开编辑器（编辑已有记录）：按当前记录预填表单，保存走 PUT + version 乐观锁 */
  const openEdit = (record: ExceptionItem) => {
    setEditRecord(record)
    form.setFieldsValue({
      name: record.name,
      description: record.description,
      scope_type: record.scope_type,
      application_id: record.application_id ?? undefined,
      policy_id: record.policy_id ?? undefined,
      domain: record.domain || undefined,
      uri_exact: record.uri_exact || undefined,
      uri_prefix: record.uri_prefix || undefined,
      uri_regex: record.uri_regex || undefined,
      methods: record.methods ?? [],
      source_ips: record.source_ips ?? [],
      param_names: record.param_names ?? [],
      cookie_names: record.cookie_names ?? [],
      header_names: record.header_names ?? [],
      rule_ids: (record.rule_ids ?? []).map(String),
      rule_tags: record.rule_tags ?? [],
      attack_types: record.attack_types ?? [],
      content_types: record.content_types ?? [],
      exception_action: record.exception_action,
      action_target: record.action_target || undefined,
      is_temporary: record.is_temporary,
      effective_range: [
        record.effective_from ? dayjs(record.effective_from) : null,
        record.effective_until ? dayjs(record.effective_until) : null,
      ],
      reason: record.reason,
      risk_acknowledged: record.risk_acknowledged,
      target_engine: record.target_engine ?? 'WAF',
      api_rule_refs: record.api_rule_refs ?? [],
    })
  }

  const columns: ColumnsType<ExceptionItem> = [
    {
      title: '名称',
      dataIndex: 'name',
      width: 200,
      ellipsis: true,
      render: (v: string, record) => (
        <Button
          type="link"
          size="small"
          style={{ padding: 0, height: 'auto' }}
          onClick={() => setDetailId(record.id)}
        >
          {v}
        </Button>
      ),
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
      width: 120,
      // 派生状态（P0-04 §8）：由记录字段+有效期+发布/节点回执计算；无节点数据时显示「未发布/未知」
      render: (_, record) => (
        <StatusTag value={deriveExceptionStatus(record)} map={EXCEPTION_DERIVED_STATUS_META} />
      ),
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
                (() => {
                  // 启用门禁提示（最终以服务端校验为准）：NEEDS_REVIEW / 历史不支持动作禁用启用
                  const blockers = getExceptionEnableBlockers(record)
                  const btn = (
                    <Button
                      type="link"
                      size="small"
                      disabled={blockers.length > 0}
                      onClick={() => statusMutation.mutate({ id: record.id, action: 'enable' })}
                    >
                      启用
                    </Button>
                  )
                  return blockers.length > 0 ? (
                    <Tooltip title={blockers.join('；')}>
                      <span>{btn}</span>
                    </Tooltip>
                  ) : (
                    btn
                  )
                })()
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
        {batchDeleteButton}
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
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => setDetailId(record.id),
            style: { cursor: 'pointer' },
          })}
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
        title={editRecord ? '编辑例外策略（草稿）' : '新建例外策略'}
        open={createOpen || editRecord !== null}
        onCancel={closeEditor}
        onOk={() => form.submit()}
        okText="保存草稿"
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        width={720}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            scope_type: 'APPLICATION',
            exception_action: 'REMOVE_RULE',
            is_temporary: false,
            target_engine: 'WAF',
          }}
          onFinish={submitForm}
        >
          <Form.Item
            name="name"
            label="例外名称"
            rules={[
              { required: true, message: '请输入例外名称' },
              { max: 128, message: '不超过 128 个字符' },
            ]}
          >
            <Input placeholder="如：管理后台导出 API 误报豁免" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input.TextArea rows={2} placeholder="例外用途说明（可选）" />
          </Form.Item>

          {/* ============ 应用与请求范围（P0-04 §8 编辑器顺序 1） ============ */}
          <Typography.Title level={5}>应用与请求范围</Typography.Title>
          <Form.Item name="scope_type" label="范围类型" rules={[{ required: true }]}>
            <Select options={scopeOptions} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.scope_type !== cur.scope_type}>
            {({ getFieldValue }) => {
              const scope = getFieldValue('scope_type')
              if (scope === 'APPLICATION') {
                return (
                  <Form.Item
                    name="application_id"
                    label="目标应用"
                    extra="启用门禁要求绑定具体应用；留空保存的草稿将被标记为待审查（NEEDS_REVIEW）且禁止启用"
                  >
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
            <Form.Item
              name="uri_exact"
              label="路径精确匹配"
              style={{ width: '33%', marginRight: 8 }}
              dependencies={['uri_prefix', 'uri_regex']}
              rules={[
                {
                  validator: (_, v: string | undefined) => {
                    const filled = [
                      v,
                      form.getFieldValue('uri_prefix'),
                      form.getFieldValue('uri_regex'),
                    ].filter((x) => typeof x === 'string' && x.trim() !== '').length
                    if (filled === 0) {
                      return Promise.reject(new Error('路径匹配必须填写一种（精确 / 前缀 / 正则）'))
                    }
                    if (filled > 1) {
                      return Promise.reject(new Error('路径三种匹配方式最多填写一个'))
                    }
                    return Promise.resolve()
                  },
                },
              ]}
            >
              <Input placeholder="/api/export" autoComplete="off" />
            </Form.Item>
            <Form.Item
              name="uri_prefix"
              label="路径前缀匹配"
              style={{ width: '33%', marginRight: 8 }}
              dependencies={['uri_exact', 'uri_regex']}
              rules={[
                {
                  validator: (_, v: string | undefined) => {
                    if (!v) return Promise.resolve()
                    if (!v.startsWith('/')) {
                      return Promise.reject(new Error('前缀必须以 / 开头'))
                    }
                    if (v === '/') {
                      return Promise.reject(new Error('禁止裸 / 作为唯一范围（属全局范围，需另行评审）'))
                    }
                    return Promise.resolve()
                  },
                },
              ]}
            >
              <Input placeholder="/api/" autoComplete="off" />
            </Form.Item>
            <Form.Item
              name="uri_regex"
              label="路径正则匹配"
              style={{ width: '33%' }}
              dependencies={['uri_exact', 'uri_prefix']}
            >
              <Input placeholder="^/api/v\d+/export$" autoComplete="off" />
            </Form.Item>
          </Space.Compact>
          {watched?.uri_regex && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              message="路径正则属高级配置"
              description="启用需服务端 RE2 兼容校验与额外审核（长度 ≤512，需勾选风险确认），建议优先使用精确或按段前缀匹配。最终以服务端校验为准。"
            />
          )}
          <Form.Item
            name="methods"
            label="HTTP 方法"
            rules={[{ required: true, message: 'HTTP 方法必选（启用门禁：方法非空）' }]}
            extra="例外仅在声明的方法上生效；从事件创建的草稿默认事件原方法，不会扩为全部方法"
          >
            <Select mode="multiple" options={METHOD_OPTIONS} placeholder="选择方法（必选，如 POST）" />
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
          <Form.Item name="content_types" label="内容类型">
            <Select mode="tags" open={false} placeholder="如 application/json，回车添加" />
          </Form.Item>

          {/* ============ 规则与字段（P0-04 §8 编辑器顺序 2） ============ */}
          <Typography.Title level={5}>规则与字段</Typography.Title>
          <Form.Item
            name="target_engine"
            label="目标引擎"
            rules={[{ required: true }]}
            extra="WAF：Coraza/CRS 规则例外；API：API 动态防护 Finding 级规则例外（首批支持 api_schema / api_parser）"
          >
            <Select
              options={[
                { value: 'WAF', label: 'WAF（Coraza/CRS）' },
                { value: 'API', label: 'API（动态防护）' },
              ]}
              onChange={(v: ExceptionTargetEngine) =>
                form.setFieldValue(
                  'exception_action',
                  v === 'API' ? 'OBSERVE_RULE' : 'REMOVE_RULE',
                )
              }
            />
          </Form.Item>
          <Form.Item
            name="exception_action"
            label="例外动作"
            rules={[{ required: true }]}
            extra={
              watchedEngine === 'WAF'
                ? 'LOG_ONLY / ADJUST_SCORE 为历史动作，不支持新启用；请改用精确目标排除'
                : 'API 引擎仅支持 OBSERVE_RULE：被例外命中保留观察记录并取消本次执法贡献，其余命中重新计算决策'
            }
          >
            <Select options={actionOptions} />
          </Form.Item>
          {watchedEngine === 'WAF' &&
            !isActionSupportedForNewEnable('WAF', watched?.exception_action ?? '') && (
              <Alert
                type="warning"
                showIcon
                style={{ marginBottom: 16 }}
                message={`动作 ${watched?.exception_action} 不支持新启用`}
                description="该历史动作保存后仍为待审查（NEEDS_REVIEW）且禁止启用；请改为精确目标排除（REMOVE_VAR_DETECTION / REMOVE_RULE）。"
              />
            )}
          {watchedEngine === 'WAF' && (
            <>
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
              <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: -8 }}>
                规则标签在启用时经规则目录展开为冻结规则集（resolved_rule_ids），不自动扩展；攻击类型仅作事件分类筛选，不参与运行时范围、不能仅凭它授权启用。
              </Typography.Paragraph>
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
              <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: -8 }}>
                参数/Cookie/请求头名为检测目标（ARGS / REQUEST_COOKIES / REQUEST_HEADERS），REMOVE_VAR_DETECTION 必须同时填写规则 ID 与目标名；不代表这些名字对应的所有模块均放行。
              </Typography.Paragraph>
              <Form.Item name="action_target" label="动作目标">
                <Input placeholder="REMOVE_VAR_DETECTION 的目标集合别名（可选；禁止自由文本拼规则）" autoComplete="off" />
              </Form.Item>
            </>
          )}
          {watchedEngine === 'API' && (
            <Form.Item label="API 规则引用" required>
              <Form.List
                name="api_rule_refs"
                rules={[
                  {
                    validator: (_, v: ApiExceptionRuleRef[] | undefined) =>
                      (v ?? []).filter((r) => r?.detector_id && r?.rule_id).length > 0
                        ? Promise.resolve()
                        : Promise.reject(
                            new Error('API 例外必须至少引用一条规则（detector_id + rule_id）'),
                          ),
                  },
                ]}
              >
                {(fields, { add, remove }, { errors }) => (
                  <>
                    {fields.map((field) => (
                      <Space key={field.key} align="baseline" wrap style={{ marginBottom: 8 }}>
                        <Form.Item
                          name={[field.name, 'detector_id']}
                          rules={[{ required: true, message: '选择检测器' }]}
                          style={{ marginBottom: 0 }}
                        >
                          <Select
                            options={API_DETECTOR_OPTIONS}
                            placeholder="detector_id"
                            style={{ width: 230 }}
                          />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'rule_id']}
                          rules={[{ required: true, message: '填写规则 ID' }]}
                          style={{ marginBottom: 0 }}
                        >
                          <Input
                            placeholder="rule_id（稳定规则标识）"
                            style={{ width: 200 }}
                            autoComplete="off"
                          />
                        </Form.Item>
                        <Form.Item name={[field.name, 'model_version']} style={{ marginBottom: 0 }}>
                          <Input
                            placeholder="model_version（可空）"
                            style={{ width: 170 }}
                            autoComplete="off"
                          />
                        </Form.Item>
                        <Button type="link" danger onClick={() => remove(field.name)}>
                          删除
                        </Button>
                      </Space>
                    ))}
                    <Button type="dashed" onClick={() => add()} icon={<PlusOutlined />}>
                      添加规则引用
                    </Button>
                    <Form.ErrorList errors={errors} />
                  </>
                )}
              </Form.List>
            </Form.Item>
          )}

          {/* ============ 有效期（P0-04 §8 编辑器顺序 3） ============ */}
          <Typography.Title level={5}>有效期</Typography.Title>
          <Form.Item name="is_temporary" label="临时例外" valuePropName="checked">
            <Switch checkedChildren="是" unCheckedChildren="否" />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.is_temporary !== cur.is_temporary}>
            {({ getFieldValue }) => (
              <Form.Item
                name="effective_range"
                label="生效 / 失效时间"
                extra="半开区间：含生效时间、不含失效时间（UTC 秒精度）；到期无需再次发布即恢复防护"
                rules={[
                  ...(getFieldValue('is_temporary')
                    ? [
                        { required: true, message: '临时例外必须设置生效与失效时间' } as const,
                        {
                          validator: (_: unknown, v: [dayjs.Dayjs | null, dayjs.Dayjs | null] | undefined) =>
                            v?.[1]
                              ? Promise.resolve()
                              : Promise.reject(new Error('临时例外必须设置失效时间')),
                        },
                      ]
                    : []),
                  {
                    validator: (_: unknown, v: [dayjs.Dayjs | null, dayjs.Dayjs | null] | undefined) =>
                      v?.[0] && v?.[1] && !v[0].isBefore(v[1])
                        ? Promise.reject(new Error('生效时间必须早于失效时间（相等起止非法）'))
                        : Promise.resolve(),
                  },
                ]}
              >
                <DatePicker.RangePicker showTime style={{ width: '100%' }} />
              </Form.Item>
            )}
          </Form.Item>

          {/* ============ 影响预览（P0-04 §8 编辑器顺序 4） ============ */}
          <Typography.Title level={5}>影响预览</Typography.Title>
          {editRecord ? (
            <div style={{ marginBottom: 16 }}>
              <ExceptionPreviewPanel exceptionId={editRecord.id} version={editRecord.version} />
            </div>
          ) : (
            <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
              预览基于已保存的草稿版本：请先保存草稿，随后在例外详情中点击「影响预览」查看规范化范围、解析后规则引用、生效窗口与预估影响。
            </Typography.Paragraph>
          )}

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
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            前端校验仅作提示：保存 / 启用 / 预览的最终判定以服务端校验与启用门禁为准（P0-04 S4 §4）。
          </Typography.Paragraph>
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
            {canManage && (
              <Space style={{ marginBottom: 16 }}>
                <Button onClick={() => openEdit(exc)}>编辑草稿</Button>
              </Space>
            )}
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
            {exc.validation_status === 'NEEDS_REVIEW' && (
              <Alert
                type="warning"
                showIcon
                style={{ marginBottom: 16 }}
                message="该例外待审查（NEEDS_REVIEW），达标前禁止启用"
                description={
                  (exc.unsupported_reasons ?? []).length > 0 ? (
                    <ul style={{ margin: 0, paddingLeft: 18 }}>
                      {(exc.unsupported_reasons ?? []).map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  ) : (
                    '服务端未提供原因明细；请检查应用绑定、路径、方法与目标规则是否齐全。'
                  )
                }
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
              <Descriptions.Item label="派生状态">
                <StatusTag value={deriveExceptionStatus(exc)} map={EXCEPTION_DERIVED_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="原始状态">
                <StatusTag value={exc.status} map={EXCEPTION_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="目标引擎">
                <Tag color={exc.target_engine === 'API' ? 'purple' : 'blue'}>
                  {exc.target_engine ?? 'WAF'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="校验状态">
                {exc.validation_status === 'NEEDS_REVIEW' ? (
                  <Tag color="red">NEEDS_REVIEW 待审查</Tag>
                ) : (
                  <Tag color="green">{exc.validation_status ?? 'VALID'}</Tag>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="版本">v{exc.version}</Descriptions.Item>
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
              {listSection('冻结规则集', exc.resolved_rule_ids)}
              {listSection('攻击类型', exc.attack_types)}
              {listSection('Content-Type', exc.content_types)}
              <Descriptions.Item label="API 规则引用" span={2}>
                {(exc.api_rule_refs ?? []).length > 0 ? (
                  <Space wrap size={4}>
                    {(exc.api_rule_refs ?? []).map((r, i) => (
                      <Tag key={`${r.detector_id}-${r.rule_id}-${i}`}>
                        {`${r.detector_id}/${r.rule_id}${r.model_version ? `@${r.model_version}` : ''}`}
                      </Tag>
                    ))}
                  </Space>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
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
              <Descriptions.Item label="来源事件">
                {exc.source_event_id ? (
                  <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                    {exc.source_event_id}
                  </Typography.Text>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="编译指纹">
                <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {exc.compiled_fingerprint || '-'}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="例外原因" span={2}>
                {exc.reason || '-'}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>影响预览</Typography.Title>
            <div style={{ marginBottom: 16 }}>
              <ExceptionPreviewPanel exceptionId={exc.id} version={exc.version} />
            </div>
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
