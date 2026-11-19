import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Select,
  Space,
  Steps,
  Switch,
  Tag,
  Typography,
} from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi } from '../../api/apiAssets'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import {
  strongFlowApi,
  type StrongFlowDefinition,
  type StrongFlowDefinitionDetail,
  type StrongFlowDefinitionInput,
  type StrongFlowStep,
  type StrongFlowSuccessRule,
} from '../../api/strongFlow'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  INSTANCE_TRANSITIONS_NOTE,
  RETRY_SEMANTICS_META,
  STRONG_FLOW_MODE_META,
  STRONG_FLOW_STATUS_META,
  successRuleText,
  validInstanceKeyParam,
  validateStrongFlowSteps,
} from '../../utils/strongFlow'

/** 表单内单步取值（success_rule 三形态拆为扁平字段，提交时组装） */
interface StepFormValue {
  step_key?: string
  endpoint_key?: string
  sequence?: number
  status_codes_text?: string
  body_jsonpath?: string
  body_jsonpath_value?: string
  graphql_errors_empty?: boolean
  timeout_seconds?: number
  retry_semantics?: string
  parallel_group?: string
  lease_seconds?: number
  allows_202?: boolean
}

interface DefinitionFormValues {
  application_id?: string
  name: string
  binding_path_prefix: string
  instance_key_param: string
  mode: string
  steps: StepFormValue[]
}

/** 等值目标解析：JSON 标量可解析则用之（200/true/"PAID"），否则按字符串原文 */
function parseScalar(text: string): unknown {
  const raw = text.trim()
  if (raw === '') return ''
  try {
    return JSON.parse(raw) as unknown
  } catch {
    return raw
  }
}

/** 表单步骤 → 成功判定式（三形态皆空返回 null——结构校验随后拦截） */
function buildSuccessRule(s: StepFormValue): StrongFlowSuccessRule | null {
  const rule: StrongFlowSuccessRule = {}
  const codes = (s.status_codes_text ?? '')
    .split(/[,，\s]+/)
    .map((v) => v.trim())
    .filter(Boolean)
    .map(Number)
  if (codes.length > 0) rule.status_codes = codes
  const path = (s.body_jsonpath ?? '').trim()
  const valueText = (s.body_jsonpath_value ?? '').trim()
  if (path || valueText) {
    rule.body_jsonpath_equals = { path, value: parseScalar(valueText) }
  }
  if (s.graphql_errors_empty) rule.graphql_errors_empty = true
  return rule.status_codes ||
    rule.body_jsonpath_equals ||
    rule.graphql_errors_empty
    ? rule
    : null
}

/** 表单值 → 写入载荷（整体替换语义：steps 全量给出） */
function toDefinitionPayload(
  values: DefinitionFormValues,
): StrongFlowDefinitionInput {
  return {
    application_id: values.application_id ?? '',
    name: values.name.trim(),
    binding_path_prefix: values.binding_path_prefix.trim(),
    instance_key_param: values.instance_key_param.trim(),
    mode: values.mode || 'OBSERVE',
    steps: (values.steps ?? []).map((s, i) => ({
      step_key: (s.step_key ?? '').trim(),
      endpoint_key: (s.endpoint_key ?? '').trim(),
      sequence: s.sequence ?? i + 1,
      success_rule: buildSuccessRule(s),
      timeout_seconds: s.timeout_seconds ?? 60,
      retry_semantics: s.retry_semantics ?? 'IDEMPOTENT',
      parallel_group: (s.parallel_group ?? '').trim(),
      lease_seconds: s.lease_seconds ?? 60,
      allows_202: s.allows_202 ?? false,
    })),
  }
}

/** 详情步骤 → 表单回填 */
function stepToFormValue(s: StrongFlowStep): StepFormValue {
  return {
    step_key: s.step_key,
    endpoint_key: s.endpoint_key,
    sequence: s.sequence,
    status_codes_text: (s.success_rule?.status_codes ?? []).join(','),
    body_jsonpath: s.success_rule?.body_jsonpath_equals?.path ?? '',
    body_jsonpath_value:
      s.success_rule?.body_jsonpath_equals &&
      s.success_rule.body_jsonpath_equals.value !== undefined
        ? typeof s.success_rule.body_jsonpath_equals.value === 'string'
          ? s.success_rule.body_jsonpath_equals.value
          : JSON.stringify(s.success_rule.body_jsonpath_equals.value)
        : '',
    graphql_errors_empty: s.success_rule?.graphql_errors_empty ?? false,
    timeout_seconds: s.timeout_seconds,
    retry_semantics: s.retry_semantics,
    parallel_group: s.parallel_group ?? '',
    lease_seconds: s.lease_seconds,
    allows_202: s.allows_202 ?? false,
  }
}

/** 列表级步骤校验（镜像 server validateSteps 结构规则；表单值先组装为提交形态再校） */
function stepsListValidator(_: unknown, steps: StepFormValue[] | undefined) {
  const assembled = (steps ?? []).map((s, i) => ({
    step_key: (s?.step_key ?? '').trim(),
    endpoint_key: (s?.endpoint_key ?? '').trim(),
    sequence: s?.sequence ?? i + 1,
    success_rule: buildSuccessRule(s ?? {}),
    timeout_seconds: s?.timeout_seconds ?? 60,
    retry_semantics: s?.retry_semantics ?? 'IDEMPOTENT',
    parallel_group: (s?.parallel_group ?? '').trim(),
    lease_seconds: s?.lease_seconds ?? 60,
    allows_202: s?.allows_202 ?? false,
  }))
  const msg = validateStrongFlowSteps(assembled)
  return msg ? Promise.reject(new Error(msg)) : Promise.resolve()
}

/** 定义编辑抽屉（新建 POST / DRAFT 原地 PUT / 同名复制新草稿 POST） */
function DefinitionEditorDrawer({
  editId,
  source,
  onClose,
}: {
  /** 编辑 DRAFT 时为目标 id；新建/复制新草稿为 undefined */
  editId?: string
  /** 预填来源（编辑详情 / 复制新草稿来源；全新建为 null） */
  source: StrongFlowDefinitionDetail | null
  onClose: () => void
}) {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const [form] = Form.useForm<DefinitionFormValues>()
  const isEdit = Boolean(editId)
  /** 复制新草稿：application_id/name 固定（同名 version+1 由服务端递进），步骤可改 */
  const isCopyDraft = !isEdit && source !== null
  const [submitError, setSubmitError] = useState<string | null>(null)

  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })
  const endpointOptions = (endpointsQuery.data?.items ?? []).map((e) => ({
    value: e.endpoint_key,
    label: e.endpoint_key,
  }))

  const saveMut = useMutation({
    mutationFn: (input: StrongFlowDefinitionInput) =>
      isEdit
        ? strongFlowApi.updateDefinition(editId as string, input)
        : strongFlowApi.createDefinition(input),
    onSuccess: (saved) => {
      message.success(
        isEdit
          ? `已保存（版本 ${saved.version}）`
          : `已创建草稿（版本 ${saved.version}）`,
      )
      void qc.invalidateQueries({ queryKey: ['strong-flow-definitions'] })
      onClose()
    },
    onError: (e: unknown) =>
      setSubmitError(e instanceof ApiError ? e.message : '保存失败'),
  })

  const initialValues: DefinitionFormValues = source
    ? {
        application_id: source.application_id,
        name: source.name,
        binding_path_prefix: source.binding_path_prefix,
        instance_key_param: source.instance_key_param,
        mode: source.mode || 'OBSERVE',
        steps: (source.steps ?? []).map(stepToFormValue),
      }
    : {
        name: '',
        binding_path_prefix: '',
        instance_key_param: '',
        mode: 'OBSERVE',
        steps: [
          {
            sequence: 1,
            timeout_seconds: 60,
            lease_seconds: 60,
            retry_semantics: 'IDEMPOTENT',
          },
        ],
      }

  const watchedSteps = Form.useWatch('steps', form) as
    StepFormValue[] | undefined
  const watchedMode = Form.useWatch('mode', form) as string | undefined

  return (
    <Drawer
      title={
        isEdit
          ? `编辑强流程定义（版本 ${source?.version ?? '-'}）`
          : isCopyDraft
            ? '复制为新草稿版本'
            : '新建强流程定义'
      }
      width={920}
      open
      onClose={onClose}
      destroyOnHidden
      extra={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            loading={saveMut.isPending}
            onClick={() => form.submit()}
          >
            保存
          </Button>
        </Space>
      }
    >
      {submitError ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          message="保存失败"
          description={submitError}
          closable
          onClose={() => setSubmitError(null)}
        />
      ) : null}
      {isCopyDraft ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="同名新草稿说明：保存后由服务端自动生成下一版本草稿；已激活版本不可修改。"
        />
      ) : null}
      <Form<DefinitionFormValues>
        key={
          source
            ? `${source.id}:${source.version}:${isEdit ? 'edit' : 'copy'}`
            : 'create'
        }
        form={form}
        layout="vertical"
        initialValues={initialValues}
        onFinish={(values) => {
          setSubmitError(null)
          saveMut.mutate(toDefinitionPayload(values))
        }}
      >
        <Space size={16} wrap style={{ display: 'flex' }}>
          <Form.Item
            name="application_id"
            label="所属应用"
            style={{ width: 280 }}
            rules={[{ required: true, message: '请选择所属应用' }]}
          >
            <ApplicationSelect disabled={isEdit || isCopyDraft} />
          </Form.Item>
          <Form.Item
            name="name"
            label="流程名称"
            style={{ width: 280 }}
            rules={[
              { required: true, whitespace: true, message: '流程名称必填' },
              { max: 255, message: '不超过 255 字符' },
            ]}
          >
            <Input
              placeholder="如：下单支付流程"
              disabled={isEdit || isCopyDraft}
            />
          </Form.Item>
          <Form.Item
            name="mode"
            label="模式"
            rules={[{ required: true, message: '请选择模式' }]}
          >
            <Select
              style={{ width: 200 }}
              options={Object.entries(STRONG_FLOW_MODE_META).map(
                ([value, meta]) => ({ value, label: meta.label }),
              )}
            />
          </Form.Item>
        </Space>
        {watchedMode === 'PROTECT' ? (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 16 }}
            message="实断模式：违规请求将被 403 拦截"
            description="激活后，无有效预留执行依赖步骤 / 重复执行已确认步骤 / 非法并行 / 防重入序号过期提交的请求将被 403 拦截（流程违规拒绝）；证据不足恒不阻断（恒放行并标记待对账）。"
          />
        ) : null}
        <Space size={16} wrap style={{ display: 'flex' }}>
          <Form.Item
            name="binding_path_prefix"
            label="绑定路径前缀"
            style={{ width: 340 }}
            rules={[
              { required: true, whitespace: true, message: '绑定路径前缀必填' },
              { max: 512, message: '不超过 512 字符' },
              { pattern: /^\//, message: '须为 / 开头路径前缀' },
            ]}
            extra="步骤端点须属该前缀下本应用已确认端点（激活时服务端核对）"
          >
            <Input placeholder="如：/api/v1/orders" />
          </Form.Item>
          <Form.Item
            name="instance_key_param"
            label="实例引用提取器"
            style={{ width: 280 }}
            rules={[
              {
                required: true,
                whitespace: true,
                message: '实例引用提取器必填',
              },
              {
                validator: (_, v: string) =>
                  validInstanceKeyParam(v ?? '')
                    ? Promise.resolve()
                    : Promise.reject(
                        new Error('形态 query:<参数名> 或 path:<段序>'),
                      ),
              },
            ]}
            extra="实例引用来源（如 query:order_id / path:3）"
          >
            <Input placeholder="如：query:order_id" />
          </Form.Item>
        </Space>

        <Typography.Title level={5}>步骤</Typography.Title>
        <Form.List name="steps" rules={[{ validator: stepsListValidator }]}>
          {(fields, { add, remove }, { errors }) => (
            <>
              {fields.map((field) => (
                <Card
                  key={field.key}
                  size="small"
                  style={{ marginBottom: 12 }}
                  title={`步骤 ${field.name + 1}`}
                  extra={
                    <Button
                      type="link"
                      size="small"
                      danger
                      disabled={fields.length <= 1}
                      onClick={() => remove(field.name)}
                    >
                      删除步骤
                    </Button>
                  }
                >
                  <Space size={12} wrap style={{ display: 'flex' }}>
                    <Form.Item
                      name={[field.name, 'step_key']}
                      label="步骤键"
                      style={{ width: 180 }}
                      rules={[
                        {
                          required: true,
                          whitespace: true,
                          message: '步骤键必填',
                        },
                        { max: 128, message: '不超过 128 字符' },
                      ]}
                    >
                      <Input placeholder="如：register" />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'endpoint_key']}
                      label="绑定端点"
                      style={{ width: 320 }}
                      rules={[{ required: true, message: '请选择绑定端点' }]}
                    >
                      <Select
                        showSearch
                        optionFilterProp="label"
                        placeholder="选择 API 端点"
                        loading={endpointsQuery.isLoading}
                        options={endpointOptions}
                      />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'sequence']}
                      label="序号"
                      rules={[{ required: true, message: '序号必填' }]}
                    >
                      <InputNumber
                        min={1}
                        precision={0}
                        style={{ width: 90 }}
                      />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'timeout_seconds']}
                      label="超时（秒）"
                      rules={[
                        { required: true, message: '超时必填' },
                        {
                          type: 'integer',
                          min: 15,
                          max: 600,
                          message: '15~600',
                        },
                      ]}
                    >
                      <InputNumber
                        min={15}
                        max={600}
                        precision={0}
                        style={{ width: 110 }}
                      />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'lease_seconds']}
                      label="预留租约（秒）"
                      rules={[
                        { required: true, message: '租约必填' },
                        {
                          type: 'integer',
                          min: 15,
                          max: 300,
                          message: '15~300',
                        },
                      ]}
                    >
                      <InputNumber
                        min={15}
                        max={300}
                        precision={0}
                        style={{ width: 110 }}
                      />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'retry_semantics']}
                      label="重试语义"
                      rules={[{ required: true, message: '请选择重试语义' }]}
                    >
                      <Select
                        style={{ width: 180 }}
                        options={Object.entries(RETRY_SEMANTICS_META).map(
                          ([value, meta]) => ({
                            value,
                            label: meta.label,
                          }),
                        )}
                      />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'parallel_group']}
                      label="并行组（选填）"
                      style={{ width: 160 }}
                      rules={[{ max: 128, message: '不超过 128 字符' }]}
                    >
                      <Input placeholder="空=串行" />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'allows_202']}
                      label="允许 202 受理"
                      valuePropName="checked"
                      extra="202=已受理待完成，不自动完成"
                    >
                      <Switch />
                    </Form.Item>
                  </Space>
                  <Card
                    size="small"
                    type="inner"
                    title="成功判定式（至少一种形态；HTTP 2xx 不是通用成功证据）"
                  >
                    <Space size={12} wrap style={{ display: 'flex' }}>
                      <Form.Item
                        name={[field.name, 'status_codes_text']}
                        label="状态码集合"
                        style={{ width: 220 }}
                        rules={[
                          {
                            validator: (_, v: string) => {
                              const codes = (v ?? '')
                                .split(/[,，\s]+/)
                                .map((x) => x.trim())
                                .filter(Boolean)
                              if (
                                codes.some(
                                  (c) =>
                                    !/^\d+$/.test(c) ||
                                    Number(c) < 100 ||
                                    Number(c) > 599,
                                )
                              ) {
                                return Promise.reject(
                                  new Error('须为 100~599 状态码，逗号分隔'),
                                )
                              }
                              return Promise.resolve()
                            },
                          },
                        ]}
                      >
                        <Input placeholder="如：200,201" />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'body_jsonpath']}
                        label="响应体 JSONPath 等值"
                        style={{ width: 200 }}
                        rules={[
                          {
                            validator: (_, v: string) => {
                              const s = (v ?? '').trim()
                              if (
                                s &&
                                !/^\$\.[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$/.test(
                                  s,
                                )
                              ) {
                                return Promise.reject(
                                  new Error('仅点路径子集 $.a.b'),
                                )
                              }
                              return Promise.resolve()
                            },
                          },
                        ]}
                      >
                        <Input placeholder="如：$.status" />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'body_jsonpath_value']}
                        label="等值目标"
                        style={{ width: 180 }}
                      >
                        <Input placeholder="如：PAID（JSON 标量）" />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'graphql_errors_empty']}
                        label="GraphQL 错误列表为空"
                        valuePropName="checked"
                      >
                        <Checkbox />
                      </Form.Item>
                    </Space>
                  </Card>
                </Card>
              ))}
              <Form.ErrorList errors={errors} />
              <Button
                block
                icon={<PlusOutlined />}
                disabled={fields.length >= 64}
                onClick={() =>
                  add({
                    sequence: (watchedSteps ?? []).length + 1,
                    timeout_seconds: 60,
                    lease_seconds: 60,
                    retry_semantics: 'IDEMPOTENT',
                  })
                }
              >
                添加步骤
              </Button>
            </>
          )}
        </Form.List>
      </Form>
    </Drawer>
  )
}

/** 站点选择（与对象授权 Tab 同口径：name（code））；透传 Form.Item 注入的 value/onChange */
function ApplicationSelect({
  value,
  onChange,
  disabled,
}: {
  value?: string
  onChange?: (v: string) => void
  disabled?: boolean
}) {
  const applicationsQuery = useQuery({
    queryKey: ['applications', 'strong-flow-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  return (
    <Select
      showSearch
      optionFilterProp="label"
      placeholder="选择应用"
      value={value}
      onChange={onChange}
      disabled={disabled}
      loading={applicationsQuery.isLoading}
      options={(applicationsQuery.data?.items ?? []).map((app) => ({
        value: app.id,
        label: `${app.name}（${app.code}）`,
      }))}
    />
  )
}

/** 定义详情抽屉：步骤序列图 + 成功条件 + 异常策略 + 允许转换说明 */
function DefinitionDetailDrawer({
  id,
  onClose,
}: {
  id: string
  onClose: () => void
}) {
  const detailQuery = useQuery({
    queryKey: ['strong-flow-definition', id],
    queryFn: () => strongFlowApi.getDefinition(id),
  })
  const detail = detailQuery.data
  const sortedSteps = useMemo(
    () => [...(detail?.steps ?? [])].sort((a, b) => a.sequence - b.sequence),
    [detail],
  )
  return (
    <Drawer
      title={
        detail
          ? `强流程定义：${detail.name} v${detail.version}`
          : '强流程定义详情'
      }
      width={880}
      open
      onClose={onClose}
      destroyOnHidden
    >
      <QueryErrorAlert error={detailQuery.error} />
      {detail ? (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Descriptions size="small" column={2} bordered>
            <Descriptions.Item label="状态">
              <StatusTag value={detail.status} map={STRONG_FLOW_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="模式">
              <StatusTag
                value={detail.mode || 'OBSERVE'}
                map={STRONG_FLOW_MODE_META}
              />
            </Descriptions.Item>
            <Descriptions.Item label="绑定前缀">
              <Typography.Text code>
                {detail.binding_path_prefix}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="实例引用提取器">
              <Typography.Text code>
                {detail.instance_key_param}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="创建人">
              {detail.created_by_name || '—'}
            </Descriptions.Item>
            <Descriptions.Item label="创建时间">
              {formatDateTime(detail.created_at)}
            </Descriptions.Item>
            <Descriptions.Item label="激活时间">
              {detail.activated_at ? formatDateTime(detail.activated_at) : '—'}
            </Descriptions.Item>
            <Descriptions.Item label="版本">
              v{detail.version}（激活即冻结）
            </Descriptions.Item>
          </Descriptions>
          <div>
            <Typography.Text strong>步骤序列（按序号）</Typography.Text>
            <Steps
              direction="vertical"
              size="small"
              style={{ marginTop: 12 }}
              current={-1}
              items={sortedSteps.map((s) => ({
                title: (
                  <Space size={8} wrap>
                    <Typography.Text strong>
                      {s.sequence}. {s.step_key}
                    </Typography.Text>
                    {s.parallel_group ? (
                      <Tag color="purple">并行组 {s.parallel_group}</Tag>
                    ) : null}
                    {s.allows_202 ? (
                      <Tag color="cyan">允许 202 受理</Tag>
                    ) : null}
                  </Space>
                ),
                description: (
                  <Space
                    direction="vertical"
                    size={4}
                    style={{ paddingBottom: 8 }}
                  >
                    <Typography.Text code>{s.endpoint_key}</Typography.Text>
                    <Typography.Text type="secondary">
                      成功条件：{successRuleText(s.success_rule)}
                    </Typography.Text>
                    <Typography.Text type="secondary">
                      超时 {s.timeout_seconds}s · 租约 {s.lease_seconds}s ·{' '}
                      {RETRY_SEMANTICS_META[s.retry_semantics]?.label ??
                        s.retry_semantics}
                    </Typography.Text>
                  </Space>
                ),
              }))}
            />
          </div>
          <Alert
            type="info"
            showIcon
            message="允许转换与异常策略"
            description={
              <>
                <Typography.Paragraph style={{ marginBottom: 4 }}>
                  {INSTANCE_TRANSITIONS_NOTE}
                </Typography.Paragraph>
                <Typography.Paragraph
                  type="secondary"
                  style={{ marginBottom: 0 }}
                >
                  异常策略：超时 / 连接失败 / 判定式不命中 / 形态无法解析恒记为未知并进入对账（不自动回滚为可重试——超时但源站可能已成功）；证据不足恒不阻断（任何形态均不将未知结果映射为
                  403）。
                </Typography.Paragraph>
              </>
            }
          />
        </Space>
      ) : (
        <Typography.Text type="secondary">加载中…</Typography.Text>
      )}
    </Drawer>
  )
}

/**
 * 强流程定义（NG-FLOW-01 §1.9）：版本化定义管理——DRAFT 原地编辑、同名新草稿 version+1、
 * 激活即冻结（同名旧 ACTIVE 同事务停用）、RETIRED 单向终态。
 */
export default function StrongFlowDefinitionsTab() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_flow.manage')
  const [applicationId, setApplicationId] = useState<string>()
  const [statusFilter, setStatusFilter] = useState<string>()
  const [page, setPage] = useState(1)
  const [detailId, setDetailId] = useState<string | null>(null)
  /** undefined 关闭；{source:null} 全新建；{editId,source} 编辑 DRAFT；{source} 复制新草稿 */
  const [editor, setEditor] = useState<
    undefined | { editId?: string; source: StrongFlowDefinitionDetail | null }
  >(undefined)

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'strong-flow-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })

  const listQuery = useQuery({
    queryKey: ['strong-flow-definitions', applicationId, statusFilter, page],
    queryFn: () =>
      strongFlowApi.listDefinitions({
        application_id: applicationId || undefined,
        status: statusFilter || undefined,
        page,
        page_size: 20,
      }),
  })
  const invalidateList = () =>
    void qc.invalidateQueries({ queryKey: ['strong-flow-definitions'] })

  const activateMut = useMutation({
    mutationFn: (id: string) => strongFlowApi.activateDefinition(id),
    onSuccess: (d) => {
      message.success(
        `已激活（${d.name} v${d.version}），同名旧已激活版本已停用`,
      )
      invalidateList()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '激活失败'),
  })
  const retireMut = useMutation({
    mutationFn: (id: string) => strongFlowApi.retireDefinition(id),
    onSuccess: () => {
      message.success('已停用（单向终态）')
      invalidateList()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '停用失败'),
  })

  const confirmActivate = (row: StrongFlowDefinition) => {
    modal.confirm({
      title: `激活强流程定义「${row.name} v${row.version}」`,
      content: (
        <Space direction="vertical" size={8}>
          {row.mode === 'PROTECT' ? (
            <Alert
              type="error"
              showIcon
              message="实断模式：违规请求将被 403 拦截"
              description="激活后该流程违规请求将被实断（流程违规拒绝）；证据不足恒不阻断。"
            />
          ) : null}
          <Typography.Text>
            激活即冻结不可再编辑；同应用同名称的旧已激活版本将同时停用。存量实例固定创建时版本，不换图。
          </Typography.Text>
        </Space>
      ),
      okText: '确认激活',
      onOk: () => activateMut.mutateAsync(row.id),
    })
  }

  /** 打开编辑抽屉：编辑（DRAFT 原地 PUT）或复制新草稿（同名 POST，version 服务端递进） */
  const openEditor = async (
    row: StrongFlowDefinition,
    mode: 'edit' | 'copy',
  ) => {
    try {
      const detail = await strongFlowApi.getDefinition(row.id)
      setEditor({
        editId: mode === 'edit' ? row.id : undefined,
        source: detail,
      })
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '加载定义详情失败')
    }
  }

  const columns: ColumnsType<StrongFlowDefinition> = [
    {
      title: '名称',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string) => <Typography.Text strong>{v}</Typography.Text>,
    },
    {
      title: '版本',
      dataIndex: 'version',
      width: 80,
      render: (v: number) => `v${v}`,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => (
        <StatusTag value={v} map={STRONG_FLOW_STATUS_META} />
      ),
    },
    {
      title: '模式',
      dataIndex: 'mode',
      width: 150,
      render: (v: string) => (
        <StatusTag value={v || 'OBSERVE'} map={STRONG_FLOW_MODE_META} />
      ),
    },
    {
      title: '绑定前缀',
      dataIndex: 'binding_path_prefix',
      width: 200,
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '实例引用提取器',
      dataIndex: 'instance_key_param',
      width: 170,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '激活时间',
      dataIndex: 'activated_at',
      width: 170,
      render: (v?: string | null) => (v ? formatDateTime(v) : '—'),
    },
    {
      title: '操作',
      key: 'actions',
      width: 280,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button
            type="link"
            size="small"
            onClick={() => setDetailId(record.id)}
          >
            详情
          </Button>
          {canManage && record.status === 'DRAFT' ? (
            <>
              <Button
                type="link"
                size="small"
                onClick={() => void openEditor(record, 'edit')}
              >
                编辑
              </Button>
              <Button
                type="link"
                size="small"
                onClick={() => confirmActivate(record)}
              >
                激活
              </Button>
            </>
          ) : null}
          {canManage && record.status !== 'DRAFT' ? (
            <Button
              type="link"
              size="small"
              onClick={() => void openEditor(record, 'copy')}
            >
              复制为新草稿
            </Button>
          ) : null}
          {canManage && record.status !== 'RETIRED' ? (
            <Popconfirm
              title={`停用「${record.name} v${record.version}」？`}
              description="停用为单向终态，不可恢复；存量非终态实例可按旧版本走完，新实例须按已激活版本执行。"
              okText="确认停用"
              okButtonProps={{ danger: true }}
              onConfirm={() => retireMut.mutate(record.id)}
            >
              <Button type="link" size="small" danger>
                停用
              </Button>
            </Popconfirm>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
        强流程定义（响应确认型业务流程防护）：编辑产生下一版本草稿、激活即冻结、停用为单向终态；与既有流程观察基线物理隔离，无导入路径。
      </Typography.Paragraph>
      <Space wrap>
        <Select
          showSearch
          optionFilterProp="label"
          allowClear
          placeholder="全部应用"
          style={{ width: 260 }}
          value={applicationId}
          loading={applicationsQuery.isLoading}
          options={(applicationsQuery.data?.items ?? []).map((app) => ({
            value: app.id,
            label: `${app.name}（${app.code}）`,
          }))}
          onChange={(v) => {
            setApplicationId(v)
            setPage(1)
          }}
        />
        <Select
          allowClear
          placeholder="全部状态"
          style={{ width: 140 }}
          value={statusFilter}
          options={Object.entries(STRONG_FLOW_STATUS_META).map(
            ([value, meta]) => ({ value, label: meta.label }),
          )}
          onChange={(v) => {
            setStatusFilter(v)
            setPage(1)
          }}
        />
        {canManage ? (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setEditor({ source: null })}
          >
            新建强流程定义
          </Button>
        ) : null}
      </Space>
      <QueryErrorAlert error={listQuery.error} message="加载强流程定义失败" />
      <SmartTable<StrongFlowDefinition>
        storageKey="strong-flow-definitions"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1400 }}
        pagination={{
          current: page,
          pageSize: 20,
          total: listQuery.data?.total ?? 0,
          showSizeChanger: false,
          onChange: setPage,
        }}
        locale={{ emptyText: '暂无强流程定义' }}
      />
      {detailId ? (
        <DefinitionDetailDrawer
          id={detailId}
          onClose={() => setDetailId(null)}
        />
      ) : null}
      {editor !== undefined ? (
        <DefinitionEditorDrawer
          editId={editor.editId}
          source={editor.source}
          onClose={() => setEditor(undefined)}
        />
      ) : null}
    </Space>
  )
}
