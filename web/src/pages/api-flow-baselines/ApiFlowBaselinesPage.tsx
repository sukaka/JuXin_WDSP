import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  Card,
  Drawer,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import type { FormInstance } from 'antd'
import { apiEndpointsApi } from '../../api/apiAssets'
import {
  apiFlowBaselinesApi,
  toUpsertInput,
  type ApiFlowBaseline,
  type ApiFlowBaselineSummary,
  type ApiFlowBaselineUpsertInput,
  type ApiFlowStepInput,
} from '../../api/apiFlows'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import StrongFlowDefinitionsTab from './StrongFlowDefinitionsTab'
import StrongFlowInstancesTab from './StrongFlowInstancesTab'

/** 表单内单步取值（endpoint_id 未选择时为 undefined，提交前必经校验） */
interface StepFormValue {
  step_id?: string
  endpoint_id?: string
  sequence?: number
  predecessors?: string[]
  terminal?: boolean
  state_from?: string
  state_to?: string
  max_per_window?: number
  rate_window_seconds?: number
  cancels_flow?: boolean
}

interface FlowFormValues {
  flow_id: string
  name?: string
  description?: string
  enabled: boolean
  max_per_window?: number
  rate_window_seconds?: number
  steps: StepFormValue[]
}

/** 表单值 → 写入载荷（去空白、缺省补齐；校验规则保证必填项非空；空值限速/取消字段省略不发送，零值语义 = 不判定） */
function toPayload(values: FlowFormValues): ApiFlowBaselineUpsertInput {
  const steps: ApiFlowStepInput[] = (values.steps ?? []).map((s, i) => ({
    step_id: (s.step_id ?? '').trim(),
    endpoint_id: s.endpoint_id ?? '',
    sequence: s.sequence ?? i + 1,
    predecessors: s.predecessors ?? [],
    terminal: s.terminal ?? false,
    state_from: (s.state_from ?? '').trim(),
    state_to: (s.state_to ?? '').trim(),
    ...(s.max_per_window ? { max_per_window: s.max_per_window } : {}),
    ...(s.rate_window_seconds
      ? { rate_window_seconds: s.rate_window_seconds }
      : {}),
    ...(s.cancels_flow ? { cancels_flow: true } : {}),
  }))
  return {
    flow_id: values.flow_id.trim(),
    name: (values.name ?? '').trim(),
    description: (values.description ?? '').trim(),
    enabled: values.enabled,
    ...(values.max_per_window ? { max_per_window: values.max_per_window } : {}),
    ...(values.rate_window_seconds
      ? { rate_window_seconds: values.rate_window_seconds }
      : {}),
    steps,
  }
}

/** 步骤列表级校验（与 server/internal/apiflows validateFlow 同口径：≥1 步、step_id 流程内唯一） */
function validateSteps(_: unknown, steps: StepFormValue[] | undefined) {
  const list = steps ?? []
  if (list.length === 0) return Promise.reject(new Error('至少需要 1 个步骤'))
  if (list.length > 64)
    return Promise.reject(new Error('步骤数超过单流程上限 64'))
  const seen = new Set<string>()
  for (const s of list) {
    const id = (s?.step_id ?? '').trim()
    if (!id) continue // 空值由字段级 required 规则报错
    if (seen.has(id)) return Promise.reject(new Error(`步骤标识重复：${id}`))
    seen.add(id)
  }
  return Promise.resolve()
}

/** 前置步骤字段级校验（AND 语义：不得自引用、必须指向同流程已声明步骤、≤16 个） */
function predecessorValidator(
  form: FormInstance<FlowFormValues>,
  selfIndex: number,
) {
  return (_: unknown, value: string[] | undefined) => {
    const preds = value ?? []
    if (preds.length > 16)
      return Promise.reject(new Error('前置步骤超过上限 16 个'))
    const steps: StepFormValue[] = form.getFieldValue('steps') ?? []
    const declared = new Set(
      steps.map((s) => (s?.step_id ?? '').trim()).filter((id) => id.length > 0),
    )
    const self = (steps[selfIndex]?.step_id ?? '').trim()
    for (const p of preds) {
      if (p === self)
        return Promise.reject(new Error('前置步骤不得引用本步骤自身'))
      if (!declared.has(p))
        return Promise.reject(new Error(`前置步骤未声明：${p}`))
    }
    return Promise.resolve()
  }
}

/** 新建/编辑抽屉：步骤编辑器 + 乐观锁冲突（409）友好提示与「加载最新版本」恢复 */
function FlowBaselineEditorDrawer({
  flowId,
  onClose,
}: {
  /** null = 新建；否则为编辑对象 ID */
  flowId: string | null
  onClose: () => void
}) {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const [form] = Form.useForm<FlowFormValues>()
  const isEdit = flowId !== null
  /** 409 冲突提示文案（非空时抽屉内展示 Alert，保留用户编辑内容） */
  const [conflict, setConflict] = useState<string | null>(null)

  const detailQuery = useQuery({
    queryKey: ['api-flow-baseline', flowId],
    queryFn: () => apiFlowBaselinesApi.get(flowId as string),
    enabled: isEdit,
  })
  const detail = detailQuery.data

  /** 端点选项（辅助选择 endpoint_id；加载失败时如实提示，可手工核对端点 ID） */
  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })
  const endpointOptions = (endpointsQuery.data?.items ?? []).map((e) => ({
    value: e.id,
    label: e.endpoint_key,
  }))

  const invalidateList = () =>
    void qc.invalidateQueries({ queryKey: ['api-flow-baselines'] })

  const saveMut = useMutation({
    mutationFn: (input: ApiFlowBaselineUpsertInput) =>
      isEdit
        ? apiFlowBaselinesApi.update(
            flowId as string,
            input,
            detail?.version ?? 0,
          )
        : apiFlowBaselinesApi.create(input),
    onSuccess: (saved) => {
      message.success(
        isEdit ? `已保存（版本 ${saved.version}）` : '流程基线已创建',
      )
      invalidateList()
      if (isEdit)
        void qc.invalidateQueries({ queryKey: ['api-flow-baseline', flowId] })
      onClose()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && e.status === 409) {
        // 乐观锁/flow_id 冲突：保留编辑内容，提示加载最新版本后重试
        setConflict(e.message)
        invalidateList()
        if (isEdit)
          void qc.invalidateQueries({ queryKey: ['api-flow-baseline', flowId] })
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const onFinish = (values: FlowFormValues) => {
    setConflict(null)
    saveMut.mutate(toPayload(values))
  }

  /** 409 后恢复：重新拉取最新详情（version 变化触发表单重挂载，覆盖当前编辑内容） */
  const reloadLatest = async () => {
    const r = await detailQuery.refetch()
    if (r.data) setConflict(null)
  }

  const initialValues: FlowFormValues = detail
    ? {
        flow_id: detail.flow_id,
        name: detail.name,
        description: detail.description,
        enabled: detail.enabled,
        // 零值回填为 undefined（表单留空），与提交时的省略口径一致
        max_per_window: detail.max_per_window || undefined,
        rate_window_seconds: detail.rate_window_seconds || undefined,
        steps: (detail.steps ?? []).map((s) => ({
          step_id: s.step_id,
          endpoint_id: s.endpoint_id,
          sequence: s.sequence,
          predecessors: s.predecessors ?? [],
          terminal: s.terminal,
          state_from: s.state_from ?? '',
          state_to: s.state_to ?? '',
          // 零值回填为 undefined（表单留空），与提交时的省略口径一致
          max_per_window: s.max_per_window || undefined,
          rate_window_seconds: s.rate_window_seconds || undefined,
          cancels_flow: s.cancels_flow,
        })),
      }
    : {
        flow_id: '',
        name: '',
        description: '',
        enabled: true,
        steps: [{ sequence: 1, predecessors: [], terminal: false }],
      }

  const watchedSteps = Form.useWatch('steps', form) as
    StepFormValue[] | undefined

  return (
    <Drawer
      title={
        isEdit
          ? `编辑流程基线（版本 ${detail?.version ?? '-'}）`
          : '新建流程基线'
      }
      width={880}
      open
      onClose={onClose}
      destroyOnHidden
      extra={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            loading={saveMut.isPending}
            disabled={isEdit && !detail}
            onClick={() => form.submit()}
          >
            保存
          </Button>
        </Space>
      }
    >
      {conflict ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="版本冲突"
          description={`${conflict}。可加载最新版本后重试（将覆盖当前编辑内容）。`}
          action={
            isEdit ? (
              <Button
                size="small"
                onClick={() => void reloadLatest()}
                loading={detailQuery.isFetching}
              >
                加载最新版本
              </Button>
            ) : undefined
          }
        />
      ) : null}
      {isEdit && detailQuery.error ? (
        <QueryErrorAlert error={detailQuery.error} />
      ) : null}
      {isEdit && !detail && !detailQuery.error ? (
        <Typography.Text type="secondary">加载中…</Typography.Text>
      ) : (
        // version 作为 key：加载到更新版本后表单重挂载，避免乐观锁基线过期
        <Form<FlowFormValues>
          key={isEdit ? `${detail?.id}:${detail?.version}` : 'create'}
          form={form}
          layout="vertical"
          initialValues={initialValues}
          onFinish={onFinish}
        >
          <Space size={16} wrap style={{ display: 'flex' }}>
            <Form.Item
              name="flow_id"
              label="流程标识"
              style={{ width: 320 }}
              rules={[
                { required: true, whitespace: true, message: '流程标识必填' },
                { max: 128, message: '流程标识不超过 128 字符' },
              ]}
              extra="全局唯一，作为发布契约键；与其他基线重复时保存将提示冲突"
            >
              <Input placeholder="如：order-checkout" />
            </Form.Item>
            <Form.Item
              name="name"
              label="展示名"
              style={{ width: 240 }}
              rules={[{ max: 255, message: '展示名不超过 255 字符' }]}
            >
              <Input placeholder="如：下单结账流程" />
            </Form.Item>
            <Form.Item name="enabled" label="启用" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
          <Form.Item
            name="description"
            label="描述"
            rules={[{ max: 1024, message: '描述不超过 1024 字符' }]}
          >
            <Input.TextArea rows={2} placeholder="选填" />
          </Form.Item>
          <Space size={16} wrap style={{ display: 'flex' }}>
            <Form.Item
              name="max_per_window"
              label="流程级短窗次数上限（选填）"
              rules={[{ type: 'integer', min: 1, message: '须为正整数' }]}
              extra="同主体对本流程任意步骤合计调用上限，留空不判定"
            >
              <InputNumber
                min={1}
                precision={0}
                style={{ width: 160 }}
                placeholder="留空不判定"
              />
            </Form.Item>
            <Form.Item
              name="rate_window_seconds"
              label="流程级短窗秒数（选填）"
              rules={[
                {
                  type: 'integer',
                  min: 1,
                  max: 600,
                  message: '须为 1-600 的整数',
                },
              ]}
              extra="覆盖缺省 60s，上限 600s"
            >
              <InputNumber
                min={1}
                max={600}
                precision={0}
                style={{ width: 160 }}
                placeholder="缺省 60"
              />
            </Form.Item>
          </Space>

          <Typography.Title level={5}>步骤</Typography.Title>
          {endpointsQuery.error ? (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 12 }}
              message="端点列表加载失败，绑定端点下拉暂不可用"
              description={
                endpointsQuery.error instanceof ApiError
                  ? endpointsQuery.error.message
                  : '请稍后重试'
              }
            />
          ) : null}
          <Form.List name="steps" rules={[{ validator: validateSteps }]}>
            {(fields, { add, remove }, { errors }) => (
              <>
                {fields.map((field, index) => {
                  const selfId = (watchedSteps?.[index]?.step_id ?? '').trim()
                  const predecessorOptions = (watchedSteps ?? [])
                    .map((s, i) => ({
                      id: (s?.step_id ?? '').trim(),
                      index: i,
                    }))
                    .filter((s) => s.id.length > 0 && s.id !== selfId)
                    .map((s) => ({ value: s.id, label: s.id }))
                  return (
                    <Card
                      key={field.key}
                      size="small"
                      style={{ marginBottom: 12 }}
                      title={`步骤 ${index + 1}`}
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
                          name={[field.name, 'step_id']}
                          label="步骤标识"
                          style={{ width: 200 }}
                          rules={[
                            {
                              required: true,
                              whitespace: true,
                              message: '步骤标识必填',
                            },
                            { max: 128, message: '步骤标识不超过 128 字符' },
                          ]}
                        >
                          <Input placeholder="如：create-order" />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'endpoint_id']}
                          label="绑定端点"
                          style={{ width: 320 }}
                          rules={[
                            { required: true, message: '请选择绑定端点' },
                          ]}
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
                            min={0}
                            precision={0}
                            style={{ width: 100 }}
                          />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'predecessors']}
                          label="前置步骤（AND）"
                          style={{ width: 260 }}
                          rules={[
                            { validator: predecessorValidator(form, index) },
                          ]}
                        >
                          <Select
                            mode="multiple"
                            allowClear
                            placeholder="无前置约束"
                            options={predecessorOptions}
                          />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'terminal']}
                          label="终点步骤"
                          valuePropName="checked"
                        >
                          <Switch />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'state_from']}
                          label="前置状态（选填）"
                          style={{ width: 200 }}
                          rules={[{ max: 64, message: '不超过 64 字符' }]}
                        >
                          <Input placeholder="如：CREATED" />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'state_to']}
                          label="完成后状态（选填）"
                          style={{ width: 200 }}
                          rules={[{ max: 64, message: '不超过 64 字符' }]}
                        >
                          <Input placeholder="如：PAID" />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'max_per_window']}
                          label="短窗次数上限（选填）"
                          rules={[
                            { type: 'integer', min: 1, message: '须为正整数' },
                          ]}
                          extra="短窗内调用次数上限，留空不判定"
                        >
                          <InputNumber
                            min={1}
                            precision={0}
                            style={{ width: 140 }}
                            placeholder="留空不判定"
                          />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'rate_window_seconds']}
                          label="短窗秒数（选填）"
                          rules={[
                            {
                              type: 'integer',
                              min: 1,
                              max: 600,
                              message: '须为 1-600 的整数',
                            },
                          ]}
                          extra="覆盖缺省 60s，上限 600s"
                        >
                          <InputNumber
                            min={1}
                            max={600}
                            precision={0}
                            style={{ width: 140 }}
                            placeholder="缺省 60"
                          />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'cancels_flow']}
                          label="取消语义"
                          valuePropName="checked"
                          extra="声明本步骤为取消操作（如取消订单）"
                        >
                          <Switch />
                        </Form.Item>
                      </Space>
                    </Card>
                  )
                })}
                <Form.ErrorList errors={errors} />
                <Button
                  block
                  icon={<PlusOutlined />}
                  disabled={fields.length >= 64}
                  onClick={() =>
                    add({
                      sequence: (watchedSteps ?? []).length + 1,
                      predecessors: [],
                      terminal: false,
                    })
                  }
                >
                  添加步骤
                </Button>
              </>
            )}
          </Form.List>
        </Form>
      )}
    </Drawer>
  )
}

/** 只读详情抽屉：列表不含步骤明细，详情单独拉取 */
function FlowBaselineDetailDrawer({
  flowId,
  onClose,
}: {
  flowId: string
  onClose: () => void
}) {
  const detailQuery = useQuery({
    queryKey: ['api-flow-baseline', flowId],
    queryFn: () => apiFlowBaselinesApi.get(flowId),
  })
  const detail = detailQuery.data
  return (
    <Drawer
      title={detail ? `流程基线详情：${detail.flow_id}` : '流程基线详情'}
      width={880}
      open
      onClose={onClose}
      destroyOnHidden
    >
      <QueryErrorAlert error={detailQuery.error} />
      {detail ? (
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Typography.Text type="secondary">
            {detail.name || '（无展示名）'} · 版本 {detail.version} ·{' '}
            {detail.enabled ? '已启用' : '已禁用'}
            {detail.max_per_window > 0
              ? ` · 流程限速 ${detail.max_per_window} 次 / ${detail.rate_window_seconds > 0 ? detail.rate_window_seconds : 60}s`
              : ''}
            {' '}· 更新于 {formatDateTime(detail.updated_at)}
          </Typography.Text>
          {detail.description ? (
            <Typography.Paragraph>{detail.description}</Typography.Paragraph>
          ) : null}
          <Table<ApiFlowBaseline['steps'][number]>
            rowKey="step_id"
            size="small"
            pagination={false}
            dataSource={detail.steps ?? []}
            columns={[
              {
                title: '步骤标识',
                dataIndex: 'step_id',
                render: (v: string) => (
                  <Typography.Text code>{v}</Typography.Text>
                ),
              },
              {
                title: '绑定端点',
                dataIndex: 'endpoint_key',
                render: (v: string) => (
                  <Typography.Text code>{v || '-'}</Typography.Text>
                ),
              },
              { title: '序号', dataIndex: 'sequence', width: 70 },
              {
                title: '前置步骤',
                dataIndex: 'predecessors',
                render: (v: string[]) =>
                  v && v.length > 0 ? v.join('、') : '无',
              },
              {
                title: '终点',
                dataIndex: 'terminal',
                width: 70,
                render: (v: boolean) =>
                  v ? <Tag color="blue">终点</Tag> : '-',
              },
              {
                title: '状态转换',
                key: 'state',
                render: (_, s) =>
                  s.state_from || s.state_to
                    ? `${s.state_from || '∅'} → ${s.state_to || '∅'}`
                    : '-',
              },
              {
                title: '短窗限速',
                key: 'rate',
                render: (_, s) =>
                  s.max_per_window > 0
                    ? `${s.max_per_window} 次 / ${s.rate_window_seconds > 0 ? s.rate_window_seconds : 60}s`
                    : '-',
              },
              {
                title: '取消语义',
                dataIndex: 'cancels_flow',
                width: 90,
                render: (v: boolean) =>
                  v ? <Tag color="orange">取消</Tag> : '-',
              },
            ]}
          />
        </Space>
      ) : (
        <Typography.Text type="secondary">加载中…</Typography.Text>
      )}
    </Drawer>
  )
}

/**
 * 流程基线（阶段8 §44）：业务流程步骤基线管理，启用的基线进入下次发布载荷，
 * 网关装配期校验后按端点归组做流程偏离观测（OBSERVE 级只记录不阻断）。
 */
function FlowBaselinesPane() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_flow.manage')

  const [enabledFilter, setEnabledFilter] = useState<boolean | undefined>()
  /** 编辑器：undefined 关闭；null 新建；字符串为编辑对象 ID */
  const [editor, setEditor] = useState<string | null | undefined>(undefined)
  /** 只读详情抽屉对象 ID */
  const [detailId, setDetailId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['api-flow-baselines', enabledFilter],
    queryFn: () => apiFlowBaselinesApi.list({ enabled: enabledFilter }),
  })

  const invalidateList = () =>
    void qc.invalidateQueries({ queryKey: ['api-flow-baselines'] })

  /** 启用/禁用：整体替换语义下先拉详情（含最新 version 与步骤）再 PUT 翻转 enabled */
  const toggleMut = useMutation({
    mutationFn: async (row: ApiFlowBaselineSummary) => {
      const detail = await apiFlowBaselinesApi.get(row.id)
      return apiFlowBaselinesApi.update(
        row.id,
        { ...toUpsertInput(detail), enabled: !detail.enabled },
        detail.version,
      )
    },
    onSuccess: (saved) => {
      message.success(saved.enabled ? '已启用' : '已禁用')
      invalidateList()
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '操作失败')
      invalidateList()
    },
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFlowBaselinesApi.remove(id),
    onSuccess: () => {
      message.success('已删除')
      invalidateList()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const confirmToggle = (row: ApiFlowBaselineSummary) => {
    modal.confirm({
      title: row.enabled ? '禁用流程基线' : '启用流程基线',
      content: row.enabled
        ? `确定禁用「${row.flow_id}」吗？禁用后退出下次发布载荷，网关不再按该基线观测。`
        : `确定启用「${row.flow_id}」吗？启用后进入下次发布载荷，随发布在网关生效。`,
      okText: row.enabled ? '确认禁用' : '确认启用',
      onOk: () => toggleMut.mutateAsync(row),
    })
  }

  const columns: ColumnsType<ApiFlowBaselineSummary> = [
    {
      title: '流程标识',
      dataIndex: 'flow_id',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '名称',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string) =>
        v || <Typography.Text type="secondary">-</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 90,
      render: (v: boolean) =>
        v ? <Tag color="green">已启用</Tag> : <Tag>已禁用</Tag>,
    },
    { title: '步骤数', dataIndex: 'step_count', width: 90 },
    { title: '版本', dataIndex: 'version', width: 80 },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
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
          {canManage ? (
            <>
              <Button
                type="link"
                size="small"
                onClick={() => setEditor(record.id)}
              >
                编辑
              </Button>
              <Button
                type="link"
                size="small"
                onClick={() => confirmToggle(record)}
              >
                {record.enabled ? '禁用' : '启用'}
              </Button>
              <Popconfirm
                title={`删除「${record.flow_id}」？`}
                description="步骤级联删除，不可恢复"
                okText="确认删除"
                okButtonProps={{ danger: true }}
                onConfirm={() => deleteMut.mutate(record.id)}
              >
                <Button type="link" size="small" danger>
                  删除
                </Button>
              </Popconfirm>
            </>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <>
      <Typography.Paragraph type="secondary">
        定义业务流程的步骤基线（步骤绑定 API 端点，前置步骤为 AND
        语义）；启用的基线进入下次发布载荷，网关按流程偏离进行观测记录。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="按状态过滤"
          allowClear
          style={{ width: 140 }}
          value={enabledFilter}
          options={[
            { value: true, label: '已启用' },
            { value: false, label: '已禁用' },
          ]}
          onChange={(v) => setEnabledFilter(v)}
        />
        {canManage ? (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setEditor(null)}
          >
            新建流程基线
          </Button>
        ) : null}
      </Space>
      <SmartTable<ApiFlowBaselineSummary>
        storageKey="api-flow-baselines"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1000 }}
        pagination={false}
      />
      {editor !== undefined ? (
        <FlowBaselineEditorDrawer
          flowId={editor}
          onClose={() => setEditor(undefined)}
        />
      ) : null}
      {detailId ? (
        <FlowBaselineDetailDrawer
          flowId={detailId}
          onClose={() => setDetailId(null)}
        />
      ) : null}
    </>
  )
}

/**
 * 流程基线与强流程（NG-FLOW-04 §1.9 页面行）：流程观察基线（OBSERVE）与强流程（定义版本/
 * 状态图/允许转换/成功条件/异常策略/实例恢复记录 + 实例管理区块）同页分 Tab——
 * 两者物理隔离并行共存，互不消费（§1.2/D2）。
 */
export default function ApiFlowBaselinesPage() {
  return (
    <Card title="流程基线与强流程">
      <Tabs
        items={[
          {
            key: 'baselines',
            label: '流程基线（观察）',
            children: <FlowBaselinesPane />,
          },
          {
            key: 'strong-definitions',
            label: '强流程定义',
            children: <StrongFlowDefinitionsTab />,
          },
          {
            key: 'strong-instances',
            label: '强流程实例',
            children: <StrongFlowInstancesTab />,
          },
        ]}
      />
    </Card>
  )
}
