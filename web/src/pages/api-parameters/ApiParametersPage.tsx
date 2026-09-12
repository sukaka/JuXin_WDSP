import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, AutoComplete, Button, Card, Drawer, Form, InputNumber, Select, Space, Switch, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi, apiModelsApi } from '../../api/apiAssets'
import { apiParametersApi, type ApiParameter } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { API_BASE_TYPE_META, API_MODEL_VERSION_STATUS_META, API_PARAM_DIRECTION_META, API_PARAM_LOCATION_META, API_SEMANTIC_TYPE_META } from '../../utils/stage8'

/** 参数敏感级别（与 server/internal/apimodels sensitivity_level 枚举一致） */
const SENSITIVITY_LEVEL_META: Record<string, { color: string; label: string }> = {
  UNKNOWN: { color: 'default', label: '未知' },
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
}

/** 约束内容紧凑展示：每行一条「键: 值」，空约束显示占位符（四层视图单元格共用） */
function ConstraintLines({ value }: { value: Record<string, unknown> | null | undefined }) {
  const entries = Object.entries(value ?? {})
  if (entries.length === 0) return <Typography.Text type="secondary">—</Typography.Text>
  return (
    <div style={{ fontSize: 12, lineHeight: '20px' }}>
      {entries.map(([k, v]) => (
        <div key={k}>
          <Typography.Text code style={{ fontSize: 12 }}>
            {k}
          </Typography.Text>
          <Typography.Text style={{ fontSize: 12 }}>: {typeof v === 'string' ? v : JSON.stringify(v)}</Typography.Text>
        </div>
      ))}
    </div>
  )
}

/** 语义类型预设选项（自由输入，与 server/internal/apimodels statistics.go 推断词表对齐） */
const SEMANTIC_TYPE_OPTIONS = ['id', 'uuid', 'email', 'phone', 'token', 'secret', 'money', 'captcha', 'username', 'id_card', 'bank_card'].map(
  (v) => ({ value: v }),
)

interface EditFormValues {
  required: boolean
  nullable: boolean
  empty_allowed: boolean
  sensitivity_level: string
  /** 语义类型（自由输入，清空即提交空串） */
  semantic_type?: string
  /** 确认约束（钉死词汇 min_length/max_length/minimum/maximum/enum），空值不写入 */
  min_length?: number | null
  max_length?: number | null
  minimum?: number | null
  maximum?: number | null
  enum?: string[]
}

/** PATCH 提交体：4 个既有字段 + semantic_type + confirmed_constraints（整体覆盖语义，与后端一致） */
interface UpdatePayload {
  required: boolean
  nullable: boolean
  empty_allowed: boolean
  sensitivity_level: string
  semantic_type?: string
  confirmed_constraints: Record<string, unknown>
}

/** 由表单值组装 confirmed_constraints（仅收纳非空项；全空即 {}，表示清空确认约束） */
function buildConfirmedConstraints(v: EditFormValues): Record<string, unknown> {
  const cc: Record<string, unknown> = {}
  if (typeof v.min_length === 'number') cc.min_length = v.min_length
  if (typeof v.max_length === 'number') cc.max_length = v.max_length
  if (typeof v.minimum === 'number') cc.minimum = v.minimum
  if (typeof v.maximum === 'number') cc.maximum = v.maximum
  if (v.enum && v.enum.length > 0) cc.enum = v.enum
  return cc
}

/** 参数模型（WDSP / 阶段8）：按接口与模型版本查看参数约束，可人工修正与采纳推荐约束 */
export default function ApiParametersPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'api_parameter.edit')

  const [applicationId, setApplicationId] = useState<string | undefined>()
  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [modelVersionId, setModelVersionId] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<ApiParameter | null>(null)
  const [detailRecord, setDetailRecord] = useState<ApiParameter | null>(null)
  const [form] = Form.useForm<EditFormValues>()

  /** 站点选择器数据源（各站点接口数汇总） */
  const siteSummaryQuery = useQuery({
    queryKey: ['api-endpoints', 'site-summary'],
    queryFn: () => apiEndpointsApi.siteSummary(),
  })

  /** 接口选择器数据源（参数按站点 → 接口 → 模型版本三级定位） */
  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options', applicationId],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100, application_id: applicationId || undefined }),
  })

  /** 接口列表加载后默认选中第一个，避免页面空白 */
  useEffect(() => {
    if (!endpointId && endpointsQuery.data?.items.length) {
      setEndpointId(endpointsQuery.data.items[0].id)
    }
  }, [endpointId, endpointsQuery.data])

  /** 模型版本选择器数据源 */
  const versionsQuery = useQuery({
    queryKey: ['api-models', 'versions', endpointId],
    queryFn: () => apiModelsApi.list(endpointId as string, { page: 1, page_size: 100 }),
    enabled: !!endpointId,
  })

  /** 版本列表加载后默认选中第一个 */
  useEffect(() => {
    if (!modelVersionId && versionsQuery.data?.items.length) {
      setModelVersionId(versionsQuery.data.items[0].id)
    }
  }, [modelVersionId, versionsQuery.data])

  const listQuery = useQuery({
    queryKey: ['api-parameters', modelVersionId, page, pageSize],
    queryFn: () => apiParametersApi.listByModel(modelVersionId as string, { page, page_size: pageSize }),
    enabled: !!modelVersionId,
  })

  const updateMut = useMutation({
    mutationFn: (body: UpdatePayload) => apiParametersApi.update(editing?.id as string, body),
    onSuccess: (r) => {
      message.success(r.message || '已保存')
      setEditing(null)
      void qc.invalidateQueries({ queryKey: ['api-parameters'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const confirmMut = useMutation({
    mutationFn: (id: string) => apiParametersApi.confirm(id),
    onSuccess: (r) => {
      message.success(r.message || '已采纳推荐约束')
      void qc.invalidateQueries({ queryKey: ['api-parameters'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '采纳失败'),
  })

  const batchConfirmMut = useMutation({
    mutationFn: () => apiParametersApi.confirmBatch(modelVersionId as string),
    onSuccess: (r) => {
      message.success(r.message || `批量确认：成功 ${r.confirmed}，跳过 ${r.skipped}`)
      void qc.invalidateQueries({ queryKey: ['api-parameters'] })
      void qc.invalidateQueries({ queryKey: ['api-model-maturity'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '批量确认失败'),
  })

  /** 行内操作统一二次确认：采纳后以推荐约束作为确认约束 */
  const confirmRecommended = (record: ApiParameter) => {
    modal.confirm({
      title: '采纳推荐约束',
      content: `确定采纳参数「${record.parameter_name}」的推荐约束吗？采纳后以推荐约束作为该参数的确认约束。`,
      onOk: () => confirmMut.mutate(record.id),
    })
  }

  const confirmBatchAll = () => {
    modal.confirm({
      title: '批量采纳推荐约束',
      content: '将对本模型版本中全部「有推荐约束」的参数执行采纳（推荐为空的会跳过）。确认后请再发布配置到网关。',
      onOk: () => batchConfirmMut.mutate(),
    })
  }

  const openEdit = (record: ApiParameter) => {
    setEditing(record)
    const cc = (record.confirmed_constraints ?? {}) as Record<string, unknown>
    form.setFieldsValue({
      required: record.required,
      nullable: record.nullable,
      empty_allowed: record.empty_allowed,
      sensitivity_level: record.sensitivity_level || 'UNKNOWN',
      semantic_type: record.semantic_type || undefined,
      min_length: typeof cc.min_length === 'number' ? cc.min_length : undefined,
      max_length: typeof cc.max_length === 'number' ? cc.max_length : undefined,
      minimum: typeof cc.minimum === 'number' ? cc.minimum : undefined,
      maximum: typeof cc.maximum === 'number' ? cc.maximum : undefined,
      enum: Array.isArray(cc.enum)
        ? (cc.enum as unknown[]).filter((x): x is string => typeof x === 'string')
        : undefined,
    })
  }

  /** 提交：5 个约束控件归并进 confirmed_constraints，与既有 4 字段及语义类型一起 PATCH。
   *  semantic_type 清空后按空串提交（后端指针语义：省略=保留，空串=清空） */
  const submitEdit = (v: EditFormValues) => {
    updateMut.mutate({
      required: v.required,
      nullable: v.nullable,
      empty_allowed: v.empty_allowed,
      sensitivity_level: v.sensitivity_level,
      semantic_type: v.semantic_type ?? '',
      confirmed_constraints: buildConfirmedConstraints(v),
    })
  }

  const columns: ColumnsType<ApiParameter> = [
    {
      title: '方向',
      dataIndex: 'direction',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={API_PARAM_DIRECTION_META} />,
    },
    {
      title: '位置',
      dataIndex: 'location',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_PARAM_LOCATION_META} />,
    },
    {
      title: '参数名',
      dataIndex: 'parameter_name',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '基础类型',
      dataIndex: 'base_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_BASE_TYPE_META} />,
    },
    {
      title: '语义类型',
      dataIndex: 'semantic_type',
      width: 110,
      render: (v: string) => (v ? <StatusTag value={v} map={API_SEMANTIC_TYPE_META} /> : <Typography.Text type="secondary">—</Typography.Text>),
    },
    {
      title: '必填',
      dataIndex: 'required',
      width: 80,
      render: (v: boolean) => (v ? <Tag color="green">是</Tag> : <Tag>否</Tag>),
    },
    {
      title: '可空',
      dataIndex: 'nullable',
      width: 80,
      render: (v: boolean) => (v ? <Tag color="green">是</Tag> : <Tag>否</Tag>),
    },
    {
      title: '敏感级别',
      dataIndex: 'sensitivity_level',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={SENSITIVITY_LEVEL_META} />,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 90,
      render: (v: number) => (v * 100).toFixed(0) + '%',
    },
    // —— 四层视图：Observed / Recommended / Confirmed / Runtime 同屏对比 ——
    {
      title: 'Observed（观测）',
      dataIndex: 'observed_constraints',
      width: 170,
      render: (v: Record<string, unknown>) => <ConstraintLines value={v} />,
    },
    {
      title: 'Recommended（推荐）',
      dataIndex: 'recommended_constraints',
      width: 170,
      render: (v: Record<string, unknown>) => <ConstraintLines value={v} />,
    },
    {
      title: 'Confirmed（确认）',
      dataIndex: 'confirmed_constraints',
      width: 170,
      render: (v: Record<string, unknown>) => <ConstraintLines value={v} />,
    },
    {
      // Runtime 列 = 已下发网关的 confirmed 快照：当前无独立运行时快照接口，
      // 以 Confirmed 约束作为「Runtime 生效值」展示（配置发布后网关即按 Confirmed 检测）。
      title: (
        <Tooltip title="Runtime 生效值 = 已确认约束（Confirmed）快照，随配置发布下发网关后生效；当前无独立运行时快照接口">
          <span>Runtime（生效值）</span>
        </Tooltip>
      ),
      key: 'runtime_constraints',
      width: 170,
      render: (_, record) => <ConstraintLines value={record.confirmed_constraints} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      fixed: 'right',
      render: (_, record) =>
        canEdit ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => openEdit(record)}>
              编辑
            </Button>
            <Button type="link" size="small" onClick={() => confirmRecommended(record)}>
              采纳推荐约束
            </Button>
          </Space>
        ) : null,
    },
  ]

  return (
    <Card title="参数模型">
      <Typography.Paragraph type="secondary">
        这个接口该收什么参数？该长什么样
      </Typography.Paragraph>
      <QueryErrorAlert error={endpointsQuery.error ?? versionsQuery.error ?? listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Typography.Text>站点选择：</Typography.Text>
        <Select
          placeholder="全部站点"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 260 }}
          value={applicationId}
          loading={siteSummaryQuery.isLoading}
          options={(siteSummaryQuery.data?.items ?? []).map((s) => ({
            value: s.application_id,
            label: `${s.application_domain || s.application_name}（${s.endpoint_count}）`,
          }))}
          onChange={(v) => {
            setApplicationId(v)
            setEndpointId(undefined)
            setModelVersionId(undefined)
            setPage(1)
          }}
        />
        <Select
          placeholder="选择接口"
          showSearch
          optionFilterProp="label"
          style={{ width: 360 }}
          loading={endpointsQuery.isLoading}
          value={endpointId}
          options={(endpointsQuery.data?.items ?? []).map((e) => ({
            value: e.id,
            label: e.application_domain || e.application_name
              ? `${e.endpoint_key}（${e.application_domain || e.application_name}）`
              : e.endpoint_key,
          }))}
          onChange={(v) => {
            setEndpointId(v)
            setModelVersionId(undefined)
            setPage(1)
          }}
        />
        <Select
          placeholder="模型版本"
          style={{ width: 200 }}
          loading={versionsQuery.isLoading}
          value={modelVersionId}
          options={(versionsQuery.data?.items ?? []).map((m) => ({
            value: m.id,
            label: `v${m.version_number} ${API_MODEL_VERSION_STATUS_META[m.status]?.label ?? m.status}`,
          }))}
          onChange={(v) => {
            setModelVersionId(v)
            setPage(1)
          }}
        />
        {canEdit && modelVersionId ? (
          <Button type="primary" loading={batchConfirmMut.isPending} onClick={confirmBatchAll}>
            批量采纳推荐约束
          </Button>
        ) : null}
      </Space>
      <SmartTable<ApiParameter>
        storageKey="api-parameters"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        locale={modelVersionId ? undefined : { emptyText: '请先选择接口与模型版本查看参数' }}
        scroll={{ x: 1900 }}
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

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="参数详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />

      <Drawer
        title="编辑参数"
        open={!!editing}
        onClose={() => setEditing(null)}
        width={480}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setEditing(null)}>取消</Button>
            <Button type="primary" loading={updateMut.isPending} onClick={() => form.submit()}>
              保存
            </Button>
          </Space>
        }
      >
        <Typography.Paragraph type="secondary">
          参数：<Typography.Text code>{editing?.parameter_name ?? '-'}</Typography.Text>
        </Typography.Paragraph>
        <Form<EditFormValues> form={form} layout="vertical" onFinish={submitEdit}>
          <Form.Item name="required" label="必填" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="nullable" label="可空" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="empty_allowed" label="允许空值" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item name="sensitivity_level" label="敏感级别" rules={[{ required: true, message: '请选择敏感级别' }]}>
            <Select
              options={Object.entries(SENSITIVITY_LEVEL_META).map(([value, meta]) => ({
                value,
                label: `${value}（${meta.label}）`,
              }))}
            />
          </Form.Item>
          <Form.Item name="semantic_type" label="语义类型" tooltip="可自由输入；语义类型用于参数画像与敏感级别自动标注兜底">
            <AutoComplete allowClear options={SEMANTIC_TYPE_OPTIONS} placeholder="选择或输入语义类型" />
          </Form.Item>
          <Typography.Paragraph type="secondary">
            确认约束随发布通道下发网关并参与运行时检测；留空的约束项不生效，全部留空即清空确认约束。
          </Typography.Paragraph>
          <Form.Item name="min_length" label="最小长度（min_length，字符数）">
            <InputNumber min={0} precision={0} style={{ width: '100%' }} placeholder="不限制" />
          </Form.Item>
          <Form.Item name="max_length" label="最大长度（max_length，字符数）">
            <InputNumber min={0} precision={0} style={{ width: '100%' }} placeholder="不限制" />
          </Form.Item>
          <Form.Item name="minimum" label="数值下界（minimum）">
            <InputNumber style={{ width: '100%' }} placeholder="不限制" />
          </Form.Item>
          <Form.Item name="maximum" label="数值上界（maximum）">
            <InputNumber style={{ width: '100%' }} placeholder="不限制" />
          </Form.Item>
          <Form.Item name="enum" label="枚举（enum，回车添加取值）">
            <Select mode="tags" open={false} placeholder="输入取值后回车" tokenSeparators={[',']} />
          </Form.Item>
        </Form>
      </Drawer>
    </Card>
  )
}
