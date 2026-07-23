import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Drawer, Form, Select, Space, Switch, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi, apiModelsApi } from '../../api/apiAssets'
import { apiParametersApi, type ApiParameter } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import { API_MODEL_VERSION_STATUS_META } from '../../utils/stage8'

/** 参数敏感级别（与 server/internal/apimodels sensitivity_level 枚举一致） */
const SENSITIVITY_LEVEL_META: Record<string, { color: string; label: string }> = {
  UNKNOWN: { color: 'default', label: '未知' },
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
}

interface EditFormValues {
  required: boolean
  nullable: boolean
  empty_allowed: boolean
  sensitivity_level: string
}

/** 参数模型（WDSP / 阶段8）：按端点与模型版本查看参数约束，可人工修正与采纳推荐约束 */
export default function ApiParametersPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'api_parameter.edit')

  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [modelVersionId, setModelVersionId] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<ApiParameter | null>(null)
  const [form] = Form.useForm<EditFormValues>()

  /** 端点选择器数据源（参数按端点 → 模型版本两级定位） */
  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })

  /** 端点列表加载后默认选中第一个，避免页面空白 */
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
    mutationFn: (body: EditFormValues) => apiParametersApi.update(editing?.id as string, body),
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

  /** 行内操作统一二次确认：采纳后以推荐约束作为确认约束 */
  const confirmRecommended = (record: ApiParameter) => {
    modal.confirm({
      title: '采纳推荐约束',
      content: `确定采纳参数「${record.parameter_name}」的推荐约束吗？采纳后以推荐约束作为该参数的确认约束。`,
      onOk: () => confirmMut.mutate(record.id),
    })
  }

  const openEdit = (record: ApiParameter) => {
    setEditing(record)
    form.setFieldsValue({
      required: record.required,
      nullable: record.nullable,
      empty_allowed: record.empty_allowed,
      sensitivity_level: record.sensitivity_level || 'UNKNOWN',
    })
  }

  const columns: ColumnsType<ApiParameter> = [
    { title: '方向', dataIndex: 'direction', width: 100 },
    { title: '位置', dataIndex: 'location', width: 100 },
    {
      title: '参数名',
      dataIndex: 'parameter_name',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    { title: '基础类型', dataIndex: 'base_type', width: 110 },
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
      align: 'right',
      render: (v: number) => (v * 100).toFixed(0) + '%',
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
        选择端点与模型版本后查看参数级约束：方向、位置、类型与敏感级别；可人工修正参数属性，或一键采纳学习产出的推荐约束。
      </Typography.Paragraph>
      <QueryErrorAlert error={endpointsQuery.error ?? versionsQuery.error ?? listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="选择端点"
          showSearch
          optionFilterProp="label"
          style={{ width: 320 }}
          loading={endpointsQuery.isLoading}
          value={endpointId}
          options={(endpointsQuery.data?.items ?? []).map((e) => ({
            value: e.id,
            label: e.endpoint_key,
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
      </Space>
      <Table<ApiParameter>
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        locale={modelVersionId ? undefined : { emptyText: '请先选择端点与模型版本查看参数' }}
        scroll={{ x: 1200 }}
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
        <Form<EditFormValues> form={form} layout="vertical" onFinish={(v) => updateMut.mutate(v)}>
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
        </Form>
      </Drawer>
    </Card>
  )
}
