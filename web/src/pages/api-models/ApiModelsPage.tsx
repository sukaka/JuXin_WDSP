import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Drawer, Form, Input, Select, Space, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { apiEndpointsApi, apiModelsApi, type ApiModelVersion } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_MODEL_VERSION_STATUS_META } from '../../utils/stage8'

interface CandidateFormValues {
  schema_json: string
  change_summary?: string
}

/** API Schema 模型版本（按端点管理，候选经人工确认后冻结为正式模型） */
export default function ApiModelsPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'api_model.edit')

  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [form] = Form.useForm<CandidateFormValues>()

  /** 端点选择器数据源（模型版本按端点查询） */
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

  const listQuery = useQuery({
    queryKey: ['api-models', endpointId, page, pageSize],
    queryFn: () => apiModelsApi.list(endpointId as string, { page, page_size: pageSize }),
    enabled: !!endpointId,
  })

  const createMut = useMutation({
    mutationFn: (body: { schema: Record<string, string>; change_summary?: string }) =>
      apiModelsApi.createCandidate(endpointId as string, body),
    onSuccess: () => {
      message.success('候选版本已创建')
      setCreateOpen(false)
      form.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-models'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const confirmMut = useMutation({
    mutationFn: (id: string) => apiModelsApi.confirm(id),
    onSuccess: (r) => {
      message.success(r.message || '已冻结')
      void qc.invalidateQueries({ queryKey: ['api-models'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '冻结失败'),
  })

  /** 行内操作统一二次确认：冻结后不可通过偏离自动扩宽 */
  const confirmFreeze = (record: ApiModelVersion) => {
    modal.confirm({
      title: '冻结确认',
      content: `确定将端点「${record.endpoint_key}」的候选版本冻结为正式模型吗？冻结后不可通过偏离自动扩宽。`,
      onOk: () => confirmMut.mutate(record.id),
    })
  }

  const openCreate = () => {
    if (!endpointId) {
      message.warning('请先选择端点')
      return
    }
    setCreateOpen(true)
  }

  const handleCreate = (v: CandidateFormValues) => {
    if (!endpointId) {
      message.warning('请先选择端点')
      return
    }
    let schema: Record<string, string> = {}
    try {
      schema = JSON.parse(v.schema_json || '{}') as Record<string, string>
    } catch {
      message.error('结构定义须为 JSON 对象')
      return
    }
    createMut.mutate({ schema, change_summary: v.change_summary || undefined })
  }

  const selectedEndpoint = endpointsQuery.data?.items.find((e) => e.id === endpointId)

  const columns: ColumnsType<ApiModelVersion> = [
    {
      title: '端点键',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_MODEL_VERSION_STATUS_META} />,
    },
    {
      title: '哈希',
      dataIndex: 'content_hash',
      width: 140,
      render: (v: string) => (v ? <Typography.Text code>{v.slice(0, 10)}…</Typography.Text> : '-'),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 110,
      fixed: 'right',
      render: (_, record) =>
        canEdit && record.status === 'CANDIDATE' ? (
          <Button type="link" size="small" onClick={() => confirmFreeze(record)}>
            确认冻结
          </Button>
        ) : null,
    },
  ]

  return (
    <Card
      title="接口模型版本"
      extra={
        canEdit ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            创建候选
          </Button>
        ) : undefined
      }
    >
      <Typography.Paragraph type="secondary">
        选择端点后管理其 Schema 模型版本：候选版本经人工确认后冻结为正式模型；冻结后不可通过偏离自动扩宽。
      </Typography.Paragraph>
      <QueryErrorAlert error={endpointsQuery.error ?? listQuery.error} />
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
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiModelVersion>
        storageKey="api-models"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        locale={endpointId ? undefined : { emptyText: '请先选择端点查看模型版本' }}
        scroll={{ x: 1000 }}
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
        title="创建候选版本"
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        width={560}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setCreateOpen(false)}>取消</Button>
            <Button type="primary" loading={createMut.isPending} onClick={() => form.submit()}>
              创建
            </Button>
          </Space>
        }
      >
        <Typography.Paragraph type="secondary">
          目标端点：<Typography.Text code>{selectedEndpoint?.endpoint_key ?? '-'}</Typography.Text>
        </Typography.Paragraph>
        <Form<CandidateFormValues>
          form={form}
          layout="vertical"
          initialValues={{ schema_json: '{"id":"number","name":"string"}' }}
          onFinish={handleCreate}
        >
          <Form.Item
            name="schema_json"
            label="结构定义（JSON）"
            rules={[{ required: true, message: '请输入结构定义' }]}
          >
            <Input.TextArea rows={4} style={{ fontFamily: 'monospace' }} />
          </Form.Item>
          <Form.Item name="change_summary" label="变更说明（可选）">
            <Input placeholder="本次候选相对上一版本的变化" autoComplete="off" />
          </Form.Item>
        </Form>
      </Drawer>
    </Card>
  )
}
