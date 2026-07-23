import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Drawer, Form, Input, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { apiModelsApi, type ApiModelVersion } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_MODEL_VERSION_STATUS_META } from '../../utils/stage8'

interface CandidateFormValues {
  endpoint_id: string
  endpoint_key: string
  schema_json: string
}

/** API Schema 模型版本（候选 / 正式冻结） */
export default function ApiModelsPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_models.manage')

  const [endpointKey, setEndpointKey] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [form] = Form.useForm<CandidateFormValues>()

  const listQuery = useQuery({
    queryKey: ['api-model-versions', endpointKey, page, pageSize],
    queryFn: () => apiModelsApi.list({ endpoint_key: endpointKey, page, page_size: pageSize }),
  })

  const createMut = useMutation({
    mutationFn: apiModelsApi.createCandidate,
    onSuccess: () => {
      message.success('候选版本已创建')
      setCreateOpen(false)
      form.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-model-versions'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const confirmMut = useMutation({
    mutationFn: (id: string) => apiModelsApi.confirm(id),
    onSuccess: (r) => {
      message.success(r.message || '已冻结')
      void qc.invalidateQueries({ queryKey: ['api-model-versions'] })
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

  const handleCreate = (v: CandidateFormValues) => {
    let schema: Record<string, string> = {}
    try {
      schema = JSON.parse(v.schema_json || '{}') as Record<string, string>
    } catch {
      message.error('结构定义须为 JSON 对象')
      return
    }
    createMut.mutate({ endpoint_id: v.endpoint_id, endpoint_key: v.endpoint_key, schema })
  }

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
        canManage && record.status === 'CANDIDATE' ? (
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
        canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            创建候选
          </Button>
        ) : undefined
      }
    >
      <Typography.Paragraph type="secondary">
        候选版本经人工确认后冻结为正式模型；冻结后不可通过偏离自动扩宽。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="端点键"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setEndpointKey(v || undefined)
            setPage(1)
          }}
        />
      </Space>
      <Table<ApiModelVersion>
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
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
        <Form<CandidateFormValues>
          form={form}
          layout="vertical"
          initialValues={{ schema_json: '{"id":"number","name":"string"}' }}
          onFinish={handleCreate}
        >
          <Form.Item
            name="endpoint_id"
            label="端点 ID"
            rules={[{ required: true, message: '请输入端点 ID' }]}
          >
            <Input placeholder="端点唯一标识" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="endpoint_key"
            label="端点键"
            rules={[{ required: true, message: '请输入端点键' }]}
          >
            <Input placeholder="POST /v1/orders/{id}" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="schema_json"
            label="结构定义（JSON）"
            rules={[{ required: true, message: '请输入结构定义' }]}
          >
            <Input.TextArea rows={4} style={{ fontFamily: 'monospace' }} />
          </Form.Item>
        </Form>
      </Drawer>
    </Card>
  )
}
