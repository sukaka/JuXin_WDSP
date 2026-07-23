import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Drawer, Form, Input, Select, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { apiEndpointsApi, type ApiEndpointItem } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'

interface DiscoverFormValues {
  method: string
  path: string
}

/** API 端点资产（WDSP / 阶段8） */
export default function ApiEndpointsPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_endpoints.manage')

  const [status, setStatus] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [discoverOpen, setDiscoverOpen] = useState(false)
  const [form] = Form.useForm<DiscoverFormValues>()

  const listQuery = useQuery({
    queryKey: ['api-endpoints', status, page, pageSize],
    queryFn: () => apiEndpointsApi.list({ status, page, page_size: pageSize }),
  })

  const discoverMut = useMutation({
    mutationFn: apiEndpointsApi.discover,
    onSuccess: () => {
      message.success('已登记发现结果')
      setDiscoverOpen(false)
      form.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '发现失败'),
  })

  const confirmMut = useMutation({
    mutationFn: (id: string) => apiEndpointsApi.confirm(id),
    onSuccess: (r) => {
      message.success(r.message || '已确认')
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '确认失败'),
  })

  /** 行内操作统一二次确认 */
  const confirmEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '操作确认',
      content: `确定将端点「${record.method} ${record.path_template}」确认为正式接口资产吗？确认后进入正式资产管理。`,
      onOk: () => confirmMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiEndpointItem> = [
    { title: '方法', dataIndex: 'method', width: 90 },
    {
      title: '路径模板',
      dataIndex: 'path_template',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 90,
      align: 'right',
      render: (v: number) => (v * 100).toFixed(0) + '%',
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_ENDPOINT_STATUS_META} />,
    },
    { title: '命中', dataIndex: 'hit_count', width: 80, align: 'right' },
    {
      title: '最近访问',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      fixed: 'right',
      render: (_, record) => {
        if (!canManage) return null
        return record.status !== 'CONFIRMED' ? (
          <Button type="link" size="small" onClick={() => confirmEndpoint(record)}>
            确认
          </Button>
        ) : (
          <Typography.Text type="secondary">已确认</Typography.Text>
        )
      },
    },
  ]

  return (
    <Card
      title="接口端点资产"
      extra={
        canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setDiscoverOpen(true)}>
            登记发现
          </Button>
        ) : undefined
      }
    >
      <Typography.Paragraph type="secondary">
        路径自动归一化（如 /users/123 → /users/&#123;id&#125;）。确认后进入正式资产；学习模型见「接口
        模型版本」。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 140 }}
          value={status}
          options={Object.entries(API_ENDPOINT_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
      </Space>
      <Table<ApiEndpointItem>
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1100 }}
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
        title="登记接口发现"
        open={discoverOpen}
        onClose={() => setDiscoverOpen(false)}
        width={480}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setDiscoverOpen(false)}>取消</Button>
            <Button type="primary" loading={discoverMut.isPending} onClick={() => form.submit()}>
              登记
            </Button>
          </Space>
        }
      >
        <Form<DiscoverFormValues>
          form={form}
          layout="vertical"
          initialValues={{ method: 'GET' }}
          onFinish={(v) => discoverMut.mutate({ method: v.method, path: v.path, confidence: 0.6 })}
        >
          <Form.Item name="method" label="请求方法" rules={[{ required: true, message: '请选择请求方法' }]}>
            <Select
              options={['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => ({ value: m, label: m }))}
            />
          </Form.Item>
          <Form.Item
            name="path"
            label="请求路径"
            rules={[{ required: true, message: '请输入请求路径' }]}
            extra="路径将自动归一化（如 /users/123 → /users/{id}）"
          >
            <Input placeholder="/v1/users/123" autoComplete="off" />
          </Form.Item>
        </Form>
      </Drawer>
    </Card>
  )
}
