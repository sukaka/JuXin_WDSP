import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Form, Input, Select, Space, Table, Tag, Typography } from 'antd'
import { apiEndpointsApi, type ApiEndpointItem } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'

/** API 端点资产（WDSP / 阶段8） */
export default function ApiEndpointsPage() {
  const { message } = App.useApp()
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const listQuery = useQuery({
    queryKey: ['api-endpoints', page],
    queryFn: () => apiEndpointsApi.list({ page, page_size: 20 }),
  })
  const [form] = Form.useForm()

  const discoverMut = useMutation({
    mutationFn: apiEndpointsApi.discover,
    onSuccess: () => {
      message.success('已登记发现结果')
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

  const columns = [
    { title: '方法', dataIndex: 'method', width: 90 },
    { title: '路径模板', dataIndex: 'path_template', ellipsis: true },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 90,
      render: (v: number) => (v * 100).toFixed(0) + '%',
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 120,
      render: (v: string) => (
        <Tag color={v === 'CONFIRMED' ? 'green' : 'blue'}>{v}</Tag>
      ),
    },
    { title: '命中', dataIndex: 'hit_count', width: 80 },
    {
      title: '操作',
      width: 120,
      render: (_: unknown, row: ApiEndpointItem) =>
        row.status !== 'CONFIRMED' ? (
          <Button type="link" size="small" onClick={() => confirmMut.mutate(row.id)}>
            确认
          </Button>
        ) : (
          <Typography.Text type="secondary">已确认</Typography.Text>
        ),
    },
  ]

  return (
    <Card title="API 端点资产">
      <Typography.Paragraph type="secondary">
        路径自动归一化（如 /users/123 → /users/&#123;id&#125;）。确认后进入正式资产；学习模型见「API
        模型版本」。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Form
        form={form}
        layout="inline"
        style={{ marginBottom: 16 }}
        onFinish={(v) =>
          discoverMut.mutate({
            method: v.method,
            path: v.path,
            confidence: 0.6,
          })
        }
        initialValues={{ method: 'GET' }}
      >
        <Form.Item name="method" rules={[{ required: true }]}>
          <Select
            style={{ width: 100 }}
            options={['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => ({
              value: m,
              label: m,
            }))}
          />
        </Form.Item>
        <Form.Item name="path" rules={[{ required: true, message: '路径' }]}>
          <Input placeholder="/v1/users/123" style={{ width: 280 }} />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={discoverMut.isPending}>
            登记发现
          </Button>
        </Form.Item>
      </Form>
      <Table
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        pagination={{
          current: page,
          pageSize: 20,
          total: listQuery.data?.total ?? 0,
          onChange: setPage,
        }}
      />
    </Card>
  )
}
