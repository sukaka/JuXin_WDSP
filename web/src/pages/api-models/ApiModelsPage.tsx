import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App, Button, Card, Form, Input, Table, Tag, Typography } from 'antd'
import { apiModelsApi, type ApiModelVersion } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'

/** API Schema 模型版本（候选 / 正式冻结） */
export default function ApiModelsPage() {
  const { message } = App.useApp()
  const qc = useQueryClient()
  const [page, setPage] = useState(1)
  const listQuery = useQuery({
    queryKey: ['api-model-versions', page],
    queryFn: () => apiModelsApi.list({ page, page_size: 20 }),
  })
  const [form] = Form.useForm()

  const createMut = useMutation({
    mutationFn: apiModelsApi.createCandidate,
    onSuccess: () => {
      message.success('候选版本已创建')
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

  return (
    <Card title="API 模型版本">
      <Typography.Paragraph type="secondary">
        候选版本经人工确认后冻结为正式模型；冻结后不可通过偏离自动扩宽。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Form
        form={form}
        layout="vertical"
        style={{ maxWidth: 560, marginBottom: 24 }}
        onFinish={(v) => {
          let schema: Record<string, string> = {}
          try {
            schema = JSON.parse(v.schema_json || '{}') as Record<string, string>
          } catch {
            message.error('schema 须为 JSON 对象')
            return
          }
          createMut.mutate({
            endpoint_id: v.endpoint_id,
            endpoint_key: v.endpoint_key,
            schema,
          })
        }}
      >
        <Form.Item name="endpoint_id" label="端点 ID" rules={[{ required: true }]}>
          <Input placeholder="UUID" />
        </Form.Item>
        <Form.Item name="endpoint_key" label="端点键" rules={[{ required: true }]}>
          <Input placeholder="POST /v1/orders/{id}" />
        </Form.Item>
        <Form.Item
          name="schema_json"
          label="Schema JSON"
          initialValue='{"id":"number","name":"string"}'
          rules={[{ required: true }]}
        >
          <Input.TextArea rows={3} />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={createMut.isPending}>
          创建候选
        </Button>
      </Form>
      <Table
        rowKey="id"
        loading={listQuery.isLoading}
        dataSource={listQuery.data?.items ?? []}
        pagination={{ current: page, pageSize: 20, total: listQuery.data?.total ?? 0, onChange: setPage }}
        columns={[
          { title: '端点键', dataIndex: 'endpoint_key', ellipsis: true },
          {
            title: '状态',
            dataIndex: 'status',
            width: 120,
            render: (v: string) => (
              <Tag color={v === 'FORMAL' ? 'green' : v === 'CANDIDATE' ? 'blue' : 'default'}>{v}</Tag>
            ),
          },
          {
            title: '哈希',
            dataIndex: 'content_hash',
            width: 120,
            render: (v: string) => v?.slice(0, 10) + '…',
          },
          {
            title: '操作',
            width: 120,
            render: (_: unknown, row: ApiModelVersion) =>
              row.status === 'CANDIDATE' ? (
                <Button type="link" size="small" onClick={() => confirmMut.mutate(row.id)}>
                  确认冻结
                </Button>
              ) : null,
          },
        ]}
      />
    </Card>
  )
}
