import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Drawer, Form, Input, Select, Space, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons'
import { apiEndpointsApi } from '../../api/apiAssets'
import { apiClassificationsApi, type ApiClassificationItem } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'

interface CreateFormValues {
  dimension: string
  value: string
  description?: string
}

interface EndpointClassificationFormValues {
  dimensions?: { dimension: string; value: string }[]
}

/** 用途分类（WDSP / 阶段8）：维护分类体系，并为端点设置维度键值对分类 */
export default function ApiClassificationsPage() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_classification.manage')

  const [createOpen, setCreateOpen] = useState(false)
  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [createForm] = Form.useForm<CreateFormValues>()
  const [endpointForm] = Form.useForm<EndpointClassificationFormValues>()

  const listQuery = useQuery({
    queryKey: ['api-classifications'],
    queryFn: () => apiClassificationsApi.list(),
  })

  /** 端点选择器数据源（端点分类按端点设置） */
  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })

  const createMut = useMutation({
    mutationFn: (body: CreateFormValues) => apiClassificationsApi.create(body),
    onSuccess: (r) => {
      message.success(r.message || '分类已创建')
      setCreateOpen(false)
      createForm.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-classifications'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const setEndpointMut = useMutation({
    mutationFn: (dimensions: { dimension: string; value: string }[]) =>
      apiClassificationsApi.setEndpointClassification(endpointId as string, dimensions),
    onSuccess: (r) => {
      message.success(r.message || '端点分类已保存')
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const handleSaveEndpoint = (v: EndpointClassificationFormValues) => {
    if (!endpointId) {
      message.warning('请先选择端点')
      return
    }
    const dimensions = (v.dimensions ?? [])
      .map((d) => ({ dimension: d.dimension?.trim() ?? '', value: d.value?.trim() ?? '' }))
      .filter((d) => d.dimension && d.value)
    setEndpointMut.mutate(dimensions)
  }

  const columns: ColumnsType<ApiClassificationItem> = [
    { title: '维度', dataIndex: 'dimension', width: 200 },
    { title: '取值', dataIndex: 'value', width: 200 },
    {
      title: '说明',
      dataIndex: 'description',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '来源',
      dataIndex: 'is_builtin',
      width: 100,
      render: (v?: boolean) => (v ? <Tag color="blue">内置</Tag> : <Tag color="purple">自定义</Tag>),
    },
  ]

  return (
    <Card
      title="用途分类"
      extra={
        canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新增分类
          </Button>
        ) : undefined
      }
    >
      <Typography.Paragraph type="secondary">
        分类体系定义可用的维度与取值（如业务域、数据等级）；在下方为具体端点设置维度键值对，用于分类统计与防护策略匹配。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error ?? endpointsQuery.error} />
      <SmartTable<ApiClassificationItem>
        storageKey="api-classifications"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data ?? []}
        scroll={{ x: 800 }}
        pagination={{
          pageSize: 20,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
        }}
      />

      <Card size="small" title="端点分类设置" style={{ marginTop: 16 }}>
        <Form<EndpointClassificationFormValues> form={endpointForm} layout="vertical" onFinish={handleSaveEndpoint}>
          <Form.Item label="目标端点" required>
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
              onChange={(v) => setEndpointId(v)}
            />
          </Form.Item>
          <Form.List name="dimensions">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <Space key={field.key} style={{ display: 'flex', marginBottom: 8 }} align="baseline">
                    <Form.Item
                      name={[field.name, 'dimension']}
                      rules={[{ required: true, message: '请输入维度' }]}
                    >
                      <Input placeholder="维度，如 business_domain" style={{ width: 240 }} autoComplete="off" />
                    </Form.Item>
                    <Form.Item name={[field.name, 'value']} rules={[{ required: true, message: '请输入取值' }]}>
                      <Input placeholder="取值，如 finance" style={{ width: 240 }} autoComplete="off" />
                    </Form.Item>
                    {canManage ? <MinusCircleOutlined onClick={() => remove(field.name)} /> : null}
                  </Space>
                ))}
                {canManage ? (
                  <Button block type="dashed" icon={<PlusOutlined />} onClick={() => add()}>
                    添加维度
                  </Button>
                ) : null}
              </>
            )}
          </Form.List>
          {canManage ? (
            <Button
              type="primary"
              style={{ marginTop: 16 }}
              loading={setEndpointMut.isPending}
              onClick={() => endpointForm.submit()}
            >
              保存
            </Button>
          ) : null}
        </Form>
      </Card>

      <Drawer
        title="新增分类"
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        width={480}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setCreateOpen(false)}>取消</Button>
            <Button type="primary" loading={createMut.isPending} onClick={() => createForm.submit()}>
              创建
            </Button>
          </Space>
        }
      >
        <Form<CreateFormValues> form={createForm} layout="vertical" onFinish={(v) => createMut.mutate(v)}>
          <Form.Item name="dimension" label="维度" rules={[{ required: true, message: '请输入维度' }]}>
            <Input placeholder="如 business_domain" autoComplete="off" />
          </Form.Item>
          <Form.Item name="value" label="取值" rules={[{ required: true, message: '请输入取值' }]}>
            <Input placeholder="如 finance" autoComplete="off" />
          </Form.Item>
          <Form.Item name="description" label="说明（可选）">
            <Input.TextArea rows={3} placeholder="该分类的业务含义" />
          </Form.Item>
        </Form>
      </Drawer>
    </Card>
  )
}
