import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Drawer, Form, Input, Modal, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { apiSpecsApi, type ApiImportSpec, type ApiSpecDiff } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_SPEC_DIFF_TYPE_META } from '../../utils/stage8'

interface ImportFormValues {
  file_name?: string
  spec_json: string
}

/** 规范对比（WDSP / 阶段8）：导入 OpenAPI 规范并与运行时发现的端点对比差异 */
export default function ApiSpecsPage() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canImport = hasPermission(permissions, 'api_spec.import')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [importOpen, setImportOpen] = useState(false)
  const [diffSpec, setDiffSpec] = useState<ApiImportSpec | null>(null)
  const [diffPage, setDiffPage] = useState(1)
  const [diffPageSize, setDiffPageSize] = useState(20)
  const [form] = Form.useForm<ImportFormValues>()

  const listQuery = useQuery({
    queryKey: ['api-specs', page, pageSize],
    queryFn: () => apiSpecsApi.list({ page, page_size: pageSize }),
  })

  const diffQuery = useQuery({
    queryKey: ['api-specs', 'diff', diffSpec?.id, diffPage, diffPageSize],
    queryFn: () => apiSpecsApi.diff(diffSpec?.id as string, { page: diffPage, page_size: diffPageSize }),
    enabled: !!diffSpec,
  })

  const importMut = useMutation({
    mutationFn: (body: { file_name?: string; spec: Record<string, unknown> }) => apiSpecsApi.import(body),
    onSuccess: (r) => {
      message.success(r.message || `导入成功，发现 ${r.diffs} 处差异`)
      setImportOpen(false)
      form.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-specs'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '导入失败'),
  })

  const handleImport = (v: ImportFormValues) => {
    let spec: Record<string, unknown>
    try {
      const parsed: unknown = JSON.parse(v.spec_json)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        message.error('规范内容须为 JSON 对象')
        return
      }
      spec = parsed as Record<string, unknown>
    } catch {
      message.error('规范内容须为合法 JSON')
      return
    }
    importMut.mutate({ file_name: v.file_name?.trim() || undefined, spec })
  }

  const openDiff = (record: ApiImportSpec) => {
    setDiffSpec(record)
    setDiffPage(1)
  }

  const columns: ColumnsType<ApiImportSpec> = [
    {
      title: '文件名',
      dataIndex: 'file_name',
      ellipsis: true,
      render: (v?: string | null) => v || '-',
    },
    { title: '格式', dataIndex: 'format', width: 110, render: (v: string) => v || '-' },
    { title: '端点数', dataIndex: 'endpoint_count', width: 90, align: 'right' },
    {
      title: '内容哈希',
      dataIndex: 'content_hash',
      width: 140,
      render: (v: string) => (v ? <Typography.Text code>{v.slice(0, 10)}…</Typography.Text> : '-'),
    },
    {
      title: '导入时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 110,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => openDiff(record)}>
          查看差异
        </Button>
      ),
    },
  ]

  const diffColumns: ColumnsType<ApiSpecDiff> = [
    {
      title: '差异类型',
      dataIndex: 'diff_type',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={API_SPEC_DIFF_TYPE_META} />,
    },
    {
      title: '端点键',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
    {
      title: '差异明细',
      dataIndex: 'detail',
      ellipsis: true,
      render: (v: Record<string, unknown>) => {
        const s = JSON.stringify(v)
        if (!s) return '-'
        return (
          <Typography.Text code ellipsis={{ tooltip: s }} style={{ maxWidth: 360 }}>
            {s}
          </Typography.Text>
        )
      },
    },
  ]

  return (
    <Card
      title="规范对比"
      extra={
        canImport ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setImportOpen(true)}>
            导入规范
          </Button>
        ) : undefined
      }
    >
      <Typography.Paragraph type="secondary">
        导入 OpenAPI 规范后，系统自动与运行时发现的端点对比：规范缺失、运行时缺失与定义变更三类差异可用于发现影子接口。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Table<ApiImportSpec>
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

      <Modal
        title="导入规范"
        open={importOpen}
        onCancel={() => setImportOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={importMut.isPending}
        okText="导入"
        cancelText="取消"
        width={640}
        destroyOnHidden
      >
        <Form<ImportFormValues> form={form} layout="vertical" onFinish={handleImport}>
          <Form.Item name="file_name" label="文件名（可选）">
            <Input placeholder="如 openapi-payment.yaml" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="spec_json"
            label="规范内容（JSON）"
            rules={[{ required: true, message: '请输入规范内容' }]}
          >
            <Input.TextArea rows={10} style={{ fontFamily: 'monospace' }} placeholder='{"openapi":"3.0.0",...}' />
          </Form.Item>
        </Form>
      </Modal>

      <Drawer
        title={`规范差异：${diffSpec?.file_name ?? '-'}`}
        open={!!diffSpec}
        onClose={() => setDiffSpec(null)}
        width={760}
        destroyOnHidden
      >
        <QueryErrorAlert error={diffQuery.error} />
        <Table<ApiSpecDiff>
          rowKey="id"
          loading={diffQuery.isLoading}
          columns={diffColumns}
          dataSource={diffQuery.data?.items ?? []}
          scroll={{ x: 700 }}
          pagination={{
            current: diffPage,
            pageSize: diffPageSize,
            total: diffQuery.data?.total ?? 0,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => {
              setDiffPage(p)
              setDiffPageSize(ps)
            },
          }}
        />
      </Drawer>
    </Card>
  )
}
