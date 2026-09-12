import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Drawer, Form, Input, Modal, Select, Space, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import {
  apiSpecsApi,
  type ApiImportSpec,
  type ApiSpecChange,
  type ApiSpecDiff,
  type ApiSpecImportResult,
} from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_SPEC_DIFF_TYPE_META } from '../../utils/stage8'

interface ImportFormValues {
  file_name?: string
  spec_json: string
}

interface ImportUrlFormValues {
  url: string
  name?: string
  /** 可选认证头（单个键值对，如 Authorization: Bearer xxx；更多请走粘贴导入或后续扩展） */
  header_name?: string
  header_value?: string
}

/** 规范版本状态（与 apisecurity api_import_specs.status 枚举一致） */
const SPEC_STATUS_META: Record<string, { color: string; label: string }> = {
  DRAFT: { color: 'blue', label: '草稿' },
  ACTIVE: { color: 'green', label: '激活' },
  HISTORICAL: { color: 'default', label: '历史' },
  INVALID: { color: 'red', label: '无效' },
  ARCHIVED: { color: 'default', label: '归档' },
}

/** 跨版本 CHANGED 级变更类型（与 apisecurity.SpecChange.change_type 枚举一致） */
const SPEC_CHANGE_TYPE_META: Record<string, { color: string; label: string }> = {
  ENDPOINT_ADDED: { color: 'green', label: '新增 API' },
  ENDPOINT_REMOVED: { color: 'red', label: '移除 API' },
  PARAM_ADDED: { color: 'blue', label: '新增参数' },
  PARAM_REMOVED: { color: 'volcano', label: '移除参数' },
  TYPE_CHANGED: { color: 'gold', label: '类型变更' },
  REQUIRED_CHANGED: { color: 'orange', label: '必填变更' },
}

/** 导入成功提示（粘贴/URL 导入同构） */
function importSummary(r: ApiSpecImportResult): string {
  return `导入成功：${r.spec.name} v${r.spec.version_no}（接口 ${r.spec.endpoint_count} 个）；运行时缺失 ${r.missing_in_runtime}，规范缺失 ${r.missing_in_spec}，定义变更 ${r.changed}，登记 API ${r.registered_endpoints}`
}

/** 规范对比（WDSP / 阶段8）：导入 OpenAPI 规范并与运行时发现的接口对比差异；版本链激活与跨版本对比 */
export default function ApiSpecsPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canImport = hasPermission(permissions, 'api_spec.import')
  const canManage = hasPermission(permissions, 'api_spec.manage')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [importOpen, setImportOpen] = useState(false)
  const [importUrlOpen, setImportUrlOpen] = useState(false)
  const [diffSpec, setDiffSpec] = useState<ApiImportSpec | null>(null)
  const [diffPage, setDiffPage] = useState(1)
  const [diffPageSize, setDiffPageSize] = useState(20)
  /** 版本对比抽屉：vdSpec 为基准版本，vdOtherId 为对比目标版本 */
  const [vdSpec, setVdSpec] = useState<ApiImportSpec | null>(null)
  const [vdOtherId, setVdOtherId] = useState<string | undefined>()
  const [form] = Form.useForm<ImportFormValues>()
  const [urlForm] = Form.useForm<ImportUrlFormValues>()

  const listQuery = useQuery({
    queryKey: ['api-specs', page, pageSize],
    queryFn: () => apiSpecsApi.list({ page, page_size: pageSize }),
  })

  const diffQuery = useQuery({
    queryKey: ['api-specs', 'diff', diffSpec?.id, diffPage, diffPageSize],
    queryFn: () => apiSpecsApi.diff(diffSpec?.id as string, { page: diffPage, page_size: diffPageSize }),
    enabled: !!diffSpec,
  })

  /** 版本对比候选：同名版本链全部版本（排除基准自身） */
  const vdVersionsQuery = useQuery({
    queryKey: ['api-specs', 'versions', vdSpec?.name],
    queryFn: () => apiSpecsApi.list({ name: vdSpec?.name, page: 1, page_size: 100 }),
    enabled: !!vdSpec,
  })

  const versionDiffQuery = useQuery({
    queryKey: ['api-specs', 'version-diff', vdSpec?.id, vdOtherId],
    queryFn: () => apiSpecsApi.versionDiff(vdSpec?.id as string, vdOtherId as string),
    enabled: !!vdSpec && !!vdOtherId,
  })

  const importMut = useMutation({
    mutationFn: (body: { file_name?: string; spec: Record<string, unknown> }) => apiSpecsApi.import(body),
    onSuccess: (r) => {
      message.success(importSummary(r))
      setImportOpen(false)
      form.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-specs'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '导入失败'),
  })

  const importUrlMut = useMutation({
    mutationFn: (body: { url: string; name?: string; headers?: Record<string, string> }) => apiSpecsApi.importUrl(body),
    onSuccess: (r) => {
      message.success(importSummary(r))
      setImportUrlOpen(false)
      urlForm.resetFields()
      void qc.invalidateQueries({ queryKey: ['api-specs'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : 'URL 导入失败'),
  })

  const activateMut = useMutation({
    mutationFn: (id: string) => apiSpecsApi.activate(id),
    onSuccess: (r) => {
      message.success(`已激活 ${r.spec.name} v${r.spec.version_no}，同名旧版降为历史`)
      void qc.invalidateQueries({ queryKey: ['api-specs'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '激活失败'),
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

  const handleImportUrl = (v: ImportUrlFormValues) => {
    const headerName = v.header_name?.trim()
    const headerValue = v.header_value?.trim()
    if (headerName && !headerValue) {
      message.error('认证头名称已填写时，认证头值不能为空')
      return
    }
    importUrlMut.mutate({
      url: v.url.trim(),
      name: v.name?.trim() || undefined,
      headers: headerName && headerValue ? { [headerName]: headerValue } : undefined,
    })
  }

  const openDiff = (record: ApiImportSpec) => {
    setDiffSpec(record)
    setDiffPage(1)
  }

  const openVersionDiff = (record: ApiImportSpec) => {
    setVdSpec(record)
    setVdOtherId(undefined)
  }

  const confirmActivate = (record: ApiImportSpec) => {
    modal.confirm({
      title: '激活规范版本',
      content: `确定激活「${record.name} v${record.version_no}」吗？同名当前 ACTIVE 版本将降为历史。`,
      onOk: () => activateMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiImportSpec> = [
    {
      title: '规范',
      dataIndex: 'name',
      ellipsis: true,
      render: (v: string, record) =>
        v ? (
          <Space size={4}>
            <Typography.Text strong>{v}</Typography.Text>
            <Tag>v{record.version_no}</Tag>
          </Space>
        ) : (
          '-'
        ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={SPEC_STATUS_META} />,
    },
    {
      title: '文件名',
      dataIndex: 'file_name',
      ellipsis: true,
      render: (v?: string | null) => v || '-',
    },
    { title: '格式', dataIndex: 'format', width: 110, render: (v: string) => v || '-' },
    { title: '接口数', dataIndex: 'endpoint_count', width: 90 },
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
      width: 240,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => openDiff(record)}>
            查看差异
          </Button>
          <Button type="link" size="small" onClick={() => openVersionDiff(record)}>
            版本对比
          </Button>
          {canManage && record.status && record.status !== 'ACTIVE' ? (
            <Button type="link" size="small" onClick={() => confirmActivate(record)}>
              激活
            </Button>
          ) : null}
        </Space>
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
      title: '接口键',
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

  const changeColumns: ColumnsType<ApiSpecChange> = [
    {
      title: '接口键',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
    {
      title: '变更类型',
      dataIndex: 'change_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={SPEC_CHANGE_TYPE_META} />,
    },
    {
      title: '参数',
      key: 'param',
      width: 180,
      ellipsis: true,
      render: (_, record) =>
        record.param_name ? (
          <Typography.Text code>
            {record.param_in ? `${record.param_in}.` : ''}
            {record.param_name}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '变更',
      key: 'change',
      width: 180,
      ellipsis: true,
      render: (_, record) =>
        record.before || record.after ? (
          <Typography.Text code>
            {record.before || '∅'} → {record.after || '∅'}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
  ]

  const versionDiffData = versionDiffQuery.data

  return (
    <Card
      title="规范对比"
      extra={
        canImport ? (
          <Space>
            <Button icon={<PlusOutlined />} onClick={() => setImportUrlOpen(true)}>
              URL 导入
            </Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setImportOpen(true)}>
              导入规范
            </Button>
          </Space>
        ) : undefined
      }
    >
      <Typography.Paragraph type="secondary">
        导入 OpenAPI 规范后，系统自动与运行时发现的接口对比：规范缺失、运行时缺失与定义变更三类差异可用于发现影子
        API。同名再导入形成版本链（version_no 自增），同名唯一 ACTIVE 版本，可跨版本对比定义变更。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <SmartTable<ApiImportSpec>
        storageKey="api-specs"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1200 }}
        onRow={(record) => ({
          onDoubleClick: () => openDiff(record),
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

      <Modal
        title="从 URL 导入规范"
        open={importUrlOpen}
        onCancel={() => setImportUrlOpen(false)}
        onOk={() => urlForm.submit()}
        confirmLoading={importUrlMut.isPending}
        okText="导入"
        cancelText="取消"
        width={560}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          服务端拉取 URL 处的 OpenAPI 3 / Swagger 2.0 JSON 文档（仅 http/https，拒绝内网/保留地址，上限 16MiB）。
        </Typography.Paragraph>
        <Form<ImportUrlFormValues> form={urlForm} layout="vertical" onFinish={handleImportUrl}>
          <Form.Item
            name="url"
            label="规范文档 URL"
            rules={[
              { required: true, message: '请输入规范文档 URL' },
              { max: 2048, message: 'URL 不超过 2048 字符' },
            ]}
          >
            <Input placeholder="https://example.com/openapi.json" autoComplete="off" />
          </Form.Item>
          <Form.Item name="name" label="规范名称（可选，缺省取 info.title / 文件名）">
            <Input placeholder="如 payment-api" autoComplete="off" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="header_name" label="认证头名称（可选）" style={{ width: '40%', marginRight: 8 }}>
              <Input placeholder="Authorization" autoComplete="off" />
            </Form.Item>
            <Form.Item name="header_value" label="认证头值" style={{ width: '60%' }}>
              <Input.Password placeholder="Bearer xxx" autoComplete="new-password" />
            </Form.Item>
          </Space.Compact>
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
        <SmartTable<ApiSpecDiff>
          storageKey="api-specs-diff"
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

      <Drawer
        title={`版本对比：${vdSpec?.name ?? '-'}`}
        open={!!vdSpec}
        onClose={() => setVdSpec(null)}
        width={820}
        destroyOnHidden
      >
        <Space style={{ marginBottom: 16 }} wrap align="center">
          <Tag>基准 v{vdSpec?.version_no}</Tag>
          <Typography.Text type="secondary">对比目标</Typography.Text>
          <Select
            placeholder="选择同链另一版本"
            style={{ width: 280 }}
            loading={vdVersionsQuery.isLoading}
            value={vdOtherId}
            options={(vdVersionsQuery.data?.items ?? [])
              .filter((s) => s.id !== vdSpec?.id)
              .map((s) => ({
                value: s.id,
                label: `v${s.version_no}（${SPEC_STATUS_META[s.status]?.label ?? s.status}）`,
              }))}
            onChange={(v) => setVdOtherId(v)}
          />
        </Space>
        <QueryErrorAlert error={versionDiffQuery.error} />
        {versionDiffData ? (
          <Typography.Paragraph type="secondary">
            v{versionDiffData.base.version_no} → v{versionDiffData.target.version_no}，共 {versionDiffData.changes.length} 处定义变更
          </Typography.Paragraph>
        ) : null}
        <SmartTable<ApiSpecChange>
          storageKey="api-specs-version-diff"
          rowKey={(r) => `${r.endpoint_key}|${r.change_type}|${r.param_name ?? ''}`}
          loading={versionDiffQuery.isLoading || versionDiffQuery.isFetching}
          columns={changeColumns}
          dataSource={versionDiffData?.changes ?? []}
          scroll={{ x: 720 }}
          pagination={false}
        />
      </Drawer>
    </Card>
  )
}
