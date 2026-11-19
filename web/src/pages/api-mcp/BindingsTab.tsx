import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Typography,
} from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import { mcpApi, type McpBinding, type McpBindingInput, type McpBindingUpdateInput } from '../../api/mcp'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { MCP_BINDING_MODE_META } from '../../utils/mcp'
import { hasPermission } from '../../utils/permission'

interface CreateFormValues {
  application_id: string
  endpoint_path: string
  catalog_id: string
  mode: string
}

interface EditFormValues {
  catalog_id: string
  mode: string
}

/** 目录下拉（hook 封装——新建/编辑两处复用） */
function useCatalogOptions() {
  const catalogsQuery = useQuery({ queryKey: ['mcp-catalogs'], queryFn: () => mcpApi.listCatalogs() })
  return {
    loading: catalogsQuery.isLoading,
    options: (catalogsQuery.data?.items ?? []).map((c) => ({ value: c.id, label: `${c.name}（${c.status === 'ENABLED' ? '启用' : '停用'}）` })),
  }
}

/** 新建绑定对话框（同（应用,endpoint_path）恰一条——重复 409） */
function CreateBindingModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<CreateFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)
  const applicationsQuery = useQuery({
    queryKey: ['applications', 'mcp-binding-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const catalogs = useCatalogOptions()
  const watchedMode = Form.useWatch('mode', form)

  const createMut = useMutation({
    mutationFn: (body: McpBindingInput) => mcpApi.createBinding(body),
    onSuccess: () => {
      message.success('绑定已创建（随发布链热生效）')
      onSaved()
      onClose()
    },
    onError: (e: unknown) => setSubmitError(e instanceof ApiError ? e.message : '创建失败'),
  })

  return (
    <Modal
      title="新建 MCP 目录绑定"
      open
      onCancel={onClose}
      okText="创建绑定"
      confirmLoading={createMut.isPending}
      onOk={() => form.submit()}
    >
      {submitError ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message="创建失败" description={submitError} /> : null}
      <Form<CreateFormValues>
        form={form}
        layout="vertical"
        initialValues={{ mode: 'OBSERVE' }}
        onFinish={(values) => {
          setSubmitError(null)
          createMut.mutate({
            application_id: values.application_id,
            endpoint_path: values.endpoint_path.trim(),
            catalog_id: values.catalog_id,
            mode: values.mode,
          })
        }}
      >
        <Form.Item name="application_id" label="应用" rules={[{ required: true, message: '请选择应用' }]}>
          <Select
            showSearch
            optionFilterProp="label"
            placeholder="选择应用"
            loading={applicationsQuery.isLoading}
            options={(applicationsQuery.data?.items ?? []).map((app) => ({ value: app.id, label: `${app.name}（${app.code}）` }))}
          />
        </Form.Item>
        <Form.Item
          name="endpoint_path"
          label="MCP 端点精确路径"
          rules={[
            { required: true, whitespace: true, message: '端点路径必填' },
            { max: 1024, message: '不超过 1024 字符' },
            { pattern: /^\//, message: '须为 / 开头精确路径（大小写敏感）' },
          ]}
          extra="请求命中该路径且 POST+JSON 族才进入 MCP 工具调用评估（绑定驱动识别）"
        >
          <Input placeholder="如：/mcp" />
        </Form.Item>
        <Form.Item name="catalog_id" label="工具目录" rules={[{ required: true, message: '请选择工具目录' }]}>
          <Select showSearch optionFilterProp="label" placeholder="选择目录" loading={catalogs.loading} options={catalogs.options} />
        </Form.Item>
        <Form.Item name="mode" label="模式" rules={[{ required: true, message: '请选择模式' }]}>
          <Select options={Object.entries(MCP_BINDING_MODE_META).map(([value, meta]) => ({ value, label: meta.label }))} />
        </Form.Item>
        {watchedMode === 'PROTECT' ? (
          <Alert
            type="warning"
            showIcon
            message="实断模式协议化执行：违规调用将以 JSON-RPC 错误对象拒绝"
            description="发布校验提示：实断绑定端点未被 JWT 信任链覆盖时，管理面给出非阻断警示——无可信主体的请求不按目录访问控制定案（证据不足恒不阻断）。"
          />
        ) : null}
      </Form>
    </Modal>
  )
}

/** 编辑绑定对话框（仅 mode/目录可改——身份维度（应用/endpoint_path）不可改，改即删建；version 乐观锁） */
function EditBindingModal({
  binding,
  onClose,
  onSaved,
}: {
  binding: McpBinding
  onClose: () => void
  onSaved: () => void
}) {
  const [form] = Form.useForm<EditFormValues>()
  const [conflict, setConflict] = useState<string | null>(null)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const catalogs = useCatalogOptions()

  const updateMut = useMutation({
    mutationFn: (body: McpBindingUpdateInput) => mcpApi.updateBinding(binding.id, body),
    onSuccess: () => {
      setConflict(null)
      onSaved()
      onClose()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && e.status === 409) {
        setConflict('版本冲突，请刷新后重试')
        onSaved() // 触发列表刷新以取回最新 version
        return
      }
      setSubmitError(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  return (
    <Modal
      title={`编辑绑定：${binding.endpoint_path}`}
      open
      onCancel={onClose}
      okText="保存"
      confirmLoading={updateMut.isPending}
      onOk={() => form.submit()}
    >
      {conflict ? (
        <Alert type="warning" showIcon style={{ marginBottom: 12 }} message={conflict} description="绑定已被其他操作变更（乐观锁不匹配）；列表已刷新，请重新打开编辑。" />
      ) : null}
      {submitError ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message="保存失败" description={submitError} /> : null}
      <Typography.Paragraph type="secondary">
        当前乐观锁版本 v{binding.version}（随提交比对）；应用与端点路径为绑定身份维度，不可改（改即删建）。
      </Typography.Paragraph>
      <Form<EditFormValues>
        form={form}
        layout="vertical"
        initialValues={{ catalog_id: binding.catalog_id, mode: binding.mode }}
        onFinish={(values) => {
          setSubmitError(null)
          setConflict(null)
          updateMut.mutate({ catalog_id: values.catalog_id, mode: values.mode, version: binding.version })
        }}
      >
        <Form.Item name="catalog_id" label="工具目录" rules={[{ required: true, message: '请选择工具目录' }]}>
          <Select showSearch optionFilterProp="label" loading={catalogs.loading} options={catalogs.options} />
        </Form.Item>
        <Form.Item name="mode" label="模式" rules={[{ required: true, message: '请选择模式' }]}>
          <Select options={Object.entries(MCP_BINDING_MODE_META).map(([value, meta]) => ({ value, label: meta.label }))} />
        </Form.Item>
      </Form>
    </Modal>
  )
}

/**
 * MCP 绑定管理（NG-MCP G1 §1.14 端点 7~10）：应用×endpoint_path×目录×mode；
 * 绑定驱动识别——空绑定=网关 MCP 管控零行为；变更触发整站发布链热生效。
 */
export default function BindingsTab() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_spec.manage')
  const [applicationId, setApplicationId] = useState<string>()
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<McpBinding | null>(null)

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'mcp-binding-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const applicationNameMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const app of applicationsQuery.data?.items ?? []) map.set(app.id, `${app.name}（${app.code}）`)
    return map
  }, [applicationsQuery.data])

  const listQuery = useQuery({
    queryKey: ['mcp-bindings', applicationId],
    queryFn: () => mcpApi.listBindings({ application_id: applicationId || undefined }),
  })
  const invalidate = () => void qc.invalidateQueries({ queryKey: ['mcp-bindings'] })

  const deleteMut = useMutation({
    mutationFn: (id: string) => mcpApi.deleteBinding(id),
    onSuccess: () => {
      message.success('已解绑（该端点 MCP 工具调用评估零行为）')
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '解绑失败'),
  })

  const columns: ColumnsType<McpBinding> = [
    {
      title: '应用', dataIndex: 'application_id', width: 220, ellipsis: true,
      render: (v: string) => applicationNameMap.get(v) ?? <Typography.Text code>{v.slice(0, 8)}…</Typography.Text>,
    },
    { title: '端点路径', dataIndex: 'endpoint_path', width: 240, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: '工具目录', dataIndex: 'catalog_name', width: 200, ellipsis: true },
    { title: '模式', dataIndex: 'mode', width: 150, render: (v: string) => <StatusTag value={v || 'OBSERVE'} map={MCP_BINDING_MODE_META} /> },
    { title: '版本', dataIndex: 'version', width: 80, render: (v: number) => `v${v}` },
    { title: '更新时间', dataIndex: 'updated_at', width: 170, render: formatDateTime },
    {
      title: '操作', key: 'actions', width: 140, fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => setEditing(record)}>编辑</Button>
            <Popconfirm
              title={`解绑「${record.endpoint_path}」？`}
              description="解绑后该端点 MCP 工具调用评估零行为。"
              okText="确认解绑"
              okButtonProps={{ danger: true }}
              onConfirm={() => deleteMut.mutate(record.id)}
            >
              <Button type="link" size="small" danger>解绑</Button>
            </Popconfirm>
          </Space>
        ) : null,
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space style={{ display: 'flex', justifyContent: 'space-between' }} wrap>
        <Space wrap>
          <Select
            showSearch
            optionFilterProp="label"
            allowClear
            placeholder="全部应用"
            style={{ width: 260 }}
            value={applicationId}
            loading={applicationsQuery.isLoading}
            options={(applicationsQuery.data?.items ?? []).map((app) => ({ value: app.id, label: `${app.name}（${app.code}）` }))}
            onChange={(v) => setApplicationId(v)}
          />
        </Space>
        {canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreating(true)}>
            新建绑定
          </Button>
        ) : null}
      </Space>
      <QueryErrorAlert error={listQuery.error} message="加载 MCP 绑定失败" />
      <SmartTable<McpBinding>
        storageKey="mcp-bindings"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1100 }}
        pagination={false}
        locale={{ emptyText: '暂无绑定——空绑定=网关 MCP 管控零行为' }}
      />
      {creating ? <CreateBindingModal onClose={() => setCreating(false)} onSaved={invalidate} /> : null}
      {editing ? <EditBindingModal binding={editing} onClose={() => setEditing(null)} onSaved={invalidate} /> : null}
    </Space>
  )
}
