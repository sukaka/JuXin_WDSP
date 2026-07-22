import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../../../api/client'
import { aiModelsApi, patchAiProvider } from '../../../../api/ai'
import type {
  AiModel,
  AiModelBody,
  AiModelProvider,
  AiModelRoutes,
} from '../../../../api/ai'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import StatusTag from '../../../../components/StatusTag'
import { useAuthStore } from '../../../../stores/auth'
import { AI_PROVIDER_TYPE_META } from '../../../../utils/ai'
import { hasPermission } from '../../../../utils/permission'
import { ENABLE_STATUS_META } from '../../../../utils/stage4'

interface ProviderFormValues {
  name: string
  provider_type: string
  base_url: string
  api_key?: string
  status?: string
}

interface ModelFormValues {
  provider_id: string
  model_code: string
  display_name?: string
  context_window?: number | null
  max_output_tokens?: number | null
  supports_tools?: boolean
  supports_streaming?: boolean
  priority?: number | null
  timeout_seconds?: number | null
  cost_input_unit?: number | null
  cost_output_unit?: number | null
}

const PROVIDER_TYPE_OPTIONS = Object.entries(AI_PROVIDER_TYPE_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

/** 模型管理：路由档位 + 模型供应商 + 模型（ai.models.read / ai.models.manage） */
export default function AiModelsPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'ai.models.manage')

  /* ---------- 查询 ---------- */
  const routesQuery = useQuery({ queryKey: ['ai-model-routes'], queryFn: aiModelsApi.getRoutes })
  const providersQuery = useQuery({
    queryKey: ['ai-model-providers'],
    queryFn: aiModelsApi.listProviders,
  })
  const modelsQuery = useQuery({ queryKey: ['ai-models'], queryFn: aiModelsApi.listModels })

  /* ---------- 路由档位（受控，getRoutes 成功后同步） ---------- */
  const [routes, setRoutes] = useState<AiModelRoutes>({ simple: '', standard: '', high: '' })
  useEffect(() => {
    if (routesQuery.data) setRoutes(routesQuery.data)
  }, [routesQuery.data])

  /* ---------- 供应商弹窗状态 ---------- */
  const [providerOpen, setProviderOpen] = useState(false)
  const [editingProvider, setEditingProvider] = useState<AiModelProvider | null>(null)
  const [providerForm] = Form.useForm<ProviderFormValues>()
  const [rotateTarget, setRotateTarget] = useState<AiModelProvider | null>(null)
  const [rotateForm] = Form.useForm<{ api_key: string }>()

  /* ---------- 模型弹窗状态 ---------- */
  const [modelOpen, setModelOpen] = useState(false)
  const [editingModel, setEditingModel] = useState<AiModel | null>(null)
  const [modelForm] = Form.useForm<ModelFormValues>()

  const invalidateProviders = () =>
    queryClient.invalidateQueries({ queryKey: ['ai-model-providers'] })
  const invalidateModels = () => queryClient.invalidateQueries({ queryKey: ['ai-models'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  /* ---------- 路由档位保存 ---------- */
  const saveRoutesMutation = useMutation({
    mutationFn: (body: Partial<AiModelRoutes>) => aiModelsApi.putRoutes(body),
    onSuccess: (data) => {
      message.success(data.message || '路由档位已保存')
      void queryClient.invalidateQueries({ queryKey: ['ai-model-routes'] })
    },
    onError,
  })

  const saveRoutes = () => {
    const body: Partial<AiModelRoutes> = {}
    if (routes.simple) body.simple = routes.simple
    if (routes.standard) body.standard = routes.standard
    if (routes.high) body.high = routes.high
    saveRoutesMutation.mutate(body)
  }

  /* ---------- 供应商写操作 ---------- */
  const saveProviderMutation = useMutation({
    mutationFn: async (values: ProviderFormValues) => {
      if (editingProvider) {
        await patchAiProvider(editingProvider.id, {
          name: values.name,
          provider_type: values.provider_type,
          base_url: values.base_url,
          status: values.status,
        })
      } else {
        await aiModelsApi.createProvider({
          name: values.name,
          provider_type: values.provider_type,
          base_url: values.base_url,
          api_key: values.api_key || undefined,
          status: values.status || 'ENABLED',
        })
      }
    },
    onSuccess: () => {
      message.success(editingProvider ? '供应商已更新' : '供应商已创建')
      setProviderOpen(false)
      setEditingProvider(null)
      providerForm.resetFields()
      void invalidateProviders()
      void invalidateModels()
    },
    onError,
  })

  const deleteProviderMutation = useMutation({
    mutationFn: (id: string) => aiModelsApi.deleteProvider(id),
    onSuccess: (data) => {
      message.success(data.message || '供应商已删除')
      void invalidateProviders()
    },
    onError,
  })

  const rotateMutation = useMutation({
    mutationFn: (apiKey: string) =>
      aiModelsApi.rotateKey((rotateTarget as AiModelProvider).id, apiKey),
    onSuccess: (data) => {
      message.success(data.message || '密钥已轮换')
      setRotateTarget(null)
      rotateForm.resetFields()
      void invalidateProviders()
    },
    onError,
  })

  /* ---------- 模型写操作 ---------- */
  const saveModelMutation = useMutation({
    mutationFn: (values: ModelFormValues) => {
      const body: AiModelBody = {
        provider_id: editingModel ? editingModel.provider_id : values.provider_id,
        model_code: editingModel ? editingModel.model_code : values.model_code,
        display_name: values.display_name || undefined,
        context_window: values.context_window ?? undefined,
        max_output_tokens: values.max_output_tokens ?? undefined,
        supports_tools: values.supports_tools ?? false,
        supports_streaming: values.supports_streaming ?? false,
        priority: values.priority ?? undefined,
        timeout_seconds: values.timeout_seconds ?? undefined,
        cost_input_unit: values.cost_input_unit ?? undefined,
        cost_output_unit: values.cost_output_unit ?? undefined,
      }
      return editingModel
        ? aiModelsApi.updateModel(editingModel.id, body)
        : aiModelsApi.createModel(body)
    },
    onSuccess: () => {
      message.success(editingModel ? '模型已更新' : '模型已创建')
      setModelOpen(false)
      setEditingModel(null)
      modelForm.resetFields()
      void invalidateModels()
    },
    onError,
  })

  const testMutation = useMutation({
    mutationFn: (id: string) => aiModelsApi.testModel(id),
    onSuccess: (data) => {
      if (data.ok) {
        message.success(data.message)
      } else {
        message.error(data.message)
      }
    },
    onError,
  })

  const toggleModelMutation = useMutation({
    mutationFn: ({ id, enable }: { id: string; enable: boolean }) =>
      enable ? aiModelsApi.enableModel(id) : aiModelsApi.disableModel(id),
    onSuccess: (data) => {
      message.success(data.message || '操作成功')
      void invalidateModels()
    },
    onError,
  })

  const deleteModelMutation = useMutation({
    mutationFn: (id: string) => aiModelsApi.deleteModel(id),
    onSuccess: (data) => {
      message.success(data.message || '模型已删除')
      void invalidateModels()
    },
    onError,
  })

  /* ---------- 弹窗打开 ---------- */
  const openCreateProvider = () => {
    setEditingProvider(null)
    providerForm.resetFields()
    setProviderOpen(true)
  }

  const openEditProvider = (record: AiModelProvider) => {
    setEditingProvider(record)
    providerForm.resetFields()
    providerForm.setFieldsValue({
      name: record.name,
      provider_type: record.provider_type,
      base_url: record.base_url,
      status: record.status,
    })
    setProviderOpen(true)
  }

  const confirmDeleteProvider = (record: AiModelProvider) => {
    const modelCount = (modelsQuery.data ?? []).filter((m) => m.provider_id === record.id).length
    if (modelCount > 0) {
      modal.warning({
        title: '无法删除供应商',
        content: `「${record.name}」下仍有 ${modelCount} 个模型，请先在下方「模型」列表删除全部关联模型后再删除供应商。`,
      })
      return
    }
    modal.confirm({
      title: '删除确认',
      content: `确定删除供应商「${record.name}」吗？密钥密文将一并清除，且不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteProviderMutation.mutateAsync(record.id),
    })
  }

  const openCreateModel = () => {
    setEditingModel(null)
    modelForm.resetFields()
    setModelOpen(true)
  }

  const openEditModel = (record: AiModel) => {
    setEditingModel(record)
    modelForm.resetFields()
    modelForm.setFieldsValue({
      provider_id: record.provider_id,
      model_code: record.model_code,
      display_name: record.display_name || undefined,
      context_window: record.context_window,
      max_output_tokens: record.max_output_tokens,
      supports_tools: record.supports_tools,
      supports_streaming: record.supports_streaming,
      priority: record.priority,
      timeout_seconds: record.timeout_seconds,
      cost_input_unit: record.cost_input_unit,
      cost_output_unit: record.cost_output_unit,
    })
    setModelOpen(true)
  }

  const confirmDeleteModel = (record: AiModel) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除模型「${record.display_name || record.model_code}」（${record.model_code}）吗？删除后引用该模型的路由档位将失效。`,
      okButtonProps: { danger: true },
      onOk: () => deleteModelMutation.mutate(record.id),
    })
  }

  /* ---------- 选项与映射 ---------- */
  const providerNameMap = new Map((providersQuery.data ?? []).map((p) => [p.id, p.name]))
  const providerOptions = (providersQuery.data ?? []).map((p) => ({ value: p.id, label: p.name }))
  const modelOptions = [...(modelsQuery.data ?? [])]
    .sort((a, b) => Number(b.status === 'ENABLED') - Number(a.status === 'ENABLED'))
    .map((m) => ({ value: m.model_code, label: `${m.display_name}（${m.model_code}）` }))

  /* ---------- 供应商表格 ---------- */
  const providerColumns: ColumnsType<AiModelProvider> = [
    { title: '名称', dataIndex: 'name', width: 160, ellipsis: true },
    {
      title: '类型',
      dataIndex: 'provider_type',
      width: 140,
      render: (v: string) => <StatusTag value={v} map={AI_PROVIDER_TYPE_META} />,
    },
    { title: '服务地址', dataIndex: 'base_url', ellipsis: true },
    {
      title: '密钥引用',
      dataIndex: 'api_key_reference',
      width: 200,
      ellipsis: true,
      render: (v: string) => v || '未配置',
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ENABLE_STATUS_META} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
      fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => openEditProvider(record)}>
              编辑
            </Button>
            <Button type="link" size="small" onClick={() => setRotateTarget(record)}>
              轮换密钥
            </Button>
            <Button type="link" size="small" danger onClick={() => confirmDeleteProvider(record)}>
              删除
            </Button>
          </Space>
        ) : (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            仅查看
          </Typography.Text>
        ),
    },
  ]

  /* ---------- 模型表格 ---------- */
  const modelColumns: ColumnsType<AiModel> = [
    {
      title: '显示名',
      dataIndex: 'display_name',
      width: 160,
      ellipsis: true,
      render: (v: string, record) => v || record.model_code,
    },
    {
      title: '模型编码',
      dataIndex: 'model_code',
      width: 180,
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '所属供应商',
      dataIndex: 'provider_id',
      width: 140,
      ellipsis: true,
      render: (v: string) => providerNameMap.get(v) ?? '-',
    },
    { title: '上下文窗口', dataIndex: 'context_window', width: 110, align: 'right' },
    { title: '最大输出', dataIndex: 'max_output_tokens', width: 100, align: 'right' },
    {
      title: '能力',
      key: 'capabilities',
      width: 130,
      render: (_, record) => (
        <Space size={4}>
          {record.supports_tools && <Tag color="blue">工具</Tag>}
          {record.supports_streaming && <Tag color="cyan">流式输出</Tag>}
          {!record.supports_tools && !record.supports_streaming && '-'}
        </Space>
      ),
    },
    { title: '优先级', dataIndex: 'priority', width: 80, align: 'right' },
    { title: '超时(s)', dataIndex: 'timeout_seconds', width: 90, align: 'right' },
    {
      title: '成本（输入/输出）',
      key: 'cost',
      width: 150,
      align: 'right',
      render: (_, record) => `${record.cost_input_unit} / ${record.cost_output_unit}`,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ENABLE_STATUS_META} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 260,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button
            type="link"
            size="small"
            loading={testMutation.isPending && testMutation.variables === record.id}
            onClick={() => testMutation.mutate(record.id)}
          >
            测试连接
          </Button>
          {canManage && (
            <>
              <Button type="link" size="small" onClick={() => openEditModel(record)}>
                编辑
              </Button>
              {record.status === 'ENABLED' ? (
                <Popconfirm
                  title="确定停用该模型吗？"
                  onConfirm={() => toggleModelMutation.mutate({ id: record.id, enable: false })}
                >
                  <Button type="link" size="small">
                    停用
                  </Button>
                </Popconfirm>
              ) : (
                <Button
                  type="link"
                  size="small"
                  onClick={() => toggleModelMutation.mutate({ id: record.id, enable: true })}
                >
                  启用
                </Button>
              )}
              <Button type="link" size="small" danger onClick={() => confirmDeleteModel(record)}>
                删除
              </Button>
            </>
          )}
        </Space>
      ),
    },
  ]

  const ROUTE_SELECTS: {
    key: keyof AiModelRoutes
    label: string
  }[] = [
    { key: 'simple', label: '简单任务（低成本）' },
    { key: 'standard', label: '标准分析' },
    { key: 'high', label: '复杂分析' },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      {!canManage && (
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          当前账号仅有模型查看权限。新增 / 编辑 / 删除供应商与模型、保存路由档位需系统管理员权限（
          <Typography.Text code>ai.models.manage</Typography.Text>
          ）。
        </Typography.Paragraph>
      )}
      <Card title="模型路由档位">
        {routesQuery.isError ? (
          <QueryErrorAlert error={routesQuery.error} message="加载路由档位失败" />
        ) : (
          <Space direction="vertical" size={12} style={{ display: 'flex' }}>
            {ROUTE_SELECTS.map((item) => (
              <Space key={item.key} wrap>
                <Typography.Text style={{ width: 160, display: 'inline-block' }}>
                  {item.label}
                </Typography.Text>
                <Select
                  style={{ width: 360 }}
                  placeholder="选择模型"
                  loading={modelsQuery.isLoading}
                  options={modelOptions}
                  value={routes[item.key] || undefined}
                  disabled={!canManage}
                  onChange={(v) => setRoutes((r) => ({ ...r, [item.key]: v }))}
                />
              </Space>
            ))}
            {canManage && (
              <Button
                type="primary"
                style={{ alignSelf: 'flex-start' }}
                loading={saveRoutesMutation.isPending}
                onClick={saveRoutes}
              >
                保存档位
              </Button>
            )}
          </Space>
        )}
      </Card>

      <Card
        title="模型供应商"
        extra={
          canManage && (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreateProvider}>
              新建供应商
            </Button>
          )
        }
      >
        {providersQuery.isError ? (
          <QueryErrorAlert error={providersQuery.error} message="加载模型供应商失败" />
        ) : (
          <Table<AiModelProvider>
            rowKey="id"
            loading={providersQuery.isLoading}
            columns={providerColumns}
            dataSource={providersQuery.data}
            scroll={{ x: 1000 }}
            pagination={false}
          />
        )}
      </Card>

      <Card
        title="模型"
        extra={
          canManage && (
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreateModel}>
              新建模型
            </Button>
          )
        }
      >
        {modelsQuery.isError ? (
          <QueryErrorAlert error={modelsQuery.error} message="加载模型列表失败" />
        ) : (
          <Table<AiModel>
            rowKey="id"
            loading={modelsQuery.isLoading}
            columns={modelColumns}
            dataSource={modelsQuery.data}
            scroll={{ x: 1450 }}
            pagination={false}
          />
        )}
      </Card>

      <Modal
        title={editingProvider ? '编辑供应商' : '新建供应商'}
        open={providerOpen}
        onCancel={() => {
          setProviderOpen(false)
          setEditingProvider(null)
        }}
        onOk={() => providerForm.submit()}
        confirmLoading={saveProviderMutation.isPending}
        destroyOnHidden
      >
        <Form<ProviderFormValues>
          form={providerForm}
          layout="vertical"
          initialValues={{ provider_type: 'openai_compatible', status: 'ENABLED' }}
          onFinish={(values) => saveProviderMutation.mutate(values)}
        >
          <Form.Item
            name="name"
            label="名称"
            rules={[
              { required: true, message: '请输入名称' },
              { max: 100, message: '不超过 100 个字符' },
            ]}
          >
            <Input placeholder="如：自建推理集群 / 公有云兼容端点" />
          </Form.Item>
          <Form.Item
            name="provider_type"
            label="类型"
            rules={[{ required: true, message: '请选择类型' }]}
            extra="开放兼容协议 / 本地推理服务 / 本地模型均走标准对话补全接口"
          >
            <Select options={PROVIDER_TYPE_OPTIONS} placeholder="选择供应商类型" />
          </Form.Item>
          <Form.Item
            name="base_url"
            label="服务地址"
            rules={[
              { required: true, message: '请输入服务地址' },
              { max: 255, message: '不超过 255 个字符' },
            ]}
            extra="填写服务根地址即可（不要带对话补全路径）。例如：http://ollama:11434 或公有云接口根地址"
          >
            <Input placeholder="http://host:port 或 https://api.example.com" autoComplete="off" />
          </Form.Item>
          {editingProvider ? (
            <Form.Item
              name="status"
              label="状态"
              rules={[{ required: true, message: '请选择状态' }]}
            >
              <Select
                options={[
                  { value: 'ENABLED', label: '启用' },
                  { value: 'DISABLED', label: '停用' },
                ]}
              />
            </Form.Item>
          ) : (
            <Form.Item name="api_key" label="接口密钥（可选）">
              <Input.Password
                placeholder="本地推理服务可留空；公有云必填，仅创建时写入且不回显"
                autoComplete="new-password"
              />
            </Form.Item>
          )}
        </Form>
      </Modal>

      <Modal
        title={`轮换密钥：${rotateTarget?.name ?? ''}`}
        open={rotateTarget !== null}
        onCancel={() => {
          setRotateTarget(null)
          rotateForm.resetFields()
        }}
        onOk={() => rotateForm.submit()}
        confirmLoading={rotateMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          旧密钥立即失效，请确认新密钥可用。
        </Typography.Paragraph>
        <Form<{ api_key: string }>
          form={rotateForm}
          layout="vertical"
          onFinish={(values) => rotateMutation.mutate(values.api_key)}
        >
          <Form.Item
            name="api_key"
            label="新密钥"
            rules={[{ required: true, message: '请输入新密钥' }]}
          >
            <Input.Password placeholder="输入新的 接口密钥" autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={editingModel ? '编辑模型' : '新建模型'}
        open={modelOpen}
        width={640}
        onCancel={() => {
          setModelOpen(false)
          setEditingModel(null)
        }}
        onOk={() => modelForm.submit()}
        confirmLoading={saveModelMutation.isPending}
        destroyOnHidden
      >
        <Form<ModelFormValues>
          form={modelForm}
          layout="vertical"
          initialValues={{
            supports_tools: false,
            supports_streaming: true,
            priority: 100,
            timeout_seconds: 60,
          }}
          onFinish={(values) => saveModelMutation.mutate(values)}
        >
          <Form.Item
            name="provider_id"
            label="所属供应商"
            rules={[{ required: true, message: '请选择供应商' }]}
          >
            <Select
              options={providerOptions}
              placeholder="选择供应商"
              loading={providersQuery.isLoading}
              disabled={editingModel !== null}
            />
          </Form.Item>
          <Form.Item
            name="model_code"
            label="模型编码"
            rules={[
              { required: true, message: '请输入模型编码' },
              { max: 100, message: '不超过 100 个字符' },
            ]}
          >
            <Input
              placeholder="如 qwen2.5:7b"
              autoComplete="off"
              disabled={editingModel !== null}
            />
          </Form.Item>
          <Form.Item name="display_name" label="显示名" rules={[{ max: 100 }]}>
            <Input placeholder="对外展示名称（可选）" />
          </Form.Item>
          <Form.Item name="context_window" label="上下文窗口（tokens）">
            <InputNumber min={1} style={{ width: '100%' }} placeholder="如 32768" />
          </Form.Item>
          <Form.Item name="max_output_tokens" label="最大输出（tokens）">
            <InputNumber min={1} style={{ width: '100%' }} placeholder="如 4096" />
          </Form.Item>
          <Space size={24}>
            <Form.Item name="supports_tools" label="支持工具" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="supports_streaming" label="支持流式" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Space>
          <Form.Item name="priority" label="优先级">
            <InputNumber min={0} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="timeout_seconds" label="超时时间（秒）">
            <InputNumber min={1} max={600} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="cost_input_unit" label="输入单价">
            <InputNumber min={0} step={0.000001} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="cost_output_unit" label="输出单价">
            <InputNumber min={0} step={0.000001} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}
