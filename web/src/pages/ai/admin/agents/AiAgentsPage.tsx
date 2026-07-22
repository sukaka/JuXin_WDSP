import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Form,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../../../api/client'
import { aiAgentsToolsApi, patchAiAgent } from '../../../../api/ai'
import type { AiAgent } from '../../../../api/ai'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import StatusTag from '../../../../components/StatusTag'
import { useAuthStore } from '../../../../stores/auth'
import { hasPermission } from '../../../../utils/permission'
import { ENABLE_STATUS_META } from '../../../../utils/stage4'

/** Agent 管理：启停 + 允许 Tool 集配置（ai.agents.read / ai.agents.manage） */
export default function AiAgentsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'ai.agents.manage')

  const [configTarget, setConfigTarget] = useState<AiAgent | null>(null)
  const [configForm] = Form.useForm<{ allowed_tool_ids: string[] }>()

  const agentsQuery = useQuery({ queryKey: ['ai-agents'], queryFn: aiAgentsToolsApi.listAgents })
  const toolsQuery = useQuery({ queryKey: ['ai-tools'], queryFn: aiAgentsToolsApi.listTools })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['ai-agents'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      patchAiAgent(id, { enabled }),
    onSuccess: (_data, vars) => {
      message.success(vars.enabled ? 'Agent 已启用' : 'Agent 已停用')
      void invalidate()
    },
    onError,
  })

  const configMutation = useMutation({
    mutationFn: (values: { allowed_tool_ids: string[] }) =>
      patchAiAgent((configTarget as AiAgent).id, {
        allowed_tool_ids: values.allowed_tool_ids ?? [],
      }),
    onSuccess: () => {
      message.success('Agent 配置已更新')
      setConfigTarget(null)
      void invalidate()
    },
    onError,
  })

  const openConfig = (record: AiAgent) => {
    setConfigTarget(record)
    configForm.setFieldsValue({ allowed_tool_ids: record.allowed_tool_ids ?? [] })
  }

  const toolOptions = (toolsQuery.data ?? []).map((t) => ({
    value: t.code,
    label: `${t.name}（${t.code}）`,
  }))

  const columns: ColumnsType<AiAgent> = [
    {
      title: '编码',
      dataIndex: 'code',
      width: 170,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '名称',
      dataIndex: 'name',
      width: 210,
      render: (v: string, record) => (
        <Space size={4}>
          {v}
          {record.code === 'dispatcher' && <Tag color="blue">内置</Tag>}
        </Space>
      ),
    },
    {
      title: '描述',
      dataIndex: 'description',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ENABLE_STATUS_META} />,
    },
    {
      title: '注册标记',
      dataIndex: 'in_registry',
      width: 100,
      render: (v: boolean) => (v ? <Tag>已注册</Tag> : <Tag color="orange">未注册</Tag>),
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          {record.code === 'dispatcher' ? (
            <Tooltip title="总调度 Agent 为编排器内置能力，不可停用">
              <Switch checked={record.status === 'ENABLED'} disabled />
            </Tooltip>
          ) : (
            <Switch
              checked={record.status === 'ENABLED'}
              disabled={!canManage}
              loading={toggleMutation.isPending && toggleMutation.variables?.id === record.id}
              onChange={(enabled) => toggleMutation.mutate({ id: record.id, enabled })}
            />
          )}
          {canManage && (
            <Button type="link" size="small" onClick={() => openConfig(record)}>
              配置
            </Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Card title="Agent 管理">
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        <Alert
          type="info"
          showIcon
          message="Agent 启停实时生效；调度前编排器会二次校验 Agent 状态与 Tool 权限。"
        />
        {agentsQuery.isError ? (
          <QueryErrorAlert error={agentsQuery.error} message="加载 Agent 列表失败" />
        ) : (
          <Table<AiAgent>
            rowKey="id"
            loading={agentsQuery.isLoading}
            columns={columns}
            dataSource={agentsQuery.data}
            scroll={{ x: 1000 }}
            pagination={false}
          />
        )}
      </Space>

      <Modal
        title={`配置 Agent：${configTarget?.name ?? ''}`}
        open={configTarget !== null}
        onCancel={() => setConfigTarget(null)}
        onOk={() => configForm.submit()}
        confirmLoading={configMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          配置该 Agent 允许调用的 Tool 集，留空表示按 Agent 默认配置。
        </Typography.Paragraph>
        <Form<{ allowed_tool_ids: string[] }>
          form={configForm}
          layout="vertical"
          onFinish={(values) => configMutation.mutate(values)}
        >
          <Form.Item name="allowed_tool_ids" label="允许的 Tool">
            <Select
              mode="tags"
              options={toolOptions}
              loading={toolsQuery.isLoading}
              placeholder="选择 Tool，留空表示按默认配置"
            />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  )
}
