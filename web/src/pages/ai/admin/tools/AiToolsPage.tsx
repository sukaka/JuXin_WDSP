import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Form,
  InputNumber,
  Modal,
  Space,
  Switch,
  Table,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../../../api/client'
import { aiAgentsToolsApi, patchAiTool } from '../../../../api/ai'
import type { AiTool } from '../../../../api/ai'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import StatusTag from '../../../../components/StatusTag'
import { useAuthStore } from '../../../../stores/auth'
import { AI_TOOL_RISK_META } from '../../../../utils/ai'
import { formatJson } from '../../../../utils/format'
import { hasPermission } from '../../../../utils/permission'
import { ENABLE_STATUS_META } from '../../../../utils/stage4'

interface ToolConfigFormValues {
  timeout_seconds: number
  max_results: number
}

/** Tool 管理：Schema 查看 + 超时/返回数配置 + 启停（ai.tools.read / ai.tools.manage） */
export default function AiToolsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'ai.tools.manage')

  const [schemaTarget, setSchemaTarget] = useState<AiTool | null>(null)
  const [configTarget, setConfigTarget] = useState<AiTool | null>(null)
  const [configForm] = Form.useForm<ToolConfigFormValues>()

  const toolsQuery = useQuery({ queryKey: ['ai-tools'], queryFn: aiAgentsToolsApi.listTools })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['ai-tools'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      patchAiTool(id, { enabled }),
    onSuccess: (_data, vars) => {
      message.success(vars.enabled ? '工具已启用' : '工具已停用')
      void invalidate()
    },
    onError,
  })

  const configMutation = useMutation({
    mutationFn: (values: ToolConfigFormValues) =>
      patchAiTool((configTarget as AiTool).id, {
        timeout_seconds: values.timeout_seconds,
        max_results: values.max_results,
      }),
    onSuccess: () => {
      message.success('工具配置已更新')
      setConfigTarget(null)
      void invalidate()
    },
    onError,
  })

  const openConfig = (record: AiTool) => {
    setConfigTarget(record)
    configForm.setFieldsValue({
      timeout_seconds: record.timeout_seconds,
      max_results: record.max_results,
    })
  }

  const columns: ColumnsType<AiTool> = [
    {
      title: '编码',
      dataIndex: 'code',
      width: 190,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    { title: '名称', dataIndex: 'name', width: 170, ellipsis: true },
    { title: '版本', dataIndex: 'version', width: 90 },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={AI_TOOL_RISK_META} />,
    },
    {
      title: '所需权限',
      dataIndex: 'required_permission',
      width: 190,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    { title: '超时(s)', dataIndex: 'timeout_seconds', width: 90, align: 'right' },
    { title: '最大返回数', dataIndex: 'max_results', width: 110, align: 'right' },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ENABLE_STATUS_META} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" onClick={() => setSchemaTarget(record)}>
            Schema
          </Button>
          {canManage && (
            <Button type="link" size="small" onClick={() => openConfig(record)}>
              配置
            </Button>
          )}
          <Switch
            checked={record.status === 'ENABLED'}
            disabled={!canManage}
            loading={toggleMutation.isPending && toggleMutation.variables?.id === record.id}
            onChange={(enabled) => toggleMutation.mutate({ id: record.id, enabled })}
          />
        </Space>
      ),
    },
  ]

  return (
    <Card title="工具管理">
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        <Alert
          type="info"
          showIcon
          message="阶段7 仅允许 READ_ONLY 与 DRAFT_ONLY 风险等级 Tool；停用后编排器立即跳过该 Tool。"
        />
        {toolsQuery.isError ? (
          <QueryErrorAlert error={toolsQuery.error} message="加载工具列表失败" />
        ) : (
          <Table<AiTool>
            rowKey="id"
            loading={toolsQuery.isLoading}
            columns={columns}
            dataSource={toolsQuery.data}
            scroll={{ x: 1250 }}
            pagination={false}
          />
        )}
      </Space>

      <Modal
        title={`工具结构定义：${schemaTarget?.name ?? ''}`}
        open={schemaTarget !== null}
        onCancel={() => setSchemaTarget(null)}
        footer={null}
        width={640}
      >
        <pre
          style={{
            background: '#f5f5f5',
            padding: 12,
            borderRadius: 6,
            maxHeight: 400,
            overflow: 'auto',
            fontSize: 12,
          }}
        >
          {formatJson(schemaTarget?.input_schema)}
        </pre>
      </Modal>

      <Modal
        title={`配置 Tool：${configTarget?.name ?? ''}`}
        open={configTarget !== null}
        onCancel={() => setConfigTarget(null)}
        onOk={() => configForm.submit()}
        confirmLoading={configMutation.isPending}
        destroyOnHidden
      >
        <Form<ToolConfigFormValues>
          form={configForm}
          layout="vertical"
          onFinish={(values) => configMutation.mutate(values)}
        >
          <Form.Item
            name="timeout_seconds"
            label="超时时间（秒）"
            rules={[{ required: true, message: '请输入超时时间' }]}
          >
            <InputNumber min={1} max={300} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="max_results"
            label="最大返回数"
            rules={[{ required: true, message: '请输入最大返回数' }]}
          >
            <InputNumber min={1} max={1000} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  )
}
