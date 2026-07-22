import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Drawer,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { aiPromptsApi } from '../../../../api/ai'
import type { AiPrompt, AiPromptVersion } from '../../../../api/ai'
import { ApiError } from '../../../../api/client'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import StatusTag from '../../../../components/StatusTag'
import { useAuthStore } from '../../../../stores/auth'
import { AI_PROMPT_TYPE_META } from '../../../../utils/ai'
import { formatDateTime } from '../../../../utils/format'
import { hasPermission } from '../../../../utils/permission'

const PROMPT_TYPE_OPTIONS = Object.entries(AI_PROMPT_TYPE_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

interface CreateFormValues {
  code: string
  name: string
  prompt_type: string
  content: string
  change_summary?: string
}

interface VersionFormValues {
  content: string
  change_summary?: string
}

/** 提示词版本管理抽屉：版本列表 + 查看/测试/发布/回滚 + 新建版本 */
function VersionsDrawer({ prompt, onClose }: { prompt: AiPrompt; onClose: () => void }) {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canCreate = hasPermission(permissions, 'ai.prompts.create')
  const canTest = hasPermission(permissions, 'ai.prompts.test')
  const canPublish = hasPermission(permissions, 'ai.prompts.publish')
  const canRollback = hasPermission(permissions, 'ai.prompts.rollback')

  const [createOpen, setCreateOpen] = useState(false)
  const [viewing, setViewing] = useState<AiPromptVersion | null>(null)
  const [form] = Form.useForm<VersionFormValues>()

  const versionsQuery = useQuery({
    queryKey: ['ai-prompt-versions', prompt.id],
    queryFn: () => aiPromptsApi.listVersions(prompt.id),
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['ai-prompt-versions', prompt.id] })
    void queryClient.invalidateQueries({ queryKey: ['ai-prompts'] })
  }
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const testMutation = useMutation({
    mutationFn: (versionId: string) => aiPromptsApi.testVersion(versionId),
    onSuccess: (data) => {
      modal.info({
        title: data.test_result === 'PASSED' ? '静态测试通过' : '静态测试未通过',
        content: (
          <div>
            {(data.checks ?? []).map((c) => (
              <div key={c.name}>
                <Typography.Text type={c.passed ? 'success' : 'danger'}>
                  {c.passed ? '✓' : '✗'}
                </Typography.Text>{' '}
                {c.name}
                {c.message ? `：${c.message}` : ''}
              </div>
            ))}
          </div>
        ),
      })
      invalidate()
    },
    onError,
  })

  const publishMutation = useMutation({
    mutationFn: (versionId: string) => aiPromptsApi.publish(prompt.id, versionId),
    onSuccess: () => {
      message.success('版本已发布')
      invalidate()
    },
    onError,
  })

  const rollbackMutation = useMutation({
    mutationFn: (versionId: string) => aiPromptsApi.rollback(prompt.id, versionId),
    onSuccess: () => {
      message.success('已回滚到指定版本')
      invalidate()
    },
    onError,
  })

  const createVersionMutation = useMutation({
    mutationFn: (values: VersionFormValues) =>
      aiPromptsApi.createVersion(prompt.id, {
        content: values.content,
        change_summary: values.change_summary || undefined,
      }),
    onSuccess: () => {
      message.success('新版本已创建')
      setCreateOpen(false)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  const confirmPublish = (record: AiPromptVersion) => {
    modal.confirm({
      title: '发布确认',
      content: `确定将 v${record.version_number} 发布为「${prompt.name}」的当前版本吗？`,
      onOk: () => publishMutation.mutate(record.id),
    })
  }

  const confirmRollback = (record: AiPromptVersion) => {
    modal.confirm({
      title: '回滚确认',
      content: `确定将「${prompt.name}」回滚到 v${record.version_number} 吗？回滚后该版本将成为当前版本。`,
      onOk: () => rollbackMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<AiPromptVersion> = [
    {
      title: '版本号',
      key: 'version_number',
      width: 80,
      render: (_, record) => `v${record.version_number}`,
    },
    {
      title: '状态',
      key: 'status',
      width: 90,
      render: (_, record) =>
        record.is_current ? (
          <Tag color="green">当前</Tag>
        ) : record.published_at ? (
          <Tag>已发布</Tag>
        ) : (
          '-'
        ),
    },
    {
      title: '测试结果',
      dataIndex: 'test_result',
      width: 100,
      render: (v: string) =>
        v === 'PASSED' ? (
          <Tag color="green">测试通过</Tag>
        ) : v === 'FAILED' ? (
          <Tag color="red">测试失败</Tag>
        ) : (
          <Tag>未测试</Tag>
        ),
    },
    {
      title: '变更摘要',
      dataIndex: 'change_summary',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setViewing(record)}>
            查看
          </Button>
          {canTest && (
            <Button
              type="link"
              size="small"
              loading={testMutation.isPending && testMutation.variables === record.id}
              onClick={() => testMutation.mutate(record.id)}
            >
              测试
            </Button>
          )}
          {canPublish && (
            <Button
              type="link"
              size="small"
              disabled={!(record.test_result === 'PASSED' && !record.is_current)}
              onClick={() => confirmPublish(record)}
            >
              发布
            </Button>
          )}
          {canRollback && (
            <Button
              type="link"
              size="small"
              disabled={!(record.published_at && !record.is_current)}
              onClick={() => confirmRollback(record)}
            >
              回滚
            </Button>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Drawer
      title={`版本管理 - ${prompt.name}`}
      open
      onClose={onClose}
      width={720}
      destroyOnHidden
      extra={
        canCreate && (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              form.resetFields()
              setCreateOpen(true)
            }}
          >
            新建版本
          </Button>
        )
      }
    >
      <Space direction="vertical" size={12} style={{ display: 'flex' }}>
        <Typography.Text type="secondary">
          版本不可变；仅静态测试通过（PASSED）的版本可发布。
        </Typography.Text>
        {versionsQuery.isError ? (
          <QueryErrorAlert error={versionsQuery.error} message="加载版本列表失败" />
        ) : (
          <Table<AiPromptVersion>
            rowKey="id"
            size="small"
            loading={versionsQuery.isLoading}
            columns={columns}
            dataSource={versionsQuery.data}
            scroll={{ x: 860 }}
            pagination={false}
          />
        )}
      </Space>

      <Modal
        title="新建版本"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={createVersionMutation.isPending}
        destroyOnHidden
      >
        <Form<VersionFormValues>
          form={form}
          layout="vertical"
          onFinish={(values) => createVersionMutation.mutate(values)}
        >
          <Form.Item
            name="content"
            label="版本内容"
            rules={[{ required: true, message: '请输入提示词内容' }]}
          >
            <Input.TextArea rows={8} placeholder="提示词内容" />
          </Form.Item>
          <Form.Item
            name="change_summary"
            label="变更摘要"
            rules={[{ max: 200, message: '不超过 200 个字符' }]}
          >
            <Input placeholder="可选" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={viewing ? `查看版本 v${viewing.version_number}` : '查看版本'}
        open={viewing !== null}
        onCancel={() => setViewing(null)}
        footer={null}
        width={720}
      >
        <pre
          style={{
            background: '#f5f5f5',
            padding: 12,
            borderRadius: 6,
            maxHeight: 400,
            overflow: 'auto',
            fontSize: 12,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}
        >
          {viewing?.content}
        </pre>
      </Modal>
    </Drawer>
  )
}

/** Prompt 管理：Prompt 列表 + 新建 + 版本管理抽屉 */
export default function AiPromptsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canCreate = hasPermission(permissions, 'ai.prompts.create')

  const [promptType, setPromptType] = useState<string | undefined>(undefined)
  const [createOpen, setCreateOpen] = useState(false)
  const [versionsPrompt, setVersionsPrompt] = useState<AiPrompt | null>(null)
  const [form] = Form.useForm<CreateFormValues>()

  const listQuery = useQuery({
    queryKey: ['ai-prompts', promptType],
    queryFn: () => aiPromptsApi.list({ prompt_type: promptType }),
  })

  const createMutation = useMutation({
    mutationFn: (values: CreateFormValues) =>
      aiPromptsApi.create({
        code: values.code,
        name: values.name,
        prompt_type: values.prompt_type,
        content: values.content,
        change_summary: values.change_summary || undefined,
      }),
    onSuccess: () => {
      message.success('提示词已创建')
      setCreateOpen(false)
      form.resetFields()
      void queryClient.invalidateQueries({ queryKey: ['ai-prompts'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '操作失败')
    },
  })

  const columns: ColumnsType<AiPrompt> = [
    {
      title: '编码',
      dataIndex: 'code',
      width: 180,
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    { title: '名称', dataIndex: 'name', width: 200, ellipsis: true },
    {
      title: '类型',
      dataIndex: 'prompt_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={AI_PROMPT_TYPE_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => v || '-',
    },
    {
      title: '当前版本',
      dataIndex: 'current_version_id',
      width: 100,
      render: (v: string | null | undefined) =>
        v ? <Tag color="green">已发布</Tag> : <Tag>未发布</Tag>,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setVersionsPrompt(record)}>
          版本
        </Button>
      ),
    },
  ]

  return (
    <Card title="提示词管理">
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="提示词类型"
          allowClear
          style={{ width: 160 }}
          options={PROMPT_TYPE_OPTIONS}
          onChange={(v) => setPromptType(v)}
        />
        {canCreate && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建提示词
          </Button>
        )}
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载提示词列表失败" />
      ) : (
        <Table<AiPrompt>
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data}
          scroll={{ x: 1050 }}
          pagination={false}
        />
      )}

      <Modal
        title="新建提示词"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={createMutation.isPending}
        destroyOnHidden
        width={640}
      >
        <Form<CreateFormValues>
          form={form}
          layout="vertical"
          onFinish={(values) => createMutation.mutate(values)}
        >
          <Form.Item
            name="code"
            label="编码"
            rules={[
              { required: true, message: '请输入编码' },
              { max: 50, message: '不超过 50 个字符' },
            ]}
          >
            <Input placeholder="如 dispatcher.system" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="name"
            label="名称"
            rules={[
              { required: true, message: '请输入名称' },
              { max: 100, message: '不超过 100 个字符' },
            ]}
          >
            <Input placeholder="如 总调度系统提示词" />
          </Form.Item>
          <Form.Item
            name="prompt_type"
            label="类型"
            rules={[{ required: true, message: '请选择类型' }]}
          >
            <Select options={PROMPT_TYPE_OPTIONS} placeholder="请选择类型" />
          </Form.Item>
          <Form.Item
            name="content"
            label="初始版本内容"
            rules={[{ required: true, message: '请输入提示词内容' }]}
          >
            <Input.TextArea rows={8} placeholder="提示词内容" />
          </Form.Item>
          <Form.Item
            name="change_summary"
            label="变更摘要"
            rules={[{ max: 200, message: '不超过 200 个字符' }]}
          >
            <Input placeholder="可选" />
          </Form.Item>
        </Form>
      </Modal>

      {versionsPrompt && (
        <VersionsDrawer prompt={versionsPrompt} onClose={() => setVersionsPrompt(null)} />
      )}
    </Card>
  )
}
