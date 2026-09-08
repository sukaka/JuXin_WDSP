import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Tag,
} from 'antd'
import SmartTable from '../../../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { aiMemoriesApi } from '../../../../api/ai'
import type { AiMemory, AiMemoryBody } from '../../../../api/ai'
import { ApiError } from '../../../../api/client'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../../../components/RecordDetailDrawer'
import StatusTag from '../../../../components/StatusTag'
import useBatchDelete from '../../../../hooks/useBatchDelete'
import { useAuthStore } from '../../../../stores/auth'
import { AI_MEMORY_CONFIDENCE_META, AI_MEMORY_SCOPE_META } from '../../../../utils/ai'
import { formatDateTime } from '../../../../utils/format'
import { hasPermission } from '../../../../utils/permission'

const SCOPE_OPTIONS = Object.entries(AI_MEMORY_SCOPE_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

const CONFIDENCE_OPTIONS = Object.entries(AI_MEMORY_CONFIDENCE_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

interface CreateFormValues {
  memory_scope: string
  scope_reference?: string
  content: string
  confidence_type: string
}

interface EditFormValues {
  content: string
}

/** Memory 管理：本人记忆列表 + 新建/编辑/停用/删除 */
export default function AiMemoriesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'ai.memories.manage_own')

  const [scope, setScope] = useState<string | undefined>(undefined)
  const [includeDisabled, setIncludeDisabled] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<AiMemory | null>(null)
  const [detailRecord, setDetailRecord] = useState<AiMemory | null>(null)
  const [createForm] = Form.useForm<CreateFormValues>()
  const [editForm] = Form.useForm<EditFormValues>()

  const listQuery = useQuery({
    queryKey: ['ai-memories', scope, includeDisabled],
    queryFn: () =>
      aiMemoriesApi.list({ scope, include_disabled: includeDisabled || undefined }),
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<AiMemory>({
    remove: (id) => aiMemoriesApi.remove(id),
    invalidateKeys: [['ai-memories']],
    entityName: '记忆',
    canDelete: canManage,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['ai-memories'] })
  // 后端 400（如敏感信息拦截）消息必须原样展示
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (values: CreateFormValues) => {
      const body: AiMemoryBody = {
        memory_scope: values.memory_scope,
        scope_reference: values.scope_reference || undefined,
        content: values.content,
        confidence_type: values.confidence_type,
      }
      return aiMemoriesApi.create(body)
    },
    onSuccess: () => {
      message.success('记忆已创建')
      setCreateOpen(false)
      createForm.resetFields()
      void invalidate()
    },
    onError,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, content }: { id: string; content: string }) =>
      aiMemoriesApi.update(id, content),
    onSuccess: () => {
      message.success('记忆已更新')
      setEditing(null)
      void invalidate()
    },
    onError,
  })

  const disableMutation = useMutation({
    mutationFn: (id: string) => aiMemoriesApi.disable(id),
    onSuccess: () => {
      message.success('记忆已停用')
      void invalidate()
    },
    onError,
  })

  const removeMutation = useMutation({
    mutationFn: (id: string) => aiMemoriesApi.remove(id),
    onSuccess: () => {
      message.success('记忆已删除')
      void invalidate()
    },
    onError,
  })

  const openEdit = (record: AiMemory) => {
    setEditing(record)
    editForm.setFieldsValue({ content: record.content })
  }

  const confirmDelete = (record: AiMemory) => {
    modal.confirm({
      title: '删除确认',
      content: '确定删除该记忆吗？删除后不可恢复。',
      okButtonProps: { danger: true },
      onOk: () => removeMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<AiMemory> = [
    {
      title: '作用域',
      dataIndex: 'memory_scope',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={AI_MEMORY_SCOPE_META} />,
    },
    {
      title: '内容',
      dataIndex: 'content',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '置信度',
      dataIndex: 'confidence_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={AI_MEMORY_CONFIDENCE_META} />,
    },
    {
      title: '来源',
      dataIndex: 'source_type',
      width: 110,
      render: (v: string) => v || '-',
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) =>
        v === 'ACTIVE' ? <Tag color="green">启用</Tag> : <Tag>已禁用</Tag>,
    },
    {
      title: '最近使用',
      dataIndex: 'last_used_at',
      width: 170,
      render: (v: string | null | undefined) => formatDateTime(v),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 160,
      fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => openEdit(record)}>
              编辑
            </Button>
            {record.status === 'ACTIVE' && (
              <Popconfirm
                title="确定停用该记忆吗？"
                onConfirm={() => disableMutation.mutate(record.id)}
              >
                <Button type="link" size="small">
                  停用
                </Button>
              </Popconfirm>
            )}
            <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
              删除
            </Button>
          </Space>
        ) : null,
    },
  ]

  return (
    <Card title="记忆管理">
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="记忆仅属主可见；含密码/密钥/私钥特征的内容将被后端拦截。"
      />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="作用域"
          allowClear
          style={{ width: 130 }}
          options={SCOPE_OPTIONS}
          onChange={(v) => setScope(v)}
        />
        <Checkbox
          checked={includeDisabled}
          onChange={(e) => setIncludeDisabled(e.target.checked)}
        >
          显示已禁用
        </Checkbox>
        {canManage && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建记忆
          </Button>
        )}
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载记忆列表失败" />
      ) : (
        <SmartTable<AiMemory>
          storageKey="ai-admin-memories"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data}
          scroll={{ x: 1150 }}
          pagination={false}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
        />
      )}

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="记忆详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />

      <Modal
        title="新建记忆"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => createForm.submit()}
        confirmLoading={createMutation.isPending}
        destroyOnHidden
      >
        <Form<CreateFormValues>
          form={createForm}
          layout="vertical"
          initialValues={{ confidence_type: 'USER_CONFIRMED' }}
          onFinish={(values) => createMutation.mutate(values)}
        >
          <Form.Item
            name="memory_scope"
            label="作用域"
            rules={[{ required: true, message: '请选择作用域' }]}
          >
            <Select options={SCOPE_OPTIONS} placeholder="请选择作用域" />
          </Form.Item>
          <Form.Item name="scope_reference" label="作用域引用">
            <Input placeholder="作用域引用，如会话或应用标识" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="content"
            label="内容"
            rules={[
              { required: true, message: '请输入记忆内容' },
              { max: 4000, message: '不超过 4000 个字符' },
            ]}
          >
            <Input.TextArea rows={6} placeholder="记忆内容" />
          </Form.Item>
          <Form.Item name="confidence_type" label="置信度">
            <Select options={CONFIDENCE_OPTIONS} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="编辑记忆"
        open={editing !== null}
        onCancel={() => setEditing(null)}
        onOk={() => editForm.submit()}
        confirmLoading={updateMutation.isPending}
        destroyOnHidden
      >
        <Form<EditFormValues>
          form={editForm}
          layout="vertical"
          onFinish={(values) =>
            editing && updateMutation.mutate({ id: editing.id, content: values.content })
          }
        >
          <Form.Item
            name="content"
            label="内容"
            rules={[
              { required: true, message: '请输入记忆内容' },
              { max: 4000, message: '不超过 4000 个字符' },
            ]}
          >
            <Input.TextArea rows={6} placeholder="记忆内容" />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  )
}
