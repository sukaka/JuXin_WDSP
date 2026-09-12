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
  Tag,
  Typography,
} from 'antd'
import SmartTable from '../../../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { aiPromptsApi } from '../../../../api/ai'
import type { AiPrompt, AiPromptAdversarialCase, AiPromptVersion } from '../../../../api/ai'
import { ApiError } from '../../../../api/client'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../../../components/RecordDetailDrawer'
import StatusTag from '../../../../components/StatusTag'
import useBatchDelete from '../../../../hooks/useBatchDelete'
import { useAuthStore } from '../../../../stores/auth'
import { AI_PROMPT_TYPE_META } from '../../../../utils/ai'
import { formatDateTime } from '../../../../utils/format'
import { hasPermission } from '../../../../utils/permission'

const PROMPT_TYPE_OPTIONS = Object.entries(AI_PROMPT_TYPE_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

/** 对抗测试结论三态（'' = 未执行） */
const ADVERSARIAL_RESULT_META: Record<string, { color: string; label: string }> = {
  ADVERSARIAL_PASSED: { color: 'green', label: '对抗通过' },
  ADVERSARIAL_FAILED: { color: 'red', label: '对抗失败' },
}

const ADVERSARIAL_CATEGORY_LABEL: Record<string, string> = {
  PROMPT_INJECTION: '提示注入',
  PRIVILEGE_ESCALATION: '越权诱导',
  DATA_EXFILTRATION: '数据泄露诱导',
}

/** 发布门两个门槛的状态标签（发布门错误文案中的取值：PASSED/ADVERSARIAL_* /FAILED/未执行） */
function gateStateTag(state: string) {
  if (state === 'PASSED' || state === 'ADVERSARIAL_PASSED') return <Tag color="green">{state}</Tag>
  if (state === '未执行') return <Tag>未执行</Tag>
  return <Tag color="red">{state || '未知'}</Tag>
}

/** 解析发布门结构化错误文案（服务端：…（当前：回归测试=X，对抗测试=Y）），未命中返回 null */
function parsePublishGateMessage(message: string): { testResult: string; adversarialResult: string } | null {
  const m = message.match(/回归测试=([^，）]+)，对抗测试=([^，）]+)/)
  if (!m) return null
  return { testResult: m[1], adversarialResult: m[2] }
}

/** 对抗测试逐样本判定列表（失败样本如实展示原因） */
function AdversarialCaseList({ cases }: { cases: AiPromptAdversarialCase[] }) {
  if (cases.length === 0) {
    return <Typography.Text type="secondary">暂无逐样本明细</Typography.Text>
  }
  return (
    <div>
      {cases.map((c) => (
        <div key={c.id} style={{ marginBottom: 10 }}>
          <Typography.Text type={c.passed ? 'success' : 'danger'}>
            {c.passed ? '✓' : '✗'}
          </Typography.Text>{' '}
          <Typography.Text code>{c.id}</Typography.Text>{' '}
          {ADVERSARIAL_CATEGORY_LABEL[c.category] ?? c.category}
          <div style={{ fontSize: 12, color: '#888' }}>对抗输入：{c.attack}</div>
          {c.reason ? (
            <Typography.Text type="danger" style={{ fontSize: 12 }}>
              原因：{c.reason}
            </Typography.Text>
          ) : null}
        </div>
      ))}
    </div>
  )
}

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

/** 提示词版本管理抽屉：版本列表 + 查看/测试/对抗测试/发布/回滚 + 新建版本 */
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
  const [adversarialDetail, setAdversarialDetail] = useState<AiPromptVersion | null>(null)
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

  const adversarialMutation = useMutation({
    mutationFn: (versionId: string) => aiPromptsApi.adversarialTestVersion(versionId),
    onSuccess: (data) => {
      modal.info({
        title:
          data.adversarial_result === 'ADVERSARIAL_PASSED' ? '对抗测试通过' : '对抗测试未通过',
        width: 640,
        content: <AdversarialCaseList cases={data.cases ?? []} />,
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
    onError: (e) => {
      // 发布门结构化错误：如实展示回归/对抗两个门槛的当前状态
      const gate = e instanceof ApiError ? parsePublishGateMessage(e.message) : null
      if (gate) {
        modal.warning({
          title: '发布门未通过',
          content: (
            <div>
              <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
                仅回归测试 PASSED 且对抗测试 ADVERSARIAL_PASSED 的版本可发布。
              </Typography.Paragraph>
              <Space direction="vertical" size={4}>
                <span>回归测试：{gateStateTag(gate.testResult)}</span>
                <span>对抗测试：{gateStateTag(gate.adversarialResult)}</span>
              </Space>
            </div>
          ),
        })
        return
      }
      onError(e)
    },
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
      title: '对抗测试',
      dataIndex: 'adversarial_result',
      width: 100,
      render: (v: string, record) => {
        if (v === 'ADVERSARIAL_FAILED') {
          // 失败可点击查看逐样本原因
          return (
            <Tag
              color="red"
              style={{ cursor: 'pointer' }}
              onClick={() => setAdversarialDetail(record)}
            >
              对抗失败
            </Tag>
          )
        }
        if (!v) return <Tag>未执行</Tag>
        return <StatusTag value={v} map={ADVERSARIAL_RESULT_META} />
      },
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
      width: 280,
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
          {canTest && (
            <Button
              type="link"
              size="small"
              loading={
                adversarialMutation.isPending && adversarialMutation.variables === record.id
              }
              onClick={() => adversarialMutation.mutate(record.id)}
            >
              对抗测试
            </Button>
          )}
          {canPublish && (
            <Button
              type="link"
              size="small"
              disabled={
                !(
                  record.test_result === 'PASSED' &&
                  record.adversarial_result === 'ADVERSARIAL_PASSED' &&
                  !record.is_current
                )
              }
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
      width={820}
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
          版本不可变；仅回归测试通过（PASSED）且对抗测试通过（ADVERSARIAL_PASSED）的版本可发布。
        </Typography.Text>
        {versionsQuery.isError ? (
          <QueryErrorAlert error={versionsQuery.error} message="加载版本列表失败" />
        ) : (
          <SmartTable<AiPromptVersion>
            storageKey="ai-admin-prompts"
            rowKey="id"
            size="small"
            loading={versionsQuery.isLoading}
            columns={columns}
            dataSource={versionsQuery.data}
            scroll={{ x: 980 }}
            pagination={false}
            onRow={(record) => ({
              onDoubleClick: () => setViewing(record),
              style: { cursor: 'pointer' },
            })}
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

      <Modal
        title={
          adversarialDetail ? `对抗测试明细 - v${adversarialDetail.version_number}` : '对抗测试明细'
        }
        open={adversarialDetail !== null}
        onCancel={() => setAdversarialDetail(null)}
        footer={null}
        width={640}
      >
        <AdversarialCaseList cases={adversarialDetail?.adversarial_detail ?? []} />
      </Modal>
    </Drawer>
  )
}

/** Prompt 管理：Prompt 列表 + 新建 + 编辑/删除 + 版本管理抽屉 */
export default function AiPromptsPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canCreate = hasPermission(permissions, 'ai.prompts.create')
  const canEdit = hasPermission(permissions, 'ai.prompts.edit')
  const canDelete = hasPermission(permissions, 'ai.prompts.delete')

  const [promptType, setPromptType] = useState<string | undefined>(undefined)
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<AiPrompt | null>(null)
  const [versionsPrompt, setVersionsPrompt] = useState<AiPrompt | null>(null)
  const [detailRecord, setDetailRecord] = useState<AiPrompt | null>(null)
  const [form] = Form.useForm<CreateFormValues>()
  const [editForm] = Form.useForm<{ name: string }>()

  const listQuery = useQuery({
    queryKey: ['ai-prompts', promptType],
    queryFn: () => aiPromptsApi.list({ prompt_type: promptType }),
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<AiPrompt>({
    remove: (id) => aiPromptsApi.remove(id),
    invalidateKeys: [['ai-prompts']],
    entityName: '提示词',
    canDelete,
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

  const renameMutation = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) => aiPromptsApi.rename(id, { name }),
    onSuccess: () => {
      message.success('名称已更新')
      setEditing(null)
      void queryClient.invalidateQueries({ queryKey: ['ai-prompts'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '重命名失败')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => aiPromptsApi.remove(id),
    onSuccess: () => {
      message.success('提示词已删除')
      void queryClient.invalidateQueries({ queryKey: ['ai-prompts'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '删除失败')
    },
  })

  const confirmDelete = (record: AiPrompt) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除提示词「${record.name}」（${record.code}）吗？其全部版本将一并删除，不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

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
      width: 190,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setVersionsPrompt(record)}>
            版本
          </Button>
          {canEdit && (
            <Button
              type="link"
              size="small"
              onClick={() => {
                setEditing(record)
                editForm.setFieldsValue({ name: record.name })
              }}
            >
              编辑
            </Button>
          )}
          {canDelete && record.status !== 'ACTIVE' && (
            <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
              删除
            </Button>
          )}
        </Space>
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
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载提示词列表失败" />
      ) : (
        <SmartTable<AiPrompt>
          storageKey="ai-admin-prompts-2"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data}
          scroll={{ x: 1050 }}
          pagination={false}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
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

      <Modal
        title={`编辑提示词 - ${editing?.code ?? ''}`}
        open={editing !== null}
        onCancel={() => setEditing(null)}
        onOk={() => editForm.submit()}
        confirmLoading={renameMutation.isPending}
        destroyOnHidden
      >
        <Form<{ name: string }>
          form={editForm}
          layout="vertical"
          onFinish={(v) => editing && renameMutation.mutate({ id: editing.id, name: v.name })}
        >
          <Form.Item
            name="name"
            label="名称"
            rules={[
              { required: true, message: '请输入名称' },
              { max: 100, message: '不超过 100 个字符' },
            ]}
          >
            <Input placeholder="提示词名称" />
          </Form.Item>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            编码与类型不可修改；内容修改请通过「版本」新建版本后发布。
          </Typography.Paragraph>
        </Form>
      </Modal>

      {versionsPrompt && (
        <VersionsDrawer prompt={versionsPrompt} onClose={() => setVersionsPrompt(null)} />
      )}

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="提示词详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
