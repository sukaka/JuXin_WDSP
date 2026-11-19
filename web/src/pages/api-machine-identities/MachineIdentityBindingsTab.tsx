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
  Radio,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { applicationsApi } from '../../api/applications'
import { ApiError } from '../../api/client'
import {
  machineIdentityApi,
  type MachineIdentityBinding,
  type MachineIdentityBindingInput,
} from '../../api/machineIdentity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { MACHINE_IDENTITY_MODE_META, validateBindingPath } from '../../utils/machineIdentity'
import { hasPermission } from '../../utils/permission'

interface CreateFormValues {
  application_id: string
  path_kind: 'path_exact' | 'path_prefix'
  path: string
  mode: string
  proof_required: boolean
}

interface EditFormValues {
  mode: string
  proof_required: boolean
}

/** 新建绑定对话框（path_exact|path_prefix 二选一；同（应用,path）恰一条——重复 409） */
function CreateBindingModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [form] = Form.useForm<CreateFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)
  const applicationsQuery = useQuery({
    queryKey: ['applications', 'machine-identity-binding-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const watchedMode = Form.useWatch('mode', form)
  const watchedProof = Form.useWatch('proof_required', form)

  const createMut = useMutation({
    mutationFn: (body: MachineIdentityBindingInput) => machineIdentityApi.createBinding(body),
    onSuccess: () => {
      onSaved()
      onClose()
    },
    onError: (e: unknown) => setSubmitError(e instanceof ApiError ? e.message : '创建失败'),
  })

  return (
    <Modal
      title="新建机器身份绑定"
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
        initialValues={{ path_kind: 'path_exact', mode: 'OBSERVE', proof_required: false }}
        onFinish={(values) => {
          setSubmitError(null)
          createMut.mutate({
            application_id: values.application_id,
            path_exact: values.path_kind === 'path_exact' ? values.path.trim() : '',
            path_prefix: values.path_kind === 'path_prefix' ? values.path.trim() : '',
            mode: values.mode,
            proof_required: values.proof_required,
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
        <Space size={16} wrap style={{ display: 'flex' }}>
          <Form.Item name="path_kind" label="路径形态" rules={[{ required: true, message: '请选择路径形态' }]}>
            <Radio.Group>
              <Radio value="path_exact">精确路径</Radio>
              <Radio value="path_prefix">路径前缀</Radio>
            </Radio.Group>
          </Form.Item>
          <Form.Item
            name="path"
            label="路径"
            style={{ width: 320 }}
            rules={[
              { required: true, whitespace: true, message: '路径必填' },
              {
                validator: (_, v: string) => {
                  const err = validateBindingPath(form.getFieldValue('path_kind'), v ?? '')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
            extra="/ 开头、≤512 字符、不含查询串或锚点"
          >
            <Input placeholder="如：/api/v1/billing 或 /api/v1/billing/" />
          </Form.Item>
        </Space>
        <Space size={24} wrap>
          <Form.Item name="mode" label="模式" rules={[{ required: true, message: '请选择模式' }]}>
            <Select
              style={{ width: 180 }}
              options={Object.entries(MACHINE_IDENTITY_MODE_META).map(([value, meta]) => ({ value, label: meta.label }))}
            />
          </Form.Item>
          <Form.Item
            name="proof_required"
            label="强制签名"
            valuePropName="checked"
            extra="开启后，命中绑定路径且未签名的请求将被拒绝（401）"
          >
            <Switch />
          </Form.Item>
        </Space>
        {watchedMode === 'PROTECT' ? (
          <Alert
            type="warning"
            showIcon
            message="实断模式：验签失败与违规请求按协议执行（401 固定短语）"
            description="开启强制签名时，命中绑定路径且未签名的请求将直接拒绝 401（准入语义）；关闭时未签名按普通流量继续既有防护。机器身份验证通过不产生全局放行——授权/预算/WAF/API 防护照常。"
          />
        ) : null}
        {watchedMode !== 'PROTECT' && watchedProof ? (
          <Alert type="info" showIcon message="已开启强制签名：命中绑定路径且未签名的请求将拒绝 401。" />
        ) : null}
      </Form>
    </Modal>
  )
}

/** 编辑绑定对话框（仅 mode/proof_required 可改——身份维度不可改；version 乐观锁） */
function EditBindingModal({
  binding,
  onClose,
  onSaved,
}: {
  binding: MachineIdentityBinding
  onClose: () => void
  onSaved: () => void
}) {
  const [form] = Form.useForm<EditFormValues>()
  const [conflict, setConflict] = useState<string | null>(null)
  const [submitError, setSubmitError] = useState<string | null>(null)

  const updateMut = useMutation({
    mutationFn: (values: EditFormValues) =>
      machineIdentityApi.updateBinding(binding.id, { mode: values.mode, proof_required: values.proof_required, version: binding.version }),
    onSuccess: () => {
      setConflict(null)
      onSaved()
      onClose()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && e.status === 409) {
        setConflict('版本冲突，请刷新后重试')
        onSaved()
        return
      }
      setSubmitError(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  return (
    <Modal
      title={`编辑绑定：${binding.path_exact || binding.path_prefix}`}
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
        当前乐观锁版本 v{binding.version}（随提交比对）；应用与路径为绑定身份维度，不可改（改即删建）。
      </Typography.Paragraph>
      <Form<EditFormValues>
        form={form}
        layout="vertical"
        initialValues={{ mode: binding.mode, proof_required: binding.proof_required }}
        onFinish={(values) => { setSubmitError(null); setConflict(null); updateMut.mutate(values) }}
      >
        <Form.Item name="mode" label="模式" rules={[{ required: true, message: '请选择模式' }]}>
          <Select options={Object.entries(MACHINE_IDENTITY_MODE_META).map(([value, meta]) => ({ value, label: meta.label }))} />
        </Form.Item>
        <Form.Item name="proof_required" label="强制签名" valuePropName="checked" extra="开启后，命中绑定路径且未签名的请求将被拒绝（401）">
          <Switch />
        </Form.Item>
      </Form>
    </Modal>
  )
}

/**
 * 机器身份绑定管理（§1.12 端点 9~12）：应用×path selector×mode×proof_required；
 * 绑定驱动识别（请求命中绑定路径才进入签名评估；绑定不引用身份——登记册全局生效；空绑定=零行为）。
 */
export default function MachineIdentityBindingsTab() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'jwt_trust.manage')
  const [applicationId, setApplicationId] = useState<string>()
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<MachineIdentityBinding | null>(null)

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'machine-identity-binding-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const applicationNameMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const app of applicationsQuery.data?.items ?? []) map.set(app.id, `${app.name}（${app.code}）`)
    return map
  }, [applicationsQuery.data])

  const listQuery = useQuery({
    queryKey: ['machine-identity-bindings', applicationId],
    queryFn: () => machineIdentityApi.listBindings({ application_id: applicationId || undefined }),
  })
  const invalidate = () => void qc.invalidateQueries({ queryKey: ['machine-identity-bindings'] })

  const deleteMut = useMutation({
    mutationFn: (id: string) => machineIdentityApi.deleteBinding(id),
    onSuccess: () => {
      message.success('已解绑（该端点机器身份签名评估零行为）')
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '解绑失败'),
  })

  const columns: ColumnsType<MachineIdentityBinding> = [
    {
      title: '应用', dataIndex: 'application_id', width: 220, ellipsis: true,
      render: (v: string) => applicationNameMap.get(v) ?? <Typography.Text code>{v.slice(0, 8)}…</Typography.Text>,
    },
    {
      title: '路径', key: 'path', width: 300,
      render: (_, record) => (
        <Space size={4}>
          <Tag color={record.path_exact ? 'blue' : 'purple'}>{record.path_exact ? '精确' : '前缀'}</Tag>
          <Typography.Text code>{record.path_exact || record.path_prefix}</Typography.Text>
        </Space>
      ),
    },
    { title: '模式', dataIndex: 'mode', width: 150, render: (v: string) => <StatusTag value={v || 'OBSERVE'} map={MACHINE_IDENTITY_MODE_META} /> },
    {
      title: '强制签名', dataIndex: 'proof_required', width: 100,
      render: (v: boolean) => (v ? <Tag color="red">未签名 401</Tag> : <Typography.Text type="secondary">否</Typography.Text>),
    },
    { title: '版本', dataIndex: 'version', width: 70, render: (v: number) => `v${v}` },
    { title: '更新时间', dataIndex: 'updated_at', width: 170, render: formatDateTime },
    {
      title: '操作', key: 'actions', width: 140, fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => setEditing(record)}>编辑</Button>
            <Popconfirm
              title={`解绑「${record.path_exact || record.path_prefix}」？`}
              description="解绑后该端点机器身份签名评估零行为。"
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
        {canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreating(true)}>
            新建绑定
          </Button>
        ) : null}
      </Space>
      <QueryErrorAlert error={listQuery.error} message="加载机器身份绑定失败" />
      <SmartTable<MachineIdentityBinding>
        storageKey="machine-identity-bindings"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1150 }}
        pagination={false}
        locale={{ emptyText: '暂无绑定——空绑定=网关机器身份评估零行为' }}
      />
      {creating ? <CreateBindingModal onClose={() => setCreating(false)} onSaved={invalidate} /> : null}
      {editing ? <EditBindingModal binding={editing} onClose={() => setEditing(null)} onSaved={invalidate} /> : null}
    </Space>
  )
}
