import { useState } from 'react'
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
  Switch,
  Tag,
  Typography,
} from 'antd'
import { PlusOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import {
  machineIdentityApi,
  type MachineIdentity,
  type MachineIdentityInput,
  type MachineIdentitySummary,
} from '../../api/machineIdentity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { BOT_EXEMPT_NOTE, IDENTITY_STATUS_META } from '../../utils/machineIdentity'
import { hasPermission } from '../../utils/permission'
import IdentityDetailDrawer from './IdentityDetailDrawer'

interface IdentityFormValues {
  identity_name: string
  tenant_id?: string
  principal_binding?: string
  status: string
  bot_challenge_exempt: boolean
}

/** 身份新建/编辑对话框（PUT 乐观锁 version 随行；同名/版本冲突 409） */
function IdentityEditorModal({
  editing,
  onClose,
  onSaved,
}: {
  /** null=新建；否则为编辑对象（含 version） */
  editing: MachineIdentity | null
  onClose: () => void
  onSaved: () => void
}) {
  const [form] = Form.useForm<IdentityFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)

  const saveMut = useMutation({
    mutationFn: (body: MachineIdentityInput) =>
      editing ? machineIdentityApi.updateIdentity(editing.id, body) : machineIdentityApi.createIdentity(body),
    onSuccess: () => {
      onSaved()
      onClose()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && e.status === 409) {
        setSubmitError(e.message.includes('version') || e.message.includes('乐观锁') ? `版本冲突，请刷新后重试（${e.message}）` : e.message)
        return
      }
      setSubmitError(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  return (
    <Modal
      title={editing ? `编辑机器身份：${editing.identity_name}` : '登记机器身份'}
      open
      onCancel={onClose}
      okText={editing ? '保存' : '登记'}
      confirmLoading={saveMut.isPending}
      onOk={() => form.submit()}
      width={560}
    >
      {submitError ? (
        <Alert type="error" showIcon style={{ marginBottom: 12 }} message="保存失败" description={submitError} />
      ) : null}
      <Form<IdentityFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          identity_name: editing?.identity_name ?? '',
          tenant_id: editing?.tenant_id ?? '',
          principal_binding: editing?.principal_binding ?? '',
          status: editing?.status ?? 'ENABLED',
          bot_challenge_exempt: editing?.bot_challenge_exempt ?? false,
        }}
        onFinish={(values) => {
          setSubmitError(null)
          saveMut.mutate({
            identity_name: values.identity_name.trim(),
            tenant_id: values.tenant_id?.trim() ? values.tenant_id.trim() : null,
            principal_binding: values.principal_binding?.trim() ? values.principal_binding.trim() : null,
            status: values.status,
            bot_challenge_exempt: values.bot_challenge_exempt,
            ...(editing ? { version: editing.version } : {}),
          })
        }}
      >
        <Form.Item
          name="identity_name"
          label="身份名"
          rules={[{ required: true, whitespace: true, message: '身份名必填' }, { max: 128, message: '不超过 128 字符' }]}
          extra="全局唯一（同名 409）；签名 keyid 登记册按身份+kid 精确查找"
        >
          <Input placeholder="如：billing-agent" />
        </Form.Item>
        <Form.Item
          name="tenant_id"
          label="租户范围（可空）"
          rules={[{ max: 128, message: '不超过 128 字符' }]}
          extra="留空=跨租户共享身份（显式）"
        >
          <Input placeholder="留空 = 跨租户共享" allowClear />
        </Form.Item>
        <Form.Item
          name="principal_binding"
          label="绑定主体（可空）"
          rules={[{ max: 128, message: '不超过 128 字符' }]}
          extra="绑定 JWT VerifiedPrincipalID 指纹值——声明即强制一致"
        >
          <Input placeholder="留空 = 不绑定主体" allowClear />
        </Form.Item>
        <Space size={24} wrap>
          <Form.Item name="status" label="状态" rules={[{ required: true, message: '请选择状态' }]}>
            <Select
              style={{ width: 160 }}
              options={Object.entries(IDENTITY_STATUS_META).map(([value, meta]) => ({ value, label: `${meta.label}（${value}）` }))}
            />
          </Form.Item>
          <Form.Item name="bot_challenge_exempt" label="Bot 挑战豁免" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Space>
        <Alert type="info" showIcon message={BOT_EXEMPT_NOTE} />
      </Form>
    </Modal>
  )
}

/**
 * 机器身份列表（NG-ID G1 §1.12 管理面）：身份/键状态摘要（ACTIVE/RETIRED/REVOKED 计数）/
 * bot_challenge_exempt/撤销水位/启停状态；写操作（登记/编辑/删除）随发布链热生效。
 */
export default function IdentitiesTab() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'jwt_trust.manage')
  const [detailId, setDetailId] = useState<string | null>(null)
  /** undefined 关闭；null 新建；否则编辑对象 */
  const [editor, setEditor] = useState<MachineIdentity | null | undefined>(undefined)

  const listQuery = useQuery({
    queryKey: ['machine-identities'],
    queryFn: () => machineIdentityApi.listIdentities(),
  })
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['machine-identities'] })
    void qc.invalidateQueries({ queryKey: ['machine-identity'] })
  }

  const deleteMut = useMutation({
    mutationFn: (id: string) => machineIdentityApi.deleteIdentity(id),
    onSuccess: () => {
      message.success('身份已删除（键级联删除）')
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const columns: ColumnsType<MachineIdentitySummary> = [
    { title: '身份名', dataIndex: 'identity_name', width: 180, ellipsis: true, render: (v: string) => <Typography.Text strong>{v}</Typography.Text> },
    {
      title: '租户', dataIndex: 'tenant_id', width: 130,
      render: (v?: string | null) => (v ? <Typography.Text code>{v}</Typography.Text> : <Tag>跨租户共享</Tag>),
    },
    {
      title: '键状态摘要', key: 'keys', width: 240,
      render: (_, record) => (
        <Space size={4} wrap>
          <Tag>共 {record.key_count}</Tag>
          <Tag color="green">ACTIVE {record.active_keys}</Tag>
          <Tag color="gold">RETIRED {record.retired_keys}</Tag>
          <Tag color="red">REVOKED {record.revoked_keys}</Tag>
        </Space>
      ),
    },
    {
      title: 'Bot 豁免前提', dataIndex: 'bot_challenge_exempt', width: 110,
      render: (v: boolean) => (v ? <Tag color="orange">声明豁免</Tag> : <Typography.Text type="secondary">不豁免</Typography.Text>),
    },
    { title: '状态', dataIndex: 'status', width: 90, render: (v: string) => <StatusTag value={v} map={IDENTITY_STATUS_META} /> },
    { title: '版本', dataIndex: 'version', width: 70, render: (v: number) => `v${v}` },
    { title: '更新时间', dataIndex: 'updated_at', width: 170, render: formatDateTime },
    {
      title: '操作', key: 'actions', width: 190, fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>详情</Button>
          {canManage ? (
            <>
              <Button type="link" size="small" onClick={() => setEditor(record)}>编辑</Button>
              <Popconfirm
                title={`删除身份「${record.identity_name}」？`}
                description="键行级联删除；存在任一机器身份绑定时将 409（先解绑再删除——登记册全局生效）。"
                okText="确认删除"
                okButtonProps={{ danger: true }}
                onConfirm={() => deleteMut.mutate(record.id)}
              >
                <Button type="link" size="small" danger>删除</Button>
              </Popconfirm>
            </>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space style={{ display: 'flex', justifyContent: 'space-between' }} wrap>
        <Typography.Text type="secondary">
          撤销水位（单调不下降）：<Typography.Text code>{listQuery.data?.revocation_watermark ?? '—'}</Typography.Text>
          （快照水位低于网关已应用水位拒载——普通回滚不复活已撤销密钥）
        </Typography.Text>
        {canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditor(null)}>
            登记机器身份
          </Button>
        ) : null}
      </Space>
      <QueryErrorAlert error={listQuery.error} message="加载机器身份失败" />
      <SmartTable<MachineIdentitySummary>
        storageKey="machine-identities"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1450 }}
        pagination={false}
        locale={{ emptyText: '暂无机器身份——登记后静态导入公钥' }}
      />
      {detailId ? (
        <IdentityDetailDrawer id={detailId} canManage={canManage} onClose={() => setDetailId(null)} />
      ) : null}
      {editor !== undefined ? (
        <IdentityEditorModal editing={editor} onClose={() => setEditor(undefined)} onSaved={invalidate} />
      ) : null}
    </Space>
  )
}
