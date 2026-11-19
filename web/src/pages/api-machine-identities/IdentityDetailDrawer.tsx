import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import {
  machineIdentityApi,
  type MachineIdentityKey,
  type MachineIdentityKeyInput,
} from '../../api/machineIdentity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import {
  BOT_EXEMPT_NOTE,
  IDENTITY_STATUS_META,
  KEY_ALG_META,
  KEY_STATUS_META,
  REVOKE_WARNING,
  ROTATE_OVERLAP_NOTE,
  shortFingerprint,
  validatePemText,
} from '../../utils/machineIdentity'

interface KeyFormValues {
  kid: string
  alg: string
  public_key_pem: string
  not_before?: { toISOString: () => string } | null
  not_after?: { toISOString: () => string } | null
  overlap_hours?: number
}

/** 键表单（导入/轮换共用）：kid/alg/PEM/not_before/not_after（+轮换重叠窗口） */
function KeyFormFields({ rotate }: { rotate?: boolean }) {
  return (
    <>
      <Form.Item
        name="kid"
        label={rotate ? '新密钥标识（kid）' : '密钥标识（kid）'}
        rules={[{ required: true, whitespace: true, message: '密钥标识必填' }, { max: 128, message: '不超过 128 字符' }]}
        extra="身份内唯一（重复 409）；签名密钥登记册精确查找"
      >
        <Input placeholder="如：2026-10-primary" />
      </Form.Item>
      <Form.Item name="alg" label="算法" rules={[{ required: true, message: '请选择算法' }]}>
        <Select
          options={Object.keys(KEY_ALG_META).map((value) => ({ value, label: KEY_ALG_META[value].label }))}
          placeholder="选择算法"
        />
      </Form.Item>
      <Form.Item
        name="public_key_pem"
        label="公钥 PEM"
        rules={[{
          required: true,
          validator: (_, v: string) => {
            const err = validatePemText(v ?? '')
            return err ? Promise.reject(new Error(err)) : Promise.resolve()
          },
        }]}
        extra="恰一个 PUBLIC KEY 块（PKIX 或 RSA）；声明算法与实际键型不一致将 400"
      >
        <Input.TextArea rows={5} placeholder={'-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----'} style={{ fontFamily: 'monospace' }} />
      </Form.Item>
      <Space size={16} wrap>
        <Form.Item name="not_before" label="生效时间（可空）">
          <DatePicker showTime style={{ width: 220 }} />
        </Form.Item>
        <Form.Item name="not_after" label="失效时间（可空）">
          <DatePicker showTime style={{ width: 220 }} />
        </Form.Item>
        {rotate ? (
          <Form.Item
            name="overlap_hours"
            label="重叠窗口（小时）"
            initialValue={24}
            rules={[{ required: true, message: '重叠窗口必填' }, { type: 'integer', min: 1, max: 168, message: '1~168 小时（上限 168h）' }]}
          >
            <InputNumber min={1} max={168} precision={0} style={{ width: 160 }} />
          </Form.Item>
        ) : null}
      </Space>
    </>
  )
}

function keyFormPayload(values: KeyFormValues): MachineIdentityKeyInput {
  return {
    kid: values.kid.trim(),
    alg: values.alg,
    public_key_pem: values.public_key_pem.trim(),
    not_before: values.not_before ? values.not_before.toISOString() : null,
    not_after: values.not_after ? values.not_after.toISOString() : null,
    ...(values.overlap_hours !== undefined ? { overlap_hours: values.overlap_hours } : {}),
  }
}

/**
 * 身份详情抽屉（§1.12 端点 3/6/7/8）：键行表格（状态机三态/重叠窗口/revoked_seq 溯源/指纹短显）
 * + 导入公钥（PEM 校验）/ 轮换（重叠窗口 ≤168h）/ 撤销（高危确认——撤销即拒验且不可经回滚复活）。
 */
export default function IdentityDetailDrawer({
  id,
  canManage,
  onClose,
}: {
  id: string
  canManage: boolean
  onClose: () => void
}) {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const [importForm] = Form.useForm<KeyFormValues>()
  const [rotateForm] = Form.useForm<KeyFormValues>()
  const [importing, setImporting] = useState(false)
  const [rotating, setRotating] = useState<MachineIdentityKey | null>(null)
  const [formError, setFormError] = useState<string | null>(null)

  const detailQuery = useQuery({
    queryKey: ['machine-identity', id],
    queryFn: () => machineIdentityApi.getIdentity(id),
  })
  const detail = detailQuery.data

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['machine-identity', id] })
    void qc.invalidateQueries({ queryKey: ['machine-identities'] })
  }

  const importMut = useMutation({
    mutationFn: (body: MachineIdentityKeyInput) => machineIdentityApi.importKey(id, body),
    onSuccess: (key) => {
      message.success(`公钥已导入（${key.kid}，落库即生效中）`)
      setImporting(false)
      importForm.resetFields()
      invalidate()
    },
    onError: (e: unknown) => setFormError(e instanceof ApiError ? e.message : '导入失败'),
  })

  const rotateMut = useMutation({
    mutationFn: (body: MachineIdentityKeyInput) => machineIdentityApi.rotateKey(id, (rotating as MachineIdentityKey).id, body),
    onSuccess: (r) => {
      message.success(`已轮换：新键 ${r.key.kid} 已生效；旧键 ${r.retired_key.kid} 已退役（重叠窗口终点 ${r.retired_key.retire_overlap_until ?? '—'}）`)
      setRotating(null)
      rotateForm.resetFields()
      invalidate()
    },
    onError: (e: unknown) => setFormError(e instanceof ApiError ? e.message : '轮换失败'),
  })

  const revokeMut = useMutation({
    mutationFn: (keyId: string) => machineIdentityApi.revokeKey(id, keyId),
    onSuccess: (key) => {
      message.success(`已撤销 ${key.kid}（撤销水位序号=${key.revoked_seq ?? '—'}，即时生效）`)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '撤销失败'),
  })

  /** 撤销高危确认（水位单调不下降——不可经回滚复活） */
  const confirmRevoke = (key: MachineIdentityKey) => {
    modal.confirm({
      title: `撤销公钥「${key.kid}」？`,
      icon: null,
      content: (
        <Alert type="error" showIcon message="高危操作" description={REVOKE_WARNING} />
      ),
      okText: '确认撤销',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: () => revokeMut.mutateAsync(key.id),
    })
  }

  const keyColumns: ColumnsType<MachineIdentityKey> = [
    { title: '密钥标识（kid）', dataIndex: 'kid', width: 160, ellipsis: true, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: '算法', dataIndex: 'alg', width: 160 },
    {
      title: '状态', dataIndex: 'status', width: 190,
      render: (v: string) => <StatusTag value={v} map={KEY_STATUS_META} />,
    },
    { title: '生效', dataIndex: 'not_before', width: 160, render: (v?: string | null) => (v ? formatDateTime(v) : '—') },
    { title: '失效', dataIndex: 'not_after', width: 160, render: (v?: string | null) => (v ? formatDateTime(v) : '—') },
    {
      title: '重叠窗口终点', dataIndex: 'retire_overlap_until', width: 160,
      render: (v?: string | null) => (v ? formatDateTime(v) : '—'),
    },
    {
      title: '撤销水位序号', dataIndex: 'revoked_seq', width: 120,
      render: (v?: number | null) => (v !== null && v !== undefined ? <Typography.Text code>{v}</Typography.Text> : '—'),
    },
    {
      title: '指纹', dataIndex: 'key_fingerprint', width: 130,
      render: (v: string) => <Typography.Text code title={v}>{shortFingerprint(v)}</Typography.Text>,
    },
    {
      title: '操作', key: 'actions', width: 150, fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            {record.status === 'ACTIVE' ? (
              <Button type="link" size="small" onClick={() => { setFormError(null); rotateForm.resetFields(); setRotating(record) }}>轮换</Button>
            ) : null}
            {record.status !== 'REVOKED' ? (
              <Button type="link" size="small" danger onClick={() => confirmRevoke(record)}>撤销</Button>
            ) : null}
          </Space>
        ) : null,
    },
  ]

  return (
    <Drawer
      title={detail ? `机器身份：${detail.identity.identity_name}` : '机器身份详情'}
      width={1100}
      open
      onClose={onClose}
      destroyOnHidden
    >
      <QueryErrorAlert error={detailQuery.error} message="加载身份详情失败" />
      {detail ? (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Descriptions size="small" column={2} bordered>
            <Descriptions.Item label="状态"><StatusTag value={detail.identity.status} map={IDENTITY_STATUS_META} /></Descriptions.Item>
            <Descriptions.Item label="版本">v{detail.identity.version}（乐观锁）</Descriptions.Item>
            <Descriptions.Item label="租户范围">
              {detail.identity.tenant_id ? <Typography.Text code>{detail.identity.tenant_id}</Typography.Text> : <Tag>跨租户共享</Tag>}
            </Descriptions.Item>
            <Descriptions.Item label="绑定主体">
              {detail.identity.principal_binding ? (
                <Typography.Text code>{detail.identity.principal_binding}</Typography.Text>
              ) : (
                <Typography.Text type="secondary">不绑定</Typography.Text>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="Bot 挑战豁免前提">
              {detail.identity.bot_challenge_exempt ? <Tag color="orange">声明豁免</Tag> : '不豁免'}
            </Descriptions.Item>
            <Descriptions.Item label="更新时间">{formatDateTime(detail.identity.updated_at)}</Descriptions.Item>
          </Descriptions>
          {detail.identity.bot_challenge_exempt ? <Alert type="info" showIcon message={BOT_EXEMPT_NOTE} /> : null}

          <div>
            <Space style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }} wrap>
              <Typography.Text strong>公钥（{detail.keys.length}）</Typography.Text>
              {canManage ? (
                <Button type="primary" size="small" onClick={() => { setFormError(null); importForm.resetFields(); setImporting(true) }}>
                  导入公钥
                </Button>
              ) : null}
            </Space>
            <SmartTable<MachineIdentityKey>
              storageKey="machine-identity-keys"
              rowKey="id"
              size="small"
              columns={keyColumns}
              dataSource={detail.keys}
              pagination={false}
              scroll={{ x: 1350 }}
              locale={{ emptyText: '暂无公钥——唯一来源=管理面静态离线导入（禁止按请求 keyid 抓取 URL）' }}
            />
          </div>
        </Space>
      ) : (
        <Typography.Text type="secondary">加载中…</Typography.Text>
      )}

      <Modal
        title="导入公钥（静态离线导入）"
        open={importing}
        onCancel={() => setImporting(false)}
        okText="导入"
        confirmLoading={importMut.isPending}
        onOk={() => importForm.submit()}
        width={640}
      >
        {formError ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message="导入失败" description={formError} /> : null}
        <Form<KeyFormValues>
          form={importForm}
          layout="vertical"
          onFinish={(values) => { setFormError(null); importMut.mutate(keyFormPayload(values)) }}
        >
          <KeyFormFields />
        </Form>
      </Modal>

      <Modal
        title={rotating ? `轮换公钥：${rotating.kid}` : '轮换公钥'}
        open={rotating !== null}
        onCancel={() => setRotating(null)}
        okText="确认轮换"
        confirmLoading={rotateMut.isPending}
        onOk={() => rotateForm.submit()}
        width={640}
      >
        {formError ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message="轮换失败" description={formError} /> : null}
        <Alert type="info" showIcon style={{ marginBottom: 12 }} message={ROTATE_OVERLAP_NOTE} />
        <Form<KeyFormValues>
          form={rotateForm}
          layout="vertical"
          onFinish={(values) => { setFormError(null); rotateMut.mutate(keyFormPayload(values)) }}
        >
          <KeyFormFields rotate />
        </Form>
      </Modal>
    </Drawer>
  )
}
