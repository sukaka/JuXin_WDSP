import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Checkbox,
  Form,
  Input,
  InputNumber,
  Modal,
  Space,
  Tag,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { domainsApi } from '../../../api/applications'
import type { DomainBody } from '../../../api/applications'
import RecordDetailDrawer from '../../../components/RecordDetailDrawer'
import SmartTable from '../../../components/SmartTable'
import useBatchDelete from '../../../hooks/useBatchDelete'
import { useAuthStore } from '../../../stores/auth'
import { hasPermission } from '../../../utils/permission'
import type { DomainItem } from '../../../types'

interface DomainFormValues {
  hostname: string
  is_primary: boolean
  http_enabled: boolean
  http_port?: number | null
  https_enabled: boolean
  https_port?: number | null
  redirect_http_to_https: boolean
}

/** 与后端一致的域名前端校验：不含协议/路径/端口，至少两个标签，泛域名仅 *.example.com 形式 */
function validateHostname(value: string): string | null {
  const v = value.trim().toLowerCase()
  if (!v) return '请输入域名'
  if (v.includes('://')) return '域名不得包含协议（如 https://）'
  if (v.includes('/')) return '域名不得包含路径'
  if (v.includes(':')) return '域名不得包含端口号'
  if (v.startsWith('*.')) {
    const rest = v.slice(2)
    if (!rest || rest.includes('*')) return '泛域名仅支持 *.example.com 形式'
    if (rest.split('.').length < 2) return '泛域名主体至少包含两个标签'
    return null
  }
  if (v.includes('*')) return '通配符 * 只能出现在域名最左侧'
  if (v.split('.').length < 2) return '域名至少包含两个标签（如 example.com）'
  const label = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
  if (!v.split('.').every((l) => label.test(l))) return '域名标签只能包含字母、数字、短横线'
  return null
}

export default function DomainsTab({
  appId,
  deploymentMode,
}: {
  appId: string
  deploymentMode?: string
}) {
  const isMirror = deploymentMode === 'MIRROR'
  const isTransparent = deploymentMode === 'TRANSPARENT'
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [editing, setEditing] = useState<DomainItem | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<DomainItem | null>(null)
  const [form] = Form.useForm<DomainFormValues>()
  const httpEnabled = Form.useWatch('http_enabled', form)
  const httpsEnabled = Form.useWatch('https_enabled', form)
  const noProtocolEnabled =
    (httpEnabled === false && !httpsEnabled) ||
    (httpsEnabled === false && !httpEnabled)

  const listQuery = useQuery({
    queryKey: ['domains', appId],
    queryFn: () => domainsApi.list(appId),
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['domains', appId] })
    void queryClient.invalidateQueries({ queryKey: ['application', appId] })
    void queryClient.invalidateQueries({ queryKey: ['applications'] })
  }

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
    if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') void invalidate()
  }

  const toBody = (values: DomainFormValues): DomainBody => ({
    hostname: values.hostname.trim(),
    is_primary: values.is_primary ?? false,
    http_enabled: values.http_enabled,
    https_enabled: values.https_enabled,
    http_port: values.http_enabled ? (values.http_port ?? 80) : null,
    https_port: values.https_enabled ? (values.https_port ?? 443) : null,
    redirect_http_to_https: values.http_enabled && values.https_enabled
      ? (values.redirect_http_to_https ?? false)
      : false,
  })

  const saveMutation = useMutation({
    mutationFn: ({ domainId, body }: { domainId: string | null; body: DomainBody }) =>
      domainId ? domainsApi.update(appId, domainId, body) : domainsApi.create(appId, body),
    onSuccess: () => {
      setCreateOpen(false)
      setEditing(null)
      form.resetFields()
      message.success('保存成功')
      void invalidate()
    },
    onError,
  })

  const removeMutation = useMutation({
    mutationFn: (domainId: string) => domainsApi.remove(appId, domainId),
    onSuccess: () => {
      message.success('删除成功')
      void invalidate()
    },
    onError,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<DomainItem>({
    remove: (domainId) => domainsApi.remove(appId, domainId),
    invalidateKeys: [['domains']],
    entityName: '域名',
    canDelete: hasPermission(permissions, 'domains.delete'),
  })

  const openEdit = (record: DomainItem) => {
    setEditing(record)
    form.setFieldsValue({
      hostname: record.hostname,
      is_primary: record.is_primary,
      http_enabled: record.http_enabled,
      http_port: record.http_port ?? 80,
      https_enabled: record.https_enabled,
      https_port: record.https_port ?? 443,
      redirect_http_to_https: record.redirect_http_to_https,
    })
  }

  const columns: ColumnsType<DomainItem> = [
    {
      title: '域名',
      dataIndex: 'hostname',
      render: (v: string, record) => (
        <Space>
          <span style={{ fontFamily: 'monospace' }}>{v}</span>
          {record.is_primary && <Tag color="blue">主域名</Tag>}
        </Space>
      ),
    },
    {
      title: '类型',
      dataIndex: 'domain_type',
      width: 110,
      render: (v: string) => (v === 'WILDCARD' ? <Tag color="purple">泛域名</Tag> : <Tag>精确</Tag>),
    },
    {
      title: 'HTTP 监听',
      key: 'http',
      width: 110,
      render: (_, r) =>
        r.http_enabled ? <Tag color="green">:{r.http_port ?? 80}</Tag> : <Tag>关闭</Tag>,
    },
    {
      title: 'HTTPS 监听',
      key: 'https',
      width: 110,
      render: (_, r) =>
        r.https_enabled ? <Tag color="green">:{r.https_port ?? 443}</Tag> : <Tag>关闭</Tag>,
    },
    {
      title: 'HTTP 跳转 HTTPS',
      dataIndex: 'redirect_http_to_https',
      width: 130,
      render: (v: boolean) => (v ? <Tag color="blue">跳转</Tag> : <Tag>不跳转</Tag>),
    },
    {
      title: '操作',
      key: 'actions',
      width: 140,
      render: (_, record) => (
        <Space>
          {hasPermission(permissions, 'domains.update') && (
            <Button type="link" size="small" onClick={() => openEdit(record)}>
              编辑
            </Button>
          )}
          {hasPermission(permissions, 'domains.delete') && (
            <Button
              type="link"
              size="small"
              danger
              onClick={() =>
                modal.confirm({
                  title: '删除确认',
                  content: `确定删除域名「${record.hostname}」吗？`,
                  okButtonProps: { danger: true },
                  onOk: () => removeMutation.mutate(record.id),
                })
              }
            >
              删除
            </Button>
          )}
        </Space>
      ),
    },
  ]

  const modalOpen = createOpen || editing !== null

  return (
    <>
      <Space style={{ marginBottom: 16 }}>
        {hasPermission(permissions, 'domains.create') && (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setEditing(null)
              form.resetFields()
              setCreateOpen(true)
            }}
          >
            新增域名
          </Button>
        )}
        {batchDeleteButton}
      </Space>

      {isTransparent && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="透明串接域名与目标端口说明"
          description="请配置客户端真实访问的域名（支持精确域名或单层泛域名 *.example.com）与真实目标端口（如 HTTP 80 / HTTPS 443）；启用 HTTPS 时须在「证书绑定」上传证书，网关将按 TLS SNI 分流防护。"
        />
      )}

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载域名列表失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<DomainItem>
          storageKey="applications-domains"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          pagination={false}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
        />
      )}

      <Modal
        title={editing ? `编辑域名：${editing.hostname}` : '新增域名'}
        open={modalOpen}
        onCancel={() => {
          setCreateOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        okButtonProps={{ disabled: noProtocolEnabled }}
        confirmLoading={saveMutation.isPending}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            is_primary: false,
            http_enabled: true,
            http_port: 80,
            https_enabled: false,
            https_port: 443,
            redirect_http_to_https: false,
          }}
          onFinish={(values) => {
            if (!values.http_enabled && !values.https_enabled) {
              message.error('HTTP 与 HTTPS 至少启用一个')
              return
            }
            saveMutation.mutate({ domainId: editing?.id ?? null, body: toBody(values) })
          }}
        >
          <Form.Item
            name="hostname"
            label="域名"
            rules={[
              { required: true, message: '请输入域名' },
              {
                validator: (_, v: string) => {
                  if (!v) return Promise.resolve()
                  const err = validateHostname(v)
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
            extra="支持精确域名（example.com）或泛域名（*.example.com），不含协议与端口"
          >
            <Input placeholder="example.com 或 *.example.com" autoComplete="off" />
          </Form.Item>
          <Form.Item name="is_primary" valuePropName="checked">
            <Checkbox>设为主域名</Checkbox>
          </Form.Item>
          <Space size="large" align="start">
            <Form.Item name="http_enabled" valuePropName="checked" label="启用 HTTP">
              <Checkbox>启用</Checkbox>
            </Form.Item>
            <Form.Item
              name="http_port"
              label="HTTP 端口"
              rules={
                httpEnabled
                  ? [{ required: true, message: '请输入端口' }]
                  : []
              }
            >
              <InputNumber min={1} max={65535} disabled={!httpEnabled} style={{ width: 120 }} />
            </Form.Item>
          </Space>
          <Space size="large" align="start">
            <Form.Item name="https_enabled" valuePropName="checked" label="启用 HTTPS">
              <Checkbox>启用</Checkbox>
            </Form.Item>
            <Form.Item
              name="https_port"
              label="HTTPS 端口"
              rules={
                httpsEnabled
                  ? [{ required: true, message: '请输入端口' }]
                  : []
              }
            >
              <InputNumber min={1} max={65535} disabled={!httpsEnabled} style={{ width: 120 }} />
            </Form.Item>
          </Space>
          {isMirror && httpsEnabled && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message="镜像旁路无法解密 HTTPS，勾选 HTTPS 无需绑定证书（仅用于站点 SNI 发现）；如需检测明文流量请启用 HTTP 端口。"
            />
          )}
          {isTransparent && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message="透明串接请填写业务真实访问域名及真实目标端口（如 80 / 443）；启用 HTTPS 时须在「证书绑定」上传对应证书。"
            />
          )}
          {!isMirror && httpEnabled && httpsEnabled && (
            <Form.Item name="redirect_http_to_https" valuePropName="checked">
              <Checkbox>HTTP 自动跳转 HTTPS</Checkbox>
            </Form.Item>
          )}
          {noProtocolEnabled && (
            <Alert type="warning" showIcon message="HTTP 与 HTTPS 至少启用一个，否则无法提交保存" />
          )}
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="域名详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
