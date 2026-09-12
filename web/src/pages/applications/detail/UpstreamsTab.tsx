import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Checkbox,
  Descriptions,
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
import { ExperimentOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { upstreamsApi } from '../../../api/applications'
import type { UpstreamBody, UpstreamTestBody } from '../../../api/applications'
import RecordDetailDrawer from '../../../components/RecordDetailDrawer'
import SmartTable from '../../../components/SmartTable'
import useBatchDelete from '../../../hooks/useBatchDelete'
import { useAuthStore } from '../../../stores/auth'
import { hasPermission } from '../../../utils/permission'
import type { UpstreamItem, UpstreamTestResult } from '../../../types'

interface UpstreamFormValues {
  name: string
  scheme: string
  host: string
  port: number
  weight: number
  priority: number
  health_check_enabled: boolean
  health_check_path: string
  health_check_method: string
  health_check_interval_seconds: number
  health_check_timeout_seconds: number
  expected_status_codes: string
  connect_timeout_ms: number
  response_header_timeout_ms: number
  tls_server_name: string
  tls_verify: boolean
  max_retries: number
}

const DEFAULT_VALUES: UpstreamFormValues = {
  name: '',
  scheme: 'http',
  host: '',
  port: 80,
  weight: 10,
  priority: 0,
  health_check_enabled: false,
  health_check_path: '/health',
  health_check_method: 'GET',
  health_check_interval_seconds: 30,
  health_check_timeout_seconds: 5,
  expected_status_codes: '200',
  connect_timeout_ms: 3000,
  response_header_timeout_ms: 10000,
  tls_server_name: '',
  tls_verify: true,
  max_retries: 1,
}

/** 与后端一致的 host 前端校验：IP 或域名，不允许泛域名 */
function validateHost(value: string): string | null {
  const v = value.trim().toLowerCase()
  if (!v) return '请输入主机地址'
  if (v.includes('://') || v.includes('/') || v.includes(':')) return '主机地址不含协议、路径或端口'
  if (v.includes('*')) return '源站主机不允许使用泛域名'
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
  if (ipv4.test(v)) {
    const ok = v.split('.').every((n) => Number(n) <= 255)
    return ok ? null : 'IP 地址格式不正确'
  }
  const label = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
  if (!v.split('.').every((l) => label.test(l))) return '主机名格式不正确'
  return null
}

function TestResultView({ result }: { result: UpstreamTestResult }) {
  const failed = result.error_code !== ''
  const stepTag = (ok: boolean, okText: string, failText = '失败') =>
    ok ? <Tag color="green">{okText}</Tag> : <Tag color="red">{failText}</Tag>
  return (
    <div>
      <Alert
        type={failed ? 'error' : 'success'}
        showIcon
        message={failed ? `测试失败：${result.error_code}` : '连通性测试通过'}
        description={failed ? result.error_message : undefined}
        style={{ marginBottom: 16 }}
      />
      <Descriptions column={2} size="small" bordered>
        <Descriptions.Item label="域名解析">
          {result.dns_result === 'ok' ? (
            <Tag color="green">成功</Tag>
          ) : result.dns_result === 'failed' ? (
            <Tag color="red">失败</Tag>
          ) : (
            <Tag>未执行</Tag>
          )}
        </Descriptions.Item>
        <Descriptions.Item label="解析地址">
          {result.resolved_addresses && result.resolved_addresses.length > 0
            ? result.resolved_addresses.join(', ')
            : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="网络连接">
          {stepTag(result.tcp_connected, '已连接', '连接失败')}
        </Descriptions.Item>
        <Descriptions.Item label="加密握手">
          {result.tls_handshake ? <Tag color="green">成功</Tag> : <Tag>未执行/失败</Tag>}
        </Descriptions.Item>
        <Descriptions.Item label="证书校验">
          {result.tls_verify_result === 'ok' ? (
            <Tag color="green">通过</Tag>
          ) : (
            <span>{result.tls_verify_result || '-'}</span>
          )}
        </Descriptions.Item>
        <Descriptions.Item label="HTTP 状态码">
          {result.http_status > 0 ? result.http_status : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="响应耗时">{result.response_time_ms} ms</Descriptions.Item>
      </Descriptions>
    </div>
  )
}

export default function UpstreamsTab({ appId }: { appId: string }) {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [editing, setEditing] = useState<UpstreamItem | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<UpstreamItem | null>(null)
  const [testing, setTesting] = useState<UpstreamItem | null>(null)
  const [testResult, setTestResult] = useState<UpstreamTestResult | null>(null)
  const [allowPrivate, setAllowPrivate] = useState(false)
  const [form] = Form.useForm<UpstreamFormValues>()
  const scheme = Form.useWatch('scheme', form)
  const healthCheckEnabled = Form.useWatch('health_check_enabled', form)

  const listQuery = useQuery({
    queryKey: ['upstreams', appId],
    queryFn: () => upstreamsApi.list(appId),
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['upstreams', appId] })
    void queryClient.invalidateQueries({ queryKey: ['application', appId] })
  }

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
      message.error('数据已被他人修改，请刷新后重试')
      void invalidate()
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveMutation = useMutation({
    mutationFn: ({ id, body }: { id: string | null; body: UpstreamBody & { version?: number } }) =>
      id
        ? upstreamsApi.update(id, { ...body, version: body.version ?? 0 } as UpstreamBody & { version: number })
        : upstreamsApi.create(appId, body),
    onSuccess: () => {
      setCreateOpen(false)
      setEditing(null)
      form.resetFields()
      message.success('保存成功')
      void invalidate()
    },
    onError,
  })

  const actionMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'enable' | 'disable' | 'delete' }) => {
      const map = {
        enable: upstreamsApi.enable,
        disable: upstreamsApi.disable,
        delete: upstreamsApi.remove,
      } as const
      return map[action](id)
    },
    onSuccess: () => {
      message.success('操作成功')
      void invalidate()
    },
    onError,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<UpstreamItem>({
    remove: (id) => upstreamsApi.remove(id),
    invalidateKeys: [['upstreams']],
    entityName: '上游',
    canDelete: hasPermission(permissions, 'upstreams.delete'),
  })

  const testMutation = useMutation({
    mutationFn: (body: UpstreamTestBody) => upstreamsApi.test(body),
    onSuccess: (data) => setTestResult(data),
    onError: (e) => {
      setTestResult(null)
      message.error(e instanceof ApiError ? e.message : '测试失败')
    },
  })

  const runTest = (record: UpstreamItem, allow: boolean) => {
    setTestResult(null)
    testMutation.mutate({
      scheme: record.scheme,
      host: record.host,
      port: record.port,
      health_check_path: record.health_check_path || '/health',
      tls_server_name: record.tls_server_name ?? '',
      tls_verify: record.tls_verify,
      allow_private: allow,
    })
  }

  const columns: ColumnsType<UpstreamItem> = [
    { title: '名称', dataIndex: 'name', width: 140, render: (v: string) => v || '-' },
    {
      title: '地址',
      key: 'addr',
      render: (_, r) => (
        <span style={{ fontFamily: 'monospace' }}>
          {r.scheme}://{r.host}:{r.port}
        </span>
      ),
    },
    { title: '权重', dataIndex: 'weight', width: 80 },
    { title: '优先级', dataIndex: 'priority', width: 80 },
    {
      title: '健康检查',
      dataIndex: 'health_check_enabled',
      width: 100,
      render: (v: boolean, r) => (v ? <Tag color="blue">{r.health_check_path}</Tag> : <Tag>关闭</Tag>),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => (v === 'ACTIVE' ? <Tag color="green">已启用</Tag> : <Tag color="orange">已停用</Tag>),
    },
    {
      title: '操作',
      key: 'actions',
      width: 240,
      render: (_, record) => (
        <Space wrap>
          {hasPermission(permissions, 'upstreams.test') && (
            <Button
              type="link"
              size="small"
              icon={<ExperimentOutlined />}
              onClick={() => {
                setTesting(record)
                setTestResult(null)
                setAllowPrivate(false)
              }}
            >
              测试
            </Button>
          )}
          {hasPermission(permissions, 'upstreams.update') && (
            <Button
              type="link"
              size="small"
              onClick={() => {
                setEditing(record)
                form.setFieldsValue({
                  name: record.name,
                  scheme: record.scheme,
                  host: record.host,
                  port: record.port,
                  weight: record.weight,
                  priority: record.priority,
                  health_check_enabled: record.health_check_enabled,
                  health_check_path: record.health_check_path,
                  health_check_method: record.health_check_method,
                  health_check_interval_seconds: record.health_check_interval_seconds,
                  health_check_timeout_seconds: record.health_check_timeout_seconds,
                  expected_status_codes: record.expected_status_codes,
                  connect_timeout_ms: record.connect_timeout_ms,
                  response_header_timeout_ms: record.response_header_timeout_ms,
                  tls_server_name: record.tls_server_name,
                  tls_verify: record.tls_verify,
                  max_retries: record.max_retries,
                })
              }}
            >
              编辑
            </Button>
          )}
          {hasPermission(permissions, 'upstreams.update') &&
            (record.status === 'ACTIVE' ? (
              <Button
                type="link"
                size="small"
                onClick={() => actionMutation.mutate({ id: record.id, action: 'disable' })}
              >
                停用
              </Button>
            ) : (
              <Button
                type="link"
                size="small"
                onClick={() => actionMutation.mutate({ id: record.id, action: 'enable' })}
              >
                启用
              </Button>
            ))}
          {hasPermission(permissions, 'upstreams.delete') && (
            <Button
              type="link"
              size="small"
              danger
              onClick={() =>
                modal.confirm({
                  title: '删除确认',
                  content: `确定删除源站「${record.name || `${record.host}:${record.port}`}」吗？`,
                  okButtonProps: { danger: true },
                  onOk: () => actionMutation.mutate({ id: record.id, action: 'delete' }),
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
        {hasPermission(permissions, 'upstreams.create') && (
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setEditing(null)
              form.resetFields()
              setCreateOpen(true)
            }}
          >
            新增源站
          </Button>
        )}
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载源站列表失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<UpstreamItem>
          storageKey="applications-upstreams"
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
        title={editing ? `编辑源站：${editing.name || editing.host}` : '新增源站'}
        open={modalOpen}
        onCancel={() => {
          setCreateOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        confirmLoading={saveMutation.isPending}
        width={720}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={DEFAULT_VALUES}
          onFinish={(values) =>
            saveMutation.mutate({
              id: editing?.id ?? null,
              body: { ...values, version: editing?.version },
            })
          }
        >
          <Space size="middle" wrap style={{ display: 'flex' }}>
            <Form.Item name="name" label="名称" style={{ width: 220 }}>
              <Input placeholder="源站名称（可选）" />
            </Form.Item>
            <Form.Item name="scheme" label="协议" style={{ width: 120 }} rules={[{ required: true }]}>
              <Select
                options={[
                  { value: 'http', label: 'HTTP' },
                  { value: 'https', label: 'HTTPS' },
                ]}
                onChange={(v: string) => {
                  const cur = form.getFieldValue('port') as number
                  if (v === 'https' && cur === 80) form.setFieldValue('port', 443)
                  if (v === 'http' && cur === 443) form.setFieldValue('port', 80)
                }}
              />
            </Form.Item>
            <Form.Item
              name="host"
              label="主机地址"
              style={{ width: 240 }}
              rules={[
                { required: true, message: '请输入主机地址' },
                {
                  validator: (_, v: string) => {
                    if (!v) return Promise.resolve()
                    const err = validateHost(v)
                    return err ? Promise.reject(new Error(err)) : Promise.resolve()
                  },
                },
              ]}
            >
              <Input placeholder="IP 或域名，如 10.0.0.1 / origin.internal" autoComplete="off" />
            </Form.Item>
            <Form.Item name="port" label="端口" style={{ width: 110 }} rules={[{ required: true, message: '请输入端口' }]}>
              <InputNumber min={1} max={65535} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="weight" label="权重" style={{ width: 100 }} rules={[{ required: true, message: '请输入权重' }]}>
              <InputNumber min={1} max={100} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="priority" label="优先级" style={{ width: 100 }}>
              <InputNumber min={0} max={100} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          <Form.Item name="health_check_enabled" valuePropName="checked">
            <Checkbox>启用主动健康检查</Checkbox>
          </Form.Item>
          {healthCheckEnabled && (
            <Space size="middle" wrap style={{ display: 'flex' }}>
              <Form.Item name="health_check_path" label="检查路径" style={{ width: 180 }} rules={[{ required: true, message: '请输入检查路径' }]}>
                <Input placeholder="/health" />
              </Form.Item>
              <Form.Item name="health_check_method" label="方法" style={{ width: 110 }}>
                <Select options={[{ value: 'GET' }, { value: 'HEAD' }]} />
              </Form.Item>
              <Form.Item name="health_check_interval_seconds" label="间隔(秒)" style={{ width: 100 }}>
                <InputNumber min={1} max={3600} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="health_check_timeout_seconds" label="超时(秒)" style={{ width: 100 }}>
                <InputNumber min={1} max={300} style={{ width: '100%' }} />
              </Form.Item>
              <Form.Item name="expected_status_codes" label="期望状态码" style={{ width: 160 }}>
                <Input placeholder="如 200 或 200-299,301" />
              </Form.Item>
            </Space>
          )}

          <Space size="middle" wrap style={{ display: 'flex' }}>
            <Form.Item name="connect_timeout_ms" label="连接超时(ms)" style={{ width: 130 }}>
              <InputNumber min={100} max={60000} step={100} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="response_header_timeout_ms" label="响应头超时(ms)" style={{ width: 140 }}>
              <InputNumber min={100} max={120000} step={100} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="max_retries" label="最大重试" style={{ width: 100 }}>
              <InputNumber min={0} max={10} style={{ width: '100%' }} />
            </Form.Item>
          </Space>

          {scheme === 'https' && (
            <Space size="middle" wrap style={{ display: 'flex' }}>
              <Form.Item name="tls_server_name" label="加密域名（SNI）" style={{ width: 240 }}>
                <Input placeholder="留空则使用主机地址" />
              </Form.Item>
              <Form.Item name="tls_verify" valuePropName="checked" label=" ">
                <Checkbox>校验源站证书</Checkbox>
              </Form.Item>
            </Space>
          )}
        </Form>
      </Modal>

      <Modal
        title={`连通性测试：${testing ? `${testing.scheme}://${testing.host}:${testing.port}` : ''}`}
        open={testing !== null}
        onCancel={() => setTesting(null)}
        footer={null}
        width={640}
        destroyOnHidden
      >
        {testing && (
          <div>
            <Space style={{ marginBottom: 16 }} wrap>
              <Button
                type="primary"
                loading={testMutation.isPending}
                onClick={() => runTest(testing, allowPrivate)}
              >
                开始测试
              </Button>
              <Checkbox
                checked={allowPrivate}
                onChange={(e) => setAllowPrivate(e.target.checked)}
              >
                允许私网地址（SSRF 防护默认拦截，内网源站需勾选）
              </Checkbox>
            </Space>
            {testMutation.isPending && <Typography.Text type="secondary">测试执行中…</Typography.Text>}
            {testResult && <TestResultView result={testResult} />}
          </div>
        )}
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="源站详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
