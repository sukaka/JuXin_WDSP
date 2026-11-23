import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  List,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import { protectionPoliciesApi } from '../../api/protectionPolicies'
import type {
  CreateProtectionPolicyBody,
  UpdateProtectionPolicyBody,
} from '../../api/protectionPolicies'
import ProtectionModeTag from '../../components/ProtectionModeTag'
import SmartTable from '../../components/SmartTable'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type { ProtectionPolicyItem } from '../../types'

interface Filters {
  keyword?: string
  protection_mode?: string
}

type PolicyFormValues = Omit<CreateProtectionPolicyBody, 'code'> & { code?: string }

const CODE_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/

const MODE_OPTIONS = [
  { value: 'OFF', label: '关闭' },
  { value: 'OBSERVE', label: '观察' },
  { value: 'PROTECT', label: '防护' },
]

const PL_OPTIONS = [1, 2, 3, 4].map((n) => ({ value: n, label: `PL${n}` }))

/** 策略表单（新建含编码，编辑不含编码） */
function PolicyFormFields({ isCreate }: { isCreate: boolean }) {
  return (
    <>
      {isCreate && (
        <Form.Item
          name="code"
          label="策略编码"
          rules={[
            { required: true, message: '请输入策略编码' },
            {
              validator: (_, v: string) => {
                if (!v) return Promise.resolve()
                if (!CODE_PATTERN.test(v) || v.includes('--')) {
                  return Promise.reject(
                    new Error('3-64 位小写字母、数字或短横线，须以字母或数字开头结尾，禁止连续短横线'),
                  )
                }
                return Promise.resolve()
              },
            },
          ]}
          extra="创建后不可修改（如 high-security）"
        >
          <Input placeholder="小写字母、数字、短横线" autoComplete="off" />
        </Form.Item>
      )}
      <Form.Item
        name="name"
        label="策略名称"
        rules={[
          { required: true, message: '请输入策略名称' },
          { max: 128, message: '不超过 128 个字符' },
        ]}
      >
        <Input placeholder="策略显示名称" />
      </Form.Item>
      <Form.Item name="description" label="描述">
        <Input.TextArea rows={2} placeholder="策略用途与适用场景说明（可选）" />
      </Form.Item>
      <Form.Item name="protection_mode" label="防护模式" rules={[{ required: true }]}>
        <Select options={MODE_OPTIONS} />
      </Form.Item>
      <Form.Item
        name="paranoia_level"
        label="严格等级（PL）"
        rules={[{ required: true }]}
        extra="等级越高检测越严格、误报越多，建议从 PL1 开始"
      >
        <Select options={PL_OPTIONS} />
      </Form.Item>
      <Form.Item
        name="inbound_anomaly_threshold"
        label="入站异常阈值"
        rules={[
          { required: true, message: '请输入入站异常阈值' },
          { type: 'number', min: 1, max: 100, message: '入站异常阈值必须在 1–100 之间' },
          {
            validator: (_, v) =>
              v == null || Number.isInteger(v)
                ? Promise.resolve()
                : Promise.reject(new Error('请输入整数')),
          },
        ]}
        extra="范围 1–100；请求异常评分达到该阈值即按防护模式处理"
      >
        <InputNumber min={1} max={100} precision={0} step={1} style={{ width: '100%' }} />
      </Form.Item>
      <Form.Item
        name="outbound_anomaly_threshold"
        label="出站异常阈值"
        rules={[
          { required: true, message: '请输入出站异常阈值' },
          { type: 'number', min: 1, max: 100, message: '出站异常阈值必须在 1–100 之间' },
          {
            validator: (_, v) =>
              v == null || Number.isInteger(v)
                ? Promise.resolve()
                : Promise.reject(new Error('请输入整数')),
          },
        ]}
        extra="范围 1–100；响应异常评分达到该阈值即按防护模式处理"
      >
        <InputNumber min={1} max={100} precision={0} step={1} style={{ width: '100%' }} />
      </Form.Item>
      <Form.Item name="request_body_access" label="请求体检查" valuePropName="checked">
        <Switch checkedChildren="开启" unCheckedChildren="关闭" />
      </Form.Item>
      <Form.Item
        name="response_body_access"
        label="响应体检查"
        valuePropName="checked"
        extra="开启后可检测响应中的敏感信息泄露，会增加性能开销"
      >
        <Switch checkedChildren="开启" unCheckedChildren="关闭" />
      </Form.Item>
    </>
  )
}

export default function ProtectionPoliciesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<ProtectionPolicyItem | null>(null)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [createForm] = Form.useForm<PolicyFormValues>()
  const [editForm] = Form.useForm<PolicyFormValues>()

  const listQuery = useQuery({
    queryKey: ['protection-policies', filters, page, pageSize],
    queryFn: () => protectionPoliciesApi.list({ ...filters, page, page_size: pageSize }),
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ProtectionPolicyItem>({
    remove: (id) => protectionPoliciesApi.remove(id),
    invalidateKeys: [['protection-policies']],
    entityName: '防护策略',
    canDelete: hasPermission(permissions, 'protection_policies.delete'),
  })

  const detailQuery = useQuery({
    queryKey: ['protection-policy', detailId],
    queryFn: () => protectionPoliciesApi.get(detailId as string),
    enabled: detailId !== null,
  })

  // 详情抽屉中的应用绑定列表：取应用全量做 id → 名称映射
  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-policy'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: detailId !== null,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['protection-policies'] })

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
      message.error(e.message || '数据已被他人修改或存在冲突，请刷新后重试')
      void invalidate()
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (body: CreateProtectionPolicyBody) => protectionPoliciesApi.create(body),
    onSuccess: (data) => {
      setCreateOpen(false)
      createForm.resetFields()
      message.success(`策略「${data.name}」创建成功`)
      void invalidate()
    },
    onError,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: UpdateProtectionPolicyBody }) =>
      protectionPoliciesApi.update(id, body),
    onSuccess: () => {
      setEditing(null)
      message.success('保存成功')
      void invalidate()
    },
    onError,
  })

  const actionMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'delete' | 'copy' }): Promise<ProtectionPolicyItem | { message: string }> =>
      action === 'delete' ? protectionPoliciesApi.remove(id) : protectionPoliciesApi.copy(id),
    onSuccess: (_data, vars) => {
      message.success(vars.action === 'copy' ? '策略已复制' : '策略已删除')
      void invalidate()
    },
    onError,
  })

  const runAction = (action: 'delete' | 'copy', record: ProtectionPolicyItem) => {
    const exec = () => actionMutation.mutate({ id: record.id, action })
    if (action === 'delete') {
      modal.confirm({
        title: '删除确认',
        content:
          record.usage_count > 0
            ? `策略「${record.name}」正被 ${record.usage_count} 个应用引用，删除将被后端拒绝。确定继续吗？`
            : `确定删除策略「${record.name}」吗？删除后不可恢复。`,
        okButtonProps: { danger: true },
        onOk: exec,
      })
    } else {
      modal.confirm({
        title: '复制确认',
        content: `确定复制策略「${record.name}」吗？将生成同配置的新策略。`,
        onOk: exec,
      })
    }
  }

  const openEdit = (record: ProtectionPolicyItem) => {
    if (record.is_builtin) {
      message.warning('内置策略不允许修改，可通过复制生成可编辑副本')
      return
    }
    setEditing(record)
    editForm.setFieldsValue({
      name: record.name,
      description: record.description,
      protection_mode: record.protection_mode,
      paranoia_level: record.paranoia_level,
      inbound_anomaly_threshold: record.inbound_anomaly_threshold,
      outbound_anomaly_threshold: record.outbound_anomaly_threshold,
      request_body_access: record.request_body_access,
      response_body_access: record.response_body_access,
    })
  }

  const columns: ColumnsType<ProtectionPolicyItem> = [
    { title: '策略编码', dataIndex: 'code', width: 140 },
    {
      title: '名称',
      dataIndex: 'name',
      width: 180,
      render: (v: string, record) => (
        <Button
          type="link"
          size="small"
          style={{ padding: 0, height: 'auto' }}
          onClick={() => setDetailId(record.id)}
        >
          {v}
        </Button>
      ),
    },
    {
      title: '防护模式',
      dataIndex: 'protection_mode',
      width: 130,
      render: (v: string) => <ProtectionModeTag mode={v} />,
    },
    {
      title: '执行等级',
      dataIndex: 'paranoia_level',
      width: 90,
      align: 'center',
      render: (v: number) => <Tag color="geekblue">{`PL${v}`}</Tag>,
    },
    { title: '入站阈值', dataIndex: 'inbound_anomaly_threshold', width: 90 },
    { title: '出站阈值', dataIndex: 'outbound_anomaly_threshold', width: 90 },
    {
      title: '内置',
      dataIndex: 'is_builtin',
      width: 80,
      render: (v: boolean) => (v ? <Tag color="purple">内置</Tag> : <Tag>自定义</Tag>),
    },
    {
      title: '引用应用数',
      dataIndex: 'usage_count',
      width: 100,
      render: (v: number) => (v > 0 ? <Tag color="blue">{v}</Tag> : v),
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
      width: 220,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
            详情
          </Button>
          {hasPermission(permissions, 'protection_policies.update') && (
            <Tooltip title={record.is_builtin ? '内置策略不允许修改' : undefined}>
              <span>
                <Button type="link" size="small" disabled={record.is_builtin} onClick={() => openEdit(record)}>
                  编辑
                </Button>
              </span>
            </Tooltip>
          )}
          {hasPermission(permissions, 'protection_policies.create') && (
            <Button type="link" size="small" onClick={() => runAction('copy', record)}>
              复制
            </Button>
          )}
          {hasPermission(permissions, 'protection_policies.delete') && (
            <Tooltip title={record.is_builtin ? '内置策略不允许删除' : undefined} placement="left">
              <span>
                <Button
                  type="link"
                  size="small"
                  danger
                  disabled={record.is_builtin}
                  onClick={() => runAction('delete', record)}
                >
                  删除
                </Button>
              </span>
            </Tooltip>
          )}
        </Space>
      ),
    },
  ]

  const detail = detailQuery.data
  const appNameById = new Map((appsQuery.data?.items ?? []).map((a) => [a.id, a.name]))

  return (
    <Card
      title="防护策略"
      extra={
        hasPermission(permissions, 'protection_policies.create') && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建策略
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="搜索编码或名称"
          allowClear
          style={{ width: 240 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, keyword: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="防护模式"
          allowClear
          style={{ width: 150 }}
          options={MODE_OPTIONS}
          onChange={(v) => {
            setFilters((f) => ({ ...f, protection_mode: v }))
            setPage(1)
          }}
        />
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载防护策略失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<ProtectionPolicyItem>
          storageKey="protection-policies"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => setDetailId(record.id),
            style: { cursor: 'pointer' },
          })}
          scroll={{ x: 1250 }}
          pagination={{
            current: page,
            pageSize,
            total: listQuery.data?.total ?? 0,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => {
              setPage(p)
              setPageSize(ps)
            },
          }}
        />
      )}

      <Modal
        title="新建防护策略"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => createForm.submit()}
        confirmLoading={createMutation.isPending}
        destroyOnHidden
      >
        <Form
          form={createForm}
          layout="vertical"
          initialValues={{
            protection_mode: 'OBSERVE',
            paranoia_level: 1,
            inbound_anomaly_threshold: 5,
            outbound_anomaly_threshold: 4,
            request_body_access: true,
            response_body_access: false,
          }}
          onFinish={(values) =>
            createMutation.mutate({
              code: values.code ?? '',
              name: values.name,
              description: values.description ?? '',
              protection_mode: values.protection_mode,
              paranoia_level: values.paranoia_level,
              inbound_anomaly_threshold: values.inbound_anomaly_threshold,
              outbound_anomaly_threshold: values.outbound_anomaly_threshold,
              request_body_access: values.request_body_access,
              response_body_access: values.response_body_access,
            })
          }
        >
          <PolicyFormFields isCreate />
        </Form>
      </Modal>

      <Modal
        title={`编辑策略：${editing?.name ?? ''}`}
        open={editing !== null}
        onCancel={() => setEditing(null)}
        onOk={() => editForm.submit()}
        confirmLoading={updateMutation.isPending}
        destroyOnHidden
      >
        <Form
          form={editForm}
          layout="vertical"
          onFinish={(values) => {
            if (!editing) return
            updateMutation.mutate({
              id: editing.id,
              body: {
                name: values.name,
                description: values.description ?? '',
                protection_mode: values.protection_mode,
                paranoia_level: values.paranoia_level,
                inbound_anomaly_threshold: values.inbound_anomaly_threshold,
                outbound_anomaly_threshold: values.outbound_anomaly_threshold,
                request_body_access: values.request_body_access,
                response_body_access: values.response_body_access,
                version: editing.version,
              },
            })
          }}
        >
          <PolicyFormFields isCreate={false} />
        </Form>
      </Modal>

      <Drawer
        title="策略详情"
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={640}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载策略详情失败"
            description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          />
        ) : detail ? (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="策略编码">{detail.code}</Descriptions.Item>
              <Descriptions.Item label="名称">{detail.name}</Descriptions.Item>
              <Descriptions.Item label="描述" span={2}>
                {detail.description || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="防护模式">
                <ProtectionModeTag mode={detail.protection_mode} />
              </Descriptions.Item>
              <Descriptions.Item label="执行等级">{`PL${detail.paranoia_level}`}</Descriptions.Item>
              <Descriptions.Item label="入站异常阈值">
                {detail.inbound_anomaly_threshold}
              </Descriptions.Item>
              <Descriptions.Item label="出站异常阈值">
                {detail.outbound_anomaly_threshold}
              </Descriptions.Item>
              <Descriptions.Item label="请求体检查">
                {detail.request_body_access ? <Tag color="green">开启</Tag> : <Tag>关闭</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="响应体检查">
                {detail.response_body_access ? <Tag color="green">开启</Tag> : <Tag>关闭</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="阻断状态码">{detail.blocking_status_code}</Descriptions.Item>
              <Descriptions.Item label="是否内置">
                {detail.is_builtin ? <Tag color="purple">内置</Tag> : <Tag>自定义</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">{formatDateTime(detail.created_at)}</Descriptions.Item>
              <Descriptions.Item label="更新时间">{formatDateTime(detail.updated_at)}</Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>
              绑定应用（{detail.application_ids?.length ?? 0}）
            </Typography.Title>
            <Typography.Paragraph type="secondary" style={{ marginTop: 0 }}>
              绑定后需在「配置发布」中发布，网关才会应用本策略的 PL/阈值等参数。
            </Typography.Paragraph>
            {hasPermission(permissions, 'protection_policies.update') && (
              <Space style={{ marginBottom: 12 }} wrap>
                <Select
                  showSearch
                  optionFilterProp="label"
                  placeholder="选择应用绑定本策略"
                  style={{ minWidth: 260 }}
                  options={(appsQuery.data?.items ?? []).map((a) => ({
                    value: a.id,
                    label: `${a.name} (${a.code})`,
                  }))}
                  onSelect={(appId: string) => {
                    protectionPoliciesApi
                      .bindApplication(detail.id, appId)
                      .then(() => {
                        message.success('已绑定，请发布配置后生效')
                        void queryClient.invalidateQueries({ queryKey: ['protection-policy', detail.id] })
                        void queryClient.invalidateQueries({ queryKey: ['protection-policies'] })
                      })
                      .catch((e: unknown) => {
                        message.error(e instanceof ApiError ? e.message : '绑定失败')
                      })
                  }}
                />
              </Space>
            )}
            {appsQuery.isLoading ? (
              <Typography.Text type="secondary">加载应用列表...</Typography.Text>
            ) : (detail.application_ids ?? []).length === 0 ? (
              <Typography.Text type="secondary">暂无应用绑定该策略</Typography.Text>
            ) : (
              <List
                size="small"
                bordered
                dataSource={detail.application_ids ?? []}
                renderItem={(appId) => (
                  <List.Item
                    actions={
                      hasPermission(permissions, 'protection_policies.update')
                        ? [
                            <Button
                              key="unbind"
                              type="link"
                              size="small"
                              danger
                              onClick={() => {
                                protectionPoliciesApi
                                  .unbindApplication(detail.id, appId)
                                  .then(() => {
                                    message.success('已解绑，请发布配置后生效')
                                    void queryClient.invalidateQueries({
                                      queryKey: ['protection-policy', detail.id],
                                    })
                                    void queryClient.invalidateQueries({
                                      queryKey: ['protection-policies'],
                                    })
                                  })
                                  .catch((e: unknown) => {
                                    message.error(e instanceof ApiError ? e.message : '解绑失败')
                                  })
                              }}
                            >
                              解绑
                            </Button>,
                          ]
                        : undefined
                    }
                  >
                    <Typography.Text>{appNameById.get(appId) ?? appId}</Typography.Text>
                  </List.Item>
                )}
              />
            )}
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
