import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  List,
  Modal,
  Row,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tabs,
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
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { ATTACK_TYPE_META, RULE_SEVERITY_META, RULE_SOURCE_META } from '../../utils/stage4'
import type { ProtectionPolicyEffectiveRuleItem, ProtectionPolicyItem } from '../../types'

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

const EFFECTIVE_RULE_STATUS_META: Record<string, { color: string; label: string }> = {
  ACTIVE: { color: 'green', label: '生效' },
  DISABLED_BY_OVERRIDE: { color: 'red', label: '覆盖停用' },
  SKIPPED_BY_PL: { color: 'default', label: '高于当前PL' },
  MODE_OFF: { color: 'orange', label: '策略关闭' },
}

const EFFECTIVE_STATUS_OPTIONS = [
  { value: 'ACTIVE', label: '生效' },
  { value: 'DISABLED_BY_OVERRIDE', label: '覆盖停用' },
  { value: 'SKIPPED_BY_PL', label: '高于当前PL' },
  { value: 'MODE_OFF', label: '策略关闭' },
]

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
  const [detailTab, setDetailTab] = useState<'basic' | 'directives' | 'rules'>('basic')
  const [ruleKeyword, setRuleKeyword] = useState<string | undefined>(undefined)
  const [ruleStatus, setRuleStatus] = useState<string | undefined>(undefined)
  const [rulePage, setRulePage] = useState(1)
  const [rulePageSize, setRulePageSize] = useState(20)
  const [createForm] = Form.useForm<PolicyFormValues>()
  const [editForm] = Form.useForm<PolicyFormValues>()

  const openDetail = (id: string) => {
    setDetailTab('basic')
    setRuleKeyword(undefined)
    setRuleStatus(undefined)
    setRulePage(1)
    setDetailId(id)
  }

  const closeDetail = () => {
    setDetailId(null)
    setDetailTab('basic')
  }

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

  const contentQuery = useQuery({
    queryKey: [
      'protection-policy-content',
      detailId,
      ruleKeyword,
      ruleStatus,
      rulePage,
      rulePageSize,
    ],
    queryFn: () =>
      protectionPoliciesApi.content(detailId as string, {
        keyword: ruleKeyword,
        effective_status: ruleStatus,
        page: rulePage,
        page_size: rulePageSize,
      }),
    enabled: detailId !== null && detailTab !== 'basic',
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
            ? `策略「${record.name}」正被 ${record.usage_count} 处应用或域名引用，删除将被后端拒绝。确定继续吗？`
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
          onClick={() => openDetail(record.id)}
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
      title: '引用数',
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
          <Button type="link" size="small" onClick={() => openDetail(record.id)}>
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
            onDoubleClick: () => openDetail(record.id),
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
        title={detail ? `策略详情：${detail.name}` : '策略详情'}
        open={detailId !== null}
        onClose={closeDetail}
        width={860}
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
          <Tabs
            activeKey={detailTab}
            onChange={(key) => setDetailTab(key as 'basic' | 'directives' | 'rules')}
            items={[
              {
                key: 'basic',
                label: '基本配置与绑定',
                children: (
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
                    <Typography.Title level={5} style={{ marginTop: 20 }}>
                      绑定域名（{detail.domains?.length ?? 0}）
                    </Typography.Title>
                    <Typography.Paragraph type="secondary" style={{ marginTop: 0 }}>
                      可在「网站应用 → 域名管理」中为单个域名选择或调整防护策略；域名级策略优先于所属应用默认策略。
                    </Typography.Paragraph>
                    {(detail.domains ?? []).length === 0 ? (
                      <Typography.Text type="secondary">暂无域名单独绑定该策略</Typography.Text>
                    ) : (
                      <List
                        size="small"
                        bordered
                        dataSource={detail.domains ?? []}
                        renderItem={(dom) => (
                          <List.Item>
                            <Space wrap>
                              <Typography.Text code>{dom.hostname}</Typography.Text>
                              <Typography.Text type="secondary">
                                {dom.application_name} ({dom.application_code})
                              </Typography.Text>
                            </Space>
                          </List.Item>
                        )}
                      />
                    )}
                  </>
                ),
              },
              {
                key: 'directives',
                label: '生效指令（SecLang）',
                children: contentQuery.isLoading ? (
                  <Typography.Text type="secondary">正在生成策略指令...</Typography.Text>
                ) : contentQuery.isError ? (
                  <Alert
                    type="error"
                    showIcon
                    message="加载策略生效指令失败"
                    description={contentQuery.error instanceof ApiError ? contentQuery.error.message : undefined}
                  />
                ) : contentQuery.data ? (
                  <Space direction="vertical" size={16} style={{ width: '100%' }}>
                    <Alert
                      type="info"
                      showIcon
                      message={`网关实际执行引擎：SecRuleEngine ${contentQuery.data.sec_rule_engine}（PL${contentQuery.data.paranoia_level}，入站阈值 ${contentQuery.data.inbound_anomaly_threshold}，出站阈值 ${contentQuery.data.outbound_anomaly_threshold}）`}
                      description="以下为与配置发布完全同源生成的 Coraza SecLang 指令（包含本策略参数、全局及策略级规则覆盖、已启用自定义规则、全局 WAF 例外与按序 Include 的规则文件）。单个应用专属的例外或规则覆盖会在对应应用路由发布时额外追加。"
                    />
                    <Card
                      size="small"
                      title="完整 Coraza SecLang 指令"
                      extra={
                        <Typography.Text
                          copyable={{
                            text: contentQuery.data.generated_directives,
                            tooltips: ['复制全部指令', '已复制'],
                          }}
                        >
                          复制指令
                        </Typography.Text>
                      }
                    >
                      <pre
                        style={{
                          margin: 0,
                          maxHeight: 340,
                          overflow: 'auto',
                          background: '#f5f5f5',
                          padding: 12,
                          borderRadius: 6,
                          fontSize: 12,
                          fontFamily: 'monospace',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                        }}
                      >
                        {contentQuery.data.generated_directives}
                      </pre>
                    </Card>

                    <Card
                      size="small"
                      title={`生效规则覆盖（${contentQuery.data.overrides.length}）`}
                    >
                      {contentQuery.data.overrides.length === 0 ? (
                        <Typography.Text type="secondary">当前无全局或本策略级规则覆盖</Typography.Text>
                      ) : (
                        <List
                          size="small"
                          dataSource={contentQuery.data.overrides}
                          renderItem={(ov) => (
                            <List.Item>
                              <Space wrap>
                                <Typography.Text code>{ov.rule_id}</Typography.Text>
                                <Tag color={ov.action === 'DISABLE' ? 'red' : 'green'}>
                                  {ov.action === 'DISABLE' ? '停用规则' : '启用规则'}
                                </Tag>
                                <Tag>{ov.scope_type === 'GLOBAL' ? '全局' : '策略级'}</Tag>
                                {!ov.effective_active && <Tag color="default">已被更高优先级覆盖</Tag>}
                                {ov.reason && <Typography.Text type="secondary">{ov.reason}</Typography.Text>}
                              </Space>
                            </List.Item>
                          )}
                        />
                      )}
                    </Card>

                    <Card
                      size="small"
                      title={`已启用自定义规则（${contentQuery.data.custom_rules.length}）`}
                    >
                      {contentQuery.data.custom_rules.length === 0 ? (
                        <Typography.Text type="secondary">当前无已启用的自定义规则</Typography.Text>
                      ) : (
                        <List
                          size="small"
                          dataSource={contentQuery.data.custom_rules}
                          renderItem={(cr) => (
                            <List.Item>
                              <Space direction="vertical" size={4} style={{ width: '100%' }}>
                                <Space wrap>
                                  <Typography.Text code>{cr.rule_id}</Typography.Text>
                                  <Typography.Text strong>{cr.name}</Typography.Text>
                                  <StatusTag value={cr.severity} map={RULE_SEVERITY_META} />
                                </Space>
                                <pre
                                  style={{
                                    margin: 0,
                                    background: '#f5f5f5',
                                    padding: 8,
                                    borderRadius: 4,
                                    fontSize: 12,
                                    fontFamily: 'monospace',
                                    whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-all',
                                  }}
                                >
                                  {cr.generated_rule}
                                </pre>
                              </Space>
                            </List.Item>
                          )}
                        />
                      )}
                    </Card>

                    <Card
                      size="small"
                      title={`已启用全局 WAF 例外（${contentQuery.data.global_exceptions.length}）`}
                    >
                      {contentQuery.data.global_exceptions.length === 0 ? (
                        <Typography.Text type="secondary">当前无已启用的全局 WAF 例外</Typography.Text>
                      ) : (
                        <List
                          size="small"
                          dataSource={contentQuery.data.global_exceptions}
                          renderItem={(ex) => (
                            <List.Item>
                              <Space direction="vertical" size={4} style={{ width: '100%' }}>
                                <Space wrap>
                                  <Tag color="blue">{ex.scope_type || 'GLOBAL'}</Tag>
                                  <Typography.Text type="secondary">
                                    v{ex.exception_version} · 效果规则 ID {ex.rule_id}
                                  </Typography.Text>
                                </Space>
                                <pre
                                  style={{
                                    margin: 0,
                                    background: '#f5f5f5',
                                    padding: 8,
                                    borderRadius: 4,
                                    fontSize: 12,
                                    fontFamily: 'monospace',
                                    whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-all',
                                  }}
                                >
                                  {ex.seclang}
                                </pre>
                              </Space>
                            </List.Item>
                          )}
                        />
                      )}
                    </Card>

                    <Card size="small" title="按顺序加载的规则文件阶段">
                      <List
                        size="small"
                        dataSource={contentQuery.data.loaded_rule_files}
                        renderItem={(st) => (
                          <List.Item>
                            <Space direction="vertical" size={0}>
                              <Typography.Text code>
                                {st.order}. {st.path}
                              </Typography.Text>
                              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                                {st.description}
                              </Typography.Text>
                            </Space>
                          </List.Item>
                        )}
                      />
                    </Card>
                  </Space>
                ) : null,
              },
              {
                key: 'rules',
                label: '生效规则清单',
                children: contentQuery.isError ? (
                  <Alert
                    type="error"
                    showIcon
                    message="加载策略生效规则清单失败"
                    description={contentQuery.error instanceof ApiError ? contentQuery.error.message : undefined}
                  />
                ) : (
                  <Space direction="vertical" size={14} style={{ width: '100%' }}>
                    {contentQuery.data && (
                      <Row gutter={12}>
                        <Col span={6}>
                          <Card size="small">
                            <Statistic title="规则库总数" value={contentQuery.data.summary.total_rules} />
                          </Card>
                        </Col>
                        <Col span={6}>
                          <Card size="small">
                            <Statistic
                              title="本策略生效"
                              value={contentQuery.data.summary.active_rules}
                              valueStyle={{ color: '#389e0d' }}
                            />
                          </Card>
                        </Col>
                        <Col span={6}>
                          <Card size="small">
                            <Statistic
                              title="规则覆盖停用"
                              value={contentQuery.data.summary.disabled_by_override}
                              valueStyle={{ color: '#cf1322' }}
                            />
                          </Card>
                        </Col>
                        <Col span={6}>
                          <Card size="small">
                            <Statistic
                              title={`高于 PL${contentQuery.data.paranoia_level} 未启用`}
                              value={contentQuery.data.summary.skipped_by_pl}
                            />
                          </Card>
                        </Col>
                      </Row>
                    )}

                    <Space wrap>
                      <Input.Search
                        placeholder="按规则ID、名称或文件名搜索"
                        allowClear
                        style={{ width: 260 }}
                        onSearch={(v) => {
                          setRuleKeyword(v || undefined)
                          setRulePage(1)
                        }}
                      />
                      <Select
                        placeholder="生效状态"
                        allowClear
                        style={{ width: 150 }}
                        value={ruleStatus}
                        options={EFFECTIVE_STATUS_OPTIONS}
                        onChange={(v) => {
                          setRuleStatus(v)
                          setRulePage(1)
                        }}
                      />
                    </Space>

                    <Table<ProtectionPolicyEffectiveRuleItem>
                      rowKey="rule_id"
                      size="small"
                      loading={contentQuery.isLoading}
                      dataSource={contentQuery.data?.rules ?? []}
                      expandable={{
                        expandedRowRender: (rec) =>
                          rec.raw_rule ? (
                            <pre
                              style={{
                                margin: 0,
                                maxHeight: 240,
                                overflow: 'auto',
                                background: '#f5f5f5',
                                padding: 10,
                                borderRadius: 6,
                                fontSize: 12,
                                fontFamily: 'monospace',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-all',
                              }}
                            >
                              {rec.raw_rule}
                            </pre>
                          ) : (
                            <Typography.Text type="secondary">
                              暂未读取到原始 SecRule 原文，请先在「防护规则库」同步 CRS 规则。
                            </Typography.Text>
                          ),
                      }}
                      columns={[
                        {
                          title: '规则ID',
                          dataIndex: 'rule_id',
                          width: 96,
                          render: (v: number) => <Typography.Text code>{v}</Typography.Text>,
                        },
                        {
                          title: '名称',
                          dataIndex: 'name',
                          ellipsis: true,
                        },
                        {
                          title: '攻击类型',
                          dataIndex: 'attack_type',
                          width: 125,
                          render: (v: string) => <StatusTag value={v} map={ATTACK_TYPE_META} />,
                        },
                        {
                          title: '等级',
                          dataIndex: 'paranoia_level',
                          width: 72,
                          render: (v: number) => (v > 0 ? <Tag>{`PL${v}`}</Tag> : <Tag>通用</Tag>),
                        },
                        {
                          title: '来源',
                          dataIndex: 'rule_source',
                          width: 110,
                          render: (v: string) => <StatusTag value={v} map={RULE_SOURCE_META} />,
                        },
                        {
                          title: '状态',
                          dataIndex: 'effective_status',
                          width: 100,
                          render: (v: string) => (
                            <StatusTag value={v} map={EFFECTIVE_RULE_STATUS_META} />
                          ),
                        },
                      ]}
                      pagination={{
                        current: rulePage,
                        pageSize: rulePageSize,
                        total: contentQuery.data?.rules_total ?? 0,
                        showSizeChanger: true,
                        showTotal: (t) => `共 ${t} 条（点击行首 + 展开原始 SecRule）`,
                        onChange: (p, ps) => {
                          setRulePage(p)
                          setRulePageSize(ps)
                        },
                      }}
                    />
                  </Space>
                ),
              },
            ]}
          />
        ) : null}
      </Drawer>
    </Card>
  )
}
