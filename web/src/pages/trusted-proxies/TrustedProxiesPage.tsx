import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Tabs,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ExperimentOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { trustedProxiesApi } from '../../api/trustedProxies'
import { protectedAddressesApi } from '../../api/protectedAddresses'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  CUSTOM_HEADER_NAME_PATTERN,
  IP_VERSION_META,
  PROTECTED_ADDRESS_SOURCE_META,
  PROTECTED_ADDRESS_TYPE_META,
  TRUSTED_PROXY_HEADER_TYPE_META,
  TRUSTED_PROXY_SCOPE_META,
  isValidIPLiteral,
  validateIPOrCIDR,
} from '../../utils/stage5'
import { ENABLE_STATUS_META } from '../../utils/stage4'
import type { ProtectedAddressItem, TrustedProxyItem, TrustedProxyTestResult } from '../../types'

interface ProxyFilters {
  keyword?: string
  status?: string
  header_type?: string
}

interface ProxyFormValues {
  name: string
  cidr: string
  header_type: string
  custom_header_name?: string
  priority: number
  scope: string
  node_name?: string
  description?: string
}

interface TestFormValues {
  cidr: string
  test_ips: string[]
}

const HEADER_TYPE_OPTIONS = Object.entries(TRUSTED_PROXY_HEADER_TYPE_META).map(([value, meta]) => ({
  value,
  label: `${meta.label}（${value}）`,
}))

const SCOPE_OPTIONS = Object.entries(TRUSTED_PROXY_SCOPE_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

/** 可信代理列表 + 新建/编辑抽屉 + 命中测试 */
function TrustedProxyPanel() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'trusted_proxies.manage')

  const [filters, setFilters] = useState<ProxyFilters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<TrustedProxyItem | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [testOpen, setTestOpen] = useState(false)
  const [testResult, setTestResult] = useState<TrustedProxyTestResult | null>(null)
  const [detailRecord, setDetailRecord] = useState<TrustedProxyItem | null>(null)
  const [testDetailRecord, setTestDetailRecord] = useState<
    TrustedProxyTestResult['results'][number] | null
  >(null)
  const [form] = Form.useForm<ProxyFormValues>()
  const [testForm] = Form.useForm<TestFormValues>()

  const listQuery = useQuery({
    queryKey: ['trusted-proxies', filters, page, pageSize],
    queryFn: () => trustedProxiesApi.list({ ...filters, page, page_size: pageSize }),
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<TrustedProxyItem>({
    remove: (id) => trustedProxiesApi.remove(id),
    invalidateKeys: [['trusted-proxies']],
    entityName: '可信代理',
    canDelete: canManage,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['trusted-proxies'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveMutation = useMutation({
    mutationFn: (values: ProxyFormValues) => {
      const body = {
        name: values.name,
        cidr: values.cidr,
        header_type: values.header_type,
        custom_header_name: values.header_type === 'CUSTOM' ? (values.custom_header_name ?? '') : '',
        priority: values.priority,
        scope: values.scope,
        node_name: values.scope === 'NODE' ? (values.node_name ?? '') : '',
        description: values.description ?? '',
      }
      return editing
        ? trustedProxiesApi.update(editing.id, { ...body, version: editing.version })
        : trustedProxiesApi.create(body)
    },
    onSuccess: () => {
      message.success(editing ? '可信代理已更新' : '可信代理已创建')
      setFormOpen(false)
      setEditing(null)
      form.resetFields()
      void invalidate()
    },
    onError,
  })

  const statusMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'enable' | 'disable' }) =>
      action === 'enable' ? trustedProxiesApi.enable(id) : trustedProxiesApi.disable(id),
    onSuccess: () => {
      message.success('操作成功')
      void invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => trustedProxiesApi.remove(id),
    onSuccess: () => {
      message.success('可信代理已删除')
      void invalidate()
    },
    onError,
  })

  const testMutation = useMutation({
    mutationFn: (values: TestFormValues) =>
      trustedProxiesApi.test({ cidr: values.cidr, test_ips: values.test_ips }),
    onSuccess: (data) => setTestResult(data),
    onError: (e) => {
      setTestResult(null)
      onError(e)
    },
  })

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    setFormOpen(true)
  }

  const openEdit = (record: TrustedProxyItem) => {
    setEditing(record)
    form.setFieldsValue({
      name: record.name,
      cidr: record.cidr,
      header_type: record.header_type,
      custom_header_name: record.custom_header_name || undefined,
      priority: record.priority,
      scope: record.scope,
      node_name: record.node_name || undefined,
      description: record.description || undefined,
    })
    setFormOpen(true)
  }

  const confirmDelete = (record: TrustedProxyItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除可信代理「${record.name}」（${record.cidr}）吗？删除后该代理的转发头将不再被信任，可能影响真实客户端 IP 识别。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<TrustedProxyItem> = [
    { title: '名称', dataIndex: 'name', width: 160, ellipsis: true },
    {
      title: '网段（CIDR）',
      dataIndex: 'cidr',
      width: 150,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: 'IP 版本',
      dataIndex: 'ip_version',
      width: 80,
      render: (v: string) => <StatusTag value={v} map={IP_VERSION_META} />,
    },
    {
      title: '头类型',
      dataIndex: 'header_type',
      width: 150,
      render: (v: string, record) => (
        <Space size={4}>
          <StatusTag value={v} map={TRUSTED_PROXY_HEADER_TYPE_META} />
          {v === 'CUSTOM' && record.custom_header_name && (
            <Typography.Text code>{record.custom_header_name}</Typography.Text>
          )}
        </Space>
      ),
    },
    { title: '优先级', dataIndex: 'priority', width: 80 },
    {
      title: '范围',
      dataIndex: 'scope',
      width: 120,
      render: (v: string, record) => (
        <Space size={4}>
          <StatusTag value={v} map={TRUSTED_PROXY_SCOPE_META} />
          {v === 'NODE' && <Typography.Text type="secondary">{record.node_name}</Typography.Text>}
        </Space>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ENABLE_STATUS_META} />,
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 170,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          {canManage && (
            <>
              <Button type="link" size="small" onClick={() => openEdit(record)}>
                编辑
              </Button>
              {record.status === 'ENABLED' ? (
                <Button
                  type="link"
                  size="small"
                  onClick={() => statusMutation.mutate({ id: record.id, action: 'disable' })}
                >
                  停用
                </Button>
              ) : (
                <Button
                  type="link"
                  size="small"
                  onClick={() => statusMutation.mutate({ id: record.id, action: 'enable' })}
                >
                  启用
                </Button>
              )}
              <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
                删除
              </Button>
            </>
          )}
        </Space>
      ),
    },
  ]

  return (
    <>
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="名称 / 网段"
          allowClear
          style={{ width: 200 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, keyword: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="头类型"
          allowClear
          style={{ width: 200 }}
          options={HEADER_TYPE_OPTIONS}
          onChange={(v) => {
            setFilters((f) => ({ ...f, header_type: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 130 }}
          options={Object.entries(ENABLE_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, status: v }))
            setPage(1)
          }}
        />
        <Button icon={<ExperimentOutlined />} onClick={() => setTestOpen(true)}>
          命中测试
        </Button>
        {canManage && (
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            新建可信代理
          </Button>
        )}
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载可信代理失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<TrustedProxyItem>
          storageKey="trusted-proxies"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1250 }}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
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

      <Drawer
        title={editing ? '编辑可信代理' : '新建可信代理'}
        open={formOpen}
        onClose={() => {
          setFormOpen(false)
          setEditing(null)
        }}
        width={520}
        destroyOnHidden
        footer={
          <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button onClick={() => setFormOpen(false)}>取消</Button>
            <Button type="primary" loading={saveMutation.isPending} onClick={() => form.submit()}>
              {editing ? '保存' : '创建'}
            </Button>
          </Space>
        }
      >
        <Form<ProxyFormValues>
          form={form}
          layout="vertical"
          initialValues={{ header_type: 'X_FORWARDED_FOR', priority: 100, scope: 'GLOBAL' }}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Form.Item
            name="name"
            label="名称"
            rules={[
              { required: true, message: '请输入名称' },
              { max: 100, message: '不超过 100 个字符' },
            ]}
          >
            <Input placeholder="如：办公网出口代理" />
          </Form.Item>
          <Form.Item
            name="cidr"
            label="代理地址（单 IP 或 CIDR）"
            rules={[
              { required: true, message: '请输入代理地址' },
              {
                validator: (_, v: string) => {
                  const err = validateIPOrCIDR(v ?? '')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
            extra="禁止域名、协议前缀与端口；CIDR 将由后端掩码化规范化"
          >
            <Input placeholder="如 10.0.0.0/8 或 203.0.113.10" autoComplete="off" />
          </Form.Item>
          <Form.Item name="header_type" label="真实 IP 提取头" rules={[{ required: true }]}>
            <Select options={HEADER_TYPE_OPTIONS} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.header_type !== cur.header_type}>
            {({ getFieldValue }) =>
              getFieldValue('header_type') === 'CUSTOM' && (
                <Form.Item
                  name="custom_header_name"
                  label="自定义头名"
                  rules={[
                    { required: true, message: '自定义头类型必须填写头名' },
                    { max: 64, message: '不超过 64 个字符' },
                    {
                      pattern: CUSTOM_HEADER_NAME_PATTERN,
                      message: '仅允许字母、数字、点、下划线、连字符',
                    },
                  ]}
                >
                  <Input placeholder="如自定义客户端 IP 头名称" autoComplete="off" />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item
            name="priority"
            label="优先级（数值小者优先）"
            rules={[{ required: true, message: '请输入优先级' }]}
          >
            <InputNumber min={0} max={10000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="scope" label="生效范围" rules={[{ required: true }]}>
            <Radio.Group options={SCOPE_OPTIONS} optionType="button" />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.scope !== cur.scope}>
            {({ getFieldValue }) =>
              getFieldValue('scope') === 'NODE' && (
                <Form.Item
                  name="node_name"
                  label="节点名称"
                  rules={[
                    { required: true, message: '节点级可信代理必须指定节点名称' },
                    { max: 100, message: '不超过 100 个字符' },
                  ]}
                >
                  <Input placeholder="网关节点名称" autoComplete="off" />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item name="description" label="描述" rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} placeholder="用途说明（可选）" />
          </Form.Item>
        </Form>
      </Drawer>

      <Modal
        title="可信代理命中测试"
        open={testOpen}
        onCancel={() => {
          setTestOpen(false)
          setTestResult(null)
          testForm.resetFields()
        }}
        footer={null}
        width={720}
        destroyOnHidden
      >
        <Form<TestFormValues>
          form={testForm}
          layout="vertical"
          onFinish={(values) => testMutation.mutate(values)}
        >
          <Form.Item
            name="cidr"
            label="待测 CIDR"
            rules={[
              { required: true, message: '请输入待测网段' },
              {
                validator: (_, v: string) => {
                  const err = validateIPOrCIDR(v ?? '')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
          >
            <Input placeholder="如 10.0.0.0/8" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="test_ips"
            label="测试 IP（回车添加，1-100 个）"
            rules={[
              { required: true, message: '请至少输入一个测试 IP' },
              {
                validator: (_, v: string[] | undefined) => {
                  const ips = v ?? []
                  if (ips.length === 0 || ips.length > 100) {
                    return Promise.reject(new Error('测试IP数量必须在 1-100 之间'))
                  }
                  const invalid = ips.filter((ip) => !isValidIPLiteral(ip))
                  return invalid.length > 0
                    ? Promise.reject(new Error(`无效的IP：${invalid.join('、')}`))
                    : Promise.resolve()
                },
              },
            ]}
          >
            <Select mode="tags" open={false} placeholder="输入 IP 后回车，如 10.1.2.3" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={testMutation.isPending}>
            开始测试
          </Button>
        </Form>

        {testResult && (
          <SmartTable
            storageKey="trusted-proxies-test-result"
            style={{ marginTop: 16 }}
            rowKey="ip"
            size="small"
            pagination={false}
            dataSource={testResult.results}
            onRow={(record) => ({
              onDoubleClick: () => setTestDetailRecord(record),
              style: { cursor: 'pointer' },
            })}
            columns={[
              { title: '测试IP', dataIndex: 'ip', width: 140 },
              {
                title: '合法性',
                dataIndex: 'valid',
                width: 80,
                render: (v: boolean) =>
                  v ? <Tag color="green">合法</Tag> : <Tag color="red">非法</Tag>,
              },
              {
                title: `命中 ${testResult.cidr}`,
                dataIndex: 'matched',
                width: 130,
                render: (v: boolean, record) =>
                  !record.valid ? '-' : v ? <Tag color="green">命中</Tag> : <Tag>未命中</Tag>,
              },
              {
                title: '命中的已启用代理',
                dataIndex: 'matched_proxies',
                render: (v: TrustedProxyTestResult['results'][number]['matched_proxies']) =>
                  v.length === 0 ? (
                    '-'
                  ) : (
                    <Space wrap size={4}>
                      {v.map((p) => (
                        <Tag key={p.id} color="blue">
                          {p.name}（{p.cidr}）
                        </Tag>
                      ))}
                    </Space>
                  ),
              },
            ]}
          />
        )}
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="可信代理详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
      <RecordDetailDrawer
        open={testDetailRecord !== null}
        title="测试结果详情"
        record={testDetailRecord as Record<string, unknown> | null}
        onClose={() => setTestDetailRecord(null)}
      />
    </>
  )
}

interface AddressFormValues {
  name: string
  target: string
  description?: string
}

/** 保护地址面板：只读列表 + 新增自定义 + 删除（仅 MANUAL）+ 刷新 */
function ProtectedAddressPanel() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'protected_addresses.manage')

  const [addressType, setAddressType] = useState<string | undefined>(undefined)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<ProtectedAddressItem | null>(null)
  const [form] = Form.useForm<AddressFormValues>()

  const listQuery = useQuery({
    queryKey: ['protected-addresses', addressType, page, pageSize],
    queryFn: () => protectedAddressesApi.list({ address_type: addressType, page, page_size: pageSize }),
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ProtectedAddressItem>({
    remove: (id) => protectedAddressesApi.remove(id),
    invalidateKeys: [['protected-addresses']],
    entityName: '保护地址',
    canDelete: canManage,
    // 系统登记地址不可删除（后端 409），与行内删除按钮显隐口径一致
    rowDisabled: (record) => record.source_type !== 'MANUAL',
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['protected-addresses'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (values: AddressFormValues) => {
      const target = values.target.trim()
      // 与后端约定一致：address 与 cidr 必须且只能填写一个
      const body = target.includes('/')
        ? { name: values.name, cidr: target, description: values.description ?? '' }
        : { name: values.name, address: target, description: values.description ?? '' }
      return protectedAddressesApi.create(body)
    },
    onSuccess: () => {
      message.success('自定义保护地址已添加')
      setCreateOpen(false)
      form.resetFields()
      void invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => protectedAddressesApi.remove(id),
    onSuccess: () => {
      message.success('保护地址已删除')
      void invalidate()
    },
    onError,
  })

  const refreshMutation = useMutation({
    mutationFn: () => protectedAddressesApi.refresh(),
    onSuccess: (data) => {
      message.success(`刷新完成：新增 ${data.added} 条，跳过已存在 ${data.skipped} 条`)
      void invalidate()
    },
    onError,
  })

  const confirmDelete = (record: ProtectedAddressItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除保护地址「${record.name}」（${record.address || record.cidr}）吗？删除后该地址可被加入黑名单。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<ProtectedAddressItem> = [
    { title: '名称', dataIndex: 'name', width: 180, ellipsis: true },
    {
      title: '地址',
      key: 'target',
      width: 170,
      render: (_, record) => <Typography.Text code>{record.address || record.cidr}</Typography.Text>,
    },
    {
      title: '类型',
      dataIndex: 'address_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={PROTECTED_ADDRESS_TYPE_META} />,
    },
    {
      title: '来源',
      dataIndex: 'source_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={PROTECTED_ADDRESS_SOURCE_META} />,
    },
    {
      title: '描述',
      dataIndex: 'description',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) =>
        canManage && record.source_type === 'MANUAL' ? (
          <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
            删除
          </Button>
        ) : null,
    },
  ]

  return (
    <>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="保护地址用于防止网关/管理面/源站等关键地址被误加入黑名单。系统地址自动登记，不可删除；黑名单规则命中保护地址时将被后端拒绝。"
      />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="地址类型"
          allowClear
          style={{ width: 150 }}
          options={Object.entries(PROTECTED_ADDRESS_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setAddressType(v)
            setPage(1)
          }}
        />
        {canManage && (
          <>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => {
                form.resetFields()
                setCreateOpen(true)
              }}
            >
              新增自定义
            </Button>
            <Button
              icon={<ReloadOutlined />}
              loading={refreshMutation.isPending}
              onClick={() => refreshMutation.mutate()}
            >
              刷新系统地址
            </Button>
          </>
        )}
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载保护地址失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<ProtectedAddressItem>
          storageKey="trusted-proxies-protected-addresses"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1050 }}
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
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
        />
      )}

      <Modal
        title="新增自定义保护地址"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={createMutation.isPending}
        destroyOnHidden
      >
        <Form<AddressFormValues>
          form={form}
          layout="vertical"
          onFinish={(values) => createMutation.mutate(values)}
        >
          <Form.Item
            name="name"
            label="名称"
            rules={[
              { required: true, message: '请输入名称' },
              { max: 100, message: '不超过 100 个字符' },
            ]}
          >
            <Input placeholder="如：运维跳板机" />
          </Form.Item>
          <Form.Item
            name="target"
            label="地址（单 IP 或 CIDR）"
            rules={[
              { required: true, message: '请输入地址' },
              {
                validator: (_, v: string) => {
                  const err = validateIPOrCIDR(v ?? '')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
          >
            <Input placeholder="如 192.168.10.5 或 192.168.10.0/24" autoComplete="off" />
          </Form.Item>
          <Form.Item name="description" label="描述" rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} placeholder="用途说明（可选）" />
          </Form.Item>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="保护地址详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}

export default function TrustedProxiesPage() {
  const [tab, setTab] = useState('proxies')

  return (
    <Card title="可信代理">
      <Tabs
        activeKey={tab}
        onChange={setTab}
        items={[
          { key: 'proxies', label: '可信代理', children: <TrustedProxyPanel /> },
          { key: 'protected', label: '保护地址', children: <ProtectedAddressPanel /> },
        ]}
      />
    </Card>
  )
}
