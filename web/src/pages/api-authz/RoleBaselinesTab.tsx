import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Form, Input, InputNumber, Modal, Select, Space, Switch, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { apiAuthzApi, type ApiRoleBaseline, type ApiRoleBaselineBody } from '../../api/apiAuthz'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import EndpointSelect from './EndpointSelect'
import { useEndpointOptions } from './useEndpointOptions'
import { API_AUTHZ_METHOD_OPTIONS, API_AUTHZ_SOURCE_META } from './meta'

interface BaselineFormValues {
  endpoint_id: string
  role: string
  method: string
  action: string
  allowed: boolean
  source: string
  confidence: number
}

/** 角色基线（BFLA）：角色 × 方法 × 动作 的功能级允许/拒绝基线，候选经人工确认后转正 */
export default function RoleBaselinesTab() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_authorization.manage')

  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [role, setRole] = useState<string | undefined>()
  const [method, setMethod] = useState<string | undefined>()
  const [source, setSource] = useState<string | undefined>()
  const [confirmed, setConfirmed] = useState<boolean | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<ApiRoleBaseline | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<ApiRoleBaseline | null>(null)
  const [form] = Form.useForm<BaselineFormValues>()

  const modalOpen = createOpen || editing !== null
  const { labelOf } = useEndpointOptions()

  const listQuery = useQuery({
    queryKey: ['api-authz', 'role-baselines', endpointId, role, method, source, confirmed, page, pageSize],
    queryFn: () =>
      apiAuthzApi.listRoleBaselines({
        endpoint_id: endpointId,
        role,
        method,
        source,
        confirmed,
        page,
        page_size: pageSize,
      }),
  })

  const invalidate = () => void qc.invalidateQueries({ queryKey: ['api-authz', 'role-baselines'] })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ApiRoleBaseline>({
    remove: (id) => apiAuthzApi.deleteRoleBaseline(id),
    invalidateKeys: [['api-authz', 'role-baselines']],
    entityName: '角色基线',
    canDelete: canManage,
  })

  const createMut = useMutation({
    mutationFn: (body: ApiRoleBaselineBody) => apiAuthzApi.createRoleBaseline(body),
    onSuccess: () => {
      message.success('已创建（候选基线，确认后生效）')
      setCreateOpen(false)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const updateMut = useMutation({
    mutationFn: (vars: { id: string; body: ApiRoleBaselineBody }) => apiAuthzApi.updateRoleBaseline(vars.id, vars.body),
    onSuccess: () => {
      message.success('已保存')
      setEditing(null)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiAuthzApi.deleteRoleBaseline(id),
    onSuccess: (r) => {
      message.success(r.message || '已删除')
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const confirmMut = useMutation({
    mutationFn: (vars: { id: string; confirmed: boolean }) => apiAuthzApi.confirmRoleBaseline(vars.id, vars.confirmed),
    onSuccess: (b) => {
      message.success(b.confirmed ? '已确认为正式基线' : '已撤回确认，回到候选')
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '操作失败'),
  })

  const openCreate = () => {
    form.resetFields()
    setCreateOpen(true)
  }

  const openEdit = (record: ApiRoleBaseline) => {
    setEditing(record)
    form.resetFields()
    form.setFieldsValue({
      endpoint_id: record.endpoint_id,
      role: record.role,
      method: record.method,
      action: record.action,
      allowed: record.allowed,
      source: record.source,
      confidence: record.confidence,
    })
  }

  const handleSubmit = (v: BaselineFormValues) => {
    const body: ApiRoleBaselineBody = {
      role: v.role.trim(),
      method: v.method,
      action: v.action.trim(),
      allowed: v.allowed,
      source: v.source,
      confidence: v.confidence,
    }
    if (editing) {
      // endpoint_id 不可改（换端点 = 删除后重建），编辑仅提交可变字段
      updateMut.mutate({ id: editing.id, body })
    } else {
      createMut.mutate({ ...body, endpoint_id: v.endpoint_id })
    }
  }

  const toggleConfirm = (record: ApiRoleBaseline) => {
    modal.confirm({
      title: record.confirmed ? '撤回确认' : '确认基线',
      content: `确定${record.confirmed ? '撤回' : '确认'}基线「${record.role} ${record.method} ${record.action}」吗？${
        record.confirmed ? '撤回后回到候选状态，不再作为正式基线下发。' : '确认后成为正式基线。'
      }`,
      onOk: () => confirmMut.mutate({ id: record.id, confirmed: !record.confirmed }),
    })
  }

  const confirmDelete = (record: ApiRoleBaseline) => {
    modal.confirm({
      title: '删除基线',
      content: `确定删除基线「${record.role} ${record.method} ${record.action}」吗？删除后不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiRoleBaseline> = [
    {
      title: '接口',
      dataIndex: 'endpoint_id',
      width: 220,
      ellipsis: true,
      render: (v: string) => {
        const label = labelOf(v)
        return (
          <Tooltip title={label ? undefined : v}>
            <Typography.Text code>{label ?? v}</Typography.Text>
          </Tooltip>
        )
      },
    },
    { title: '角色', dataIndex: 'role', width: 130, ellipsis: true },
    { title: '方法', dataIndex: 'method', width: 90 },
    { title: '动作', dataIndex: 'action', width: 130, ellipsis: true },
    {
      title: '判定',
      dataIndex: 'allowed',
      width: 80,
      render: (v: boolean) => (v ? <Tag color="green">允许</Tag> : <Tag color="red">拒绝</Tag>),
    },
    {
      title: '来源',
      dataIndex: 'source',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={API_AUTHZ_SOURCE_META} />,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 90,
      render: (v: number) => (v * 100).toFixed(0) + '%',
    },
    {
      title: '确认',
      dataIndex: 'confirmed',
      width: 90,
      render: (v: boolean) => (v ? <Tag color="green">已确认</Tag> : <Tag color="gold">候选</Tag>),
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
      width: 200,
      fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => openEdit(record)}>
              编辑
            </Button>
            <Button type="link" size="small" onClick={() => toggleConfirm(record)}>
              {record.confirmed ? '撤回' : '确认'}
            </Button>
            <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
              删除
            </Button>
          </Space>
        ) : null,
    },
  ]

  return (
    <>
      <Space style={{ marginBottom: 16 }} wrap>
        <div style={{ width: 260 }}>
          <EndpointSelect
            allowClear
            placeholder="按接口过滤"
            value={endpointId}
            onChange={(v) => {
              setEndpointId(v)
              setPage(1)
            }}
          />
        </div>
        <Input.Search
          placeholder="角色码"
          allowClear
          style={{ width: 180 }}
          onSearch={(v) => {
            setRole(v.trim() || undefined)
            setPage(1)
          }}
        />
        <Select
          placeholder="方法"
          allowClear
          style={{ width: 110 }}
          value={method}
          options={API_AUTHZ_METHOD_OPTIONS}
          onChange={(v) => {
            setMethod(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="来源"
          allowClear
          style={{ width: 130 }}
          value={source}
          options={Object.entries(API_AUTHZ_SOURCE_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setSource(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="确认状态"
          allowClear
          style={{ width: 120 }}
          value={confirmed}
          options={[
            { value: true, label: '已确认' },
            { value: false, label: '候选' },
          ]}
          onChange={(v) => {
            setConfirmed(v)
            setPage(1)
          }}
        />
        {canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            新建基线
          </Button>
        ) : null}
        {batchDeleteButton}
      </Space>
      <QueryErrorAlert error={listQuery.error} />
      <SmartTable<ApiRoleBaseline>
        storageKey="api-authz-role-baselines"
        rowKey="id"
        rowSelection={rowSelection}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1400 }}
        onRow={(record) => ({ onDoubleClick: () => setDetailRecord(record), style: { cursor: 'pointer' } })}
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

      <Modal
        title={editing ? '编辑角色基线' : '新建角色基线'}
        open={modalOpen}
        onCancel={() => {
          setCreateOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        confirmLoading={createMut.isPending || updateMut.isPending}
        width={560}
        destroyOnHidden
      >
        <Form<BaselineFormValues>
          form={form}
          layout="vertical"
          initialValues={{ allowed: true, source: 'MANUAL', confidence: 0 }}
          onFinish={handleSubmit}
        >
          <Form.Item name="endpoint_id" label="接口" rules={[{ required: true, message: '请选择接口' }]}>
            <EndpointSelect disabled={!!editing} placeholder={editing ? '接口不可变更' : '选择接口'} />
          </Form.Item>
          <Form.Item
            name="role"
            label="角色码"
            rules={[
              { required: true, message: '请填写角色码' },
              { max: 64, message: '角色码不超过 64 字符' },
            ]}
          >
            <Input placeholder="如 admin、ops、anonymous" autoComplete="off" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="method" label="HTTP 方法" style={{ width: '50%', marginRight: 8 }} rules={[{ required: true, message: '请选择方法' }]}>
              <Select options={API_AUTHZ_METHOD_OPTIONS} placeholder="方法" />
            </Form.Item>
            <Form.Item
              name="action"
              label="业务动作"
              style={{ width: '50%' }}
              rules={[
                { required: true, message: '请填写业务动作' },
                { max: 64, message: '动作不超过 64 字符' },
              ]}
            >
              <Input placeholder="如 READ、EXPORT（服务端大写归一）" autoComplete="off" />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="allowed" label="判定" valuePropName="checked">
            <Switch checkedChildren="允许" unCheckedChildren="拒绝" />
          </Form.Item>
          <Form.Item name="source" label="来源" rules={[{ required: true, message: '请选择来源' }]}>
            <Select
              options={Object.entries(API_AUTHZ_SOURCE_META).map(([value, meta]) => ({
                value,
                label: `${meta.label}（${value}）`,
              }))}
            />
          </Form.Item>
          <Form.Item name="confidence" label="置信度（0–1）" rules={[{ required: true, message: '请填写置信度' }]}>
            <InputNumber min={0} max={1} step={0.1} style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="角色基线详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
