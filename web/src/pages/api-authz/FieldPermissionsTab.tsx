import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Checkbox, Form, Input, Modal, Select, Space, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import { apiAuthzApi, type ApiFieldPermission, type ApiFieldPermissionBody } from '../../api/apiAuthz'
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
import { API_FIELD_ATTRIBUTE_META, API_FIELD_DIRECTION_META } from './meta'

interface FieldPermFormValues {
  endpoint_id: string
  field_path: string
  direction: string
  attribute: string
  role?: string
  tenant?: string
}

/** 字段权限（Mass Assignment / 字段越权）：role/tenant 留空 = 默认行，填写 = 角色/租户覆盖行 */
export default function FieldPermissionsTab() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_authorization.manage')

  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [direction, setDirection] = useState<string | undefined>()
  const [attribute, setAttribute] = useState<string | undefined>()
  const [defaultsOnly, setDefaultsOnly] = useState(false)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editing, setEditing] = useState<ApiFieldPermission | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<ApiFieldPermission | null>(null)
  const [form] = Form.useForm<FieldPermFormValues>()

  const modalOpen = createOpen || editing !== null
  const { labelOf } = useEndpointOptions()

  const listQuery = useQuery({
    queryKey: ['api-authz', 'field-permissions', endpointId, direction, attribute, defaultsOnly, page, pageSize],
    queryFn: () =>
      apiAuthzApi.listFieldPermissions({
        endpoint_id: endpointId,
        direction,
        attribute,
        defaults_only: defaultsOnly || undefined,
        page,
        page_size: pageSize,
      }),
  })

  const invalidate = () => void qc.invalidateQueries({ queryKey: ['api-authz', 'field-permissions'] })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ApiFieldPermission>({
    remove: (id) => apiAuthzApi.deleteFieldPermission(id),
    invalidateKeys: [['api-authz', 'field-permissions']],
    entityName: '字段权限',
    canDelete: canManage,
  })

  const createMut = useMutation({
    mutationFn: (body: ApiFieldPermissionBody) => apiAuthzApi.createFieldPermission(body),
    onSuccess: () => {
      message.success('已创建')
      setCreateOpen(false)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const updateMut = useMutation({
    mutationFn: (vars: { id: string; body: ApiFieldPermissionBody }) =>
      apiAuthzApi.updateFieldPermission(vars.id, vars.body),
    onSuccess: () => {
      message.success('已保存')
      setEditing(null)
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '保存失败'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiAuthzApi.deleteFieldPermission(id),
    onSuccess: (r) => {
      message.success(r.message || '已删除')
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '删除失败'),
  })

  const openCreate = () => {
    form.resetFields()
    setCreateOpen(true)
  }

  const openEdit = (record: ApiFieldPermission) => {
    setEditing(record)
    form.resetFields()
    form.setFieldsValue({
      endpoint_id: record.endpoint_id,
      field_path: record.field_path,
      direction: record.direction,
      attribute: record.attribute,
      role: record.role ?? undefined,
      tenant: record.tenant ?? undefined,
    })
  }

  const handleSubmit = (v: FieldPermFormValues) => {
    // role/tenant 显式传空串 = 服务端清除为 NULL（回到默认行语义）
    const body: ApiFieldPermissionBody = {
      field_path: v.field_path.trim(),
      direction: v.direction,
      attribute: v.attribute,
      role: v.role?.trim() ?? '',
      tenant: v.tenant?.trim() ?? '',
    }
    if (editing) {
      updateMut.mutate({ id: editing.id, body })
    } else {
      createMut.mutate({ ...body, endpoint_id: v.endpoint_id })
    }
  }

  const confirmDelete = (record: ApiFieldPermission) => {
    modal.confirm({
      title: '删除字段权限',
      content: `确定删除字段「${record.field_path}」的${API_FIELD_DIRECTION_META[record.direction]?.label ?? record.direction}权限吗？删除后不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMut.mutate(record.id),
    })
  }

  /** role/tenant 列：NULL = 默认行（对该字段全部角色/租户生效） */
  const renderOverride = (v?: string | null) =>
    v ? <Typography.Text code>{v}</Typography.Text> : <Tag>默认</Tag>

  const columns: ColumnsType<ApiFieldPermission> = [
    {
      title: '接口',
      dataIndex: 'endpoint_id',
      width: 200,
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
    {
      title: '字段路径',
      dataIndex: 'field_path',
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '方向',
      dataIndex: 'direction',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={API_FIELD_DIRECTION_META} />,
    },
    {
      title: '属性',
      dataIndex: 'attribute',
      width: 130,
      render: (v: string) => <StatusTag value={v} map={API_FIELD_ATTRIBUTE_META} />,
    },
    { title: '角色', dataIndex: 'role', width: 110, render: renderOverride },
    { title: '租户', dataIndex: 'tenant', width: 110, render: renderOverride },
    {
      title: '创建人',
      dataIndex: 'created_by',
      width: 100,
      render: (v?: string | null) => v || '-',
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
      width: 130,
      fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => openEdit(record)}>
              编辑
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
      <Typography.Paragraph type="secondary">
        角色/租户留空的行即默认行：对该字段的全部角色/租户生效；填写后成为覆盖行，优先级高于默认行。
      </Typography.Paragraph>
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
        <Select
          placeholder="方向"
          allowClear
          style={{ width: 120 }}
          value={direction}
          options={Object.entries(API_FIELD_DIRECTION_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setDirection(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="属性"
          allowClear
          style={{ width: 150 }}
          value={attribute}
          options={Object.entries(API_FIELD_ATTRIBUTE_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setAttribute(v)
            setPage(1)
          }}
        />
        <Checkbox
          checked={defaultsOnly}
          onChange={(e) => {
            setDefaultsOnly(e.target.checked)
            setPage(1)
          }}
        >
          仅默认行
        </Checkbox>
        {canManage ? (
          <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
            新建字段权限
          </Button>
        ) : null}
        {batchDeleteButton}
      </Space>
      <QueryErrorAlert error={listQuery.error} />
      <SmartTable<ApiFieldPermission>
        storageKey="api-authz-field-permissions"
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
        title={editing ? '编辑字段权限' : '新建字段权限'}
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
        <Form<FieldPermFormValues>
          form={form}
          layout="vertical"
          initialValues={{ direction: 'REQUEST', attribute: 'READABLE' }}
          onFinish={handleSubmit}
        >
          <Form.Item name="endpoint_id" label="接口" rules={[{ required: true, message: '请选择接口' }]}>
            <EndpointSelect disabled={!!editing} placeholder={editing ? '接口不可变更' : '选择接口'} />
          </Form.Item>
          <Form.Item
            name="field_path"
            label="字段路径"
            rules={[
              { required: true, message: '请填写字段路径' },
              { max: 512, message: '字段路径不超过 512 字符' },
            ]}
          >
            <Input placeholder="点路径，如 user.phone、users[].id" style={{ fontFamily: 'monospace' }} autoComplete="off" />
          </Form.Item>
          <Space.Compact block>
            <Form.Item name="direction" label="方向" style={{ width: '50%', marginRight: 8 }} rules={[{ required: true, message: '请选择方向' }]}>
              <Select
                options={Object.entries(API_FIELD_DIRECTION_META).map(([value, meta]) => ({
                  value,
                  label: `${meta.label}（${value}）`,
                }))}
              />
            </Form.Item>
            <Form.Item name="attribute" label="属性" style={{ width: '50%' }} rules={[{ required: true, message: '请选择属性' }]}>
              <Select
                options={Object.entries(API_FIELD_ATTRIBUTE_META).map(([value, meta]) => ({
                  value,
                  label: `${meta.label}（${value}）`,
                }))}
              />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="role" label="角色码（可选）" extra="留空 = 默认行，对该字段全部角色生效" rules={[{ max: 64, message: '角色码不超过 64 字符' }]}>
            <Input placeholder="如 admin" autoComplete="off" />
          </Form.Item>
          <Form.Item name="tenant" label="租户码（可选）" extra="留空 = 默认行，对该字段全部租户生效" rules={[{ max: 64, message: '租户码不超过 64 字符' }]}>
            <Input placeholder="如 tenant-a" autoComplete="off" />
          </Form.Item>
        </Form>
      </Modal>
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="字段权限详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
