import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Dropdown,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Tag,
} from 'antd'
import type { MenuProps } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import SmartTable from '../../components/SmartTable'
import { DownOutlined, PlusOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { rolesApi } from '../../api/roles'
import { usersApi } from '../../api/users'
import type { CreateUserBody } from '../../api/users'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import TempPasswordModal from '../../components/TempPasswordModal'
import UserStatusTag from '../../components/UserStatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type { UserItem } from '../../types'

interface Filters {
  username?: string
  status?: string
  role_code?: string
}

function isLocked(record: UserItem): boolean {
  return (
    record.status === 'LOCKED' ||
    Boolean(record.locked_until && dayjs(record.locked_until).isAfter(dayjs()))
  )
}

export default function UsersPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const currentUserId = useAuthStore((s) => s.user?.id)

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [editing, setEditing] = useState<UserItem | null>(null)
  const [detailRecord, setDetailRecord] = useState<UserItem | null>(null)
  const [tempPassword, setTempPassword] = useState<{ password: string; notice?: string } | null>(null)
  const [createForm] = Form.useForm<CreateUserBody>()
  const [editForm] = Form.useForm<{ display_name: string; role_code: string }>()

  const listQuery = useQuery({
    queryKey: ['users', filters, page, pageSize],
    queryFn: () => usersApi.list({ ...filters, page, page_size: pageSize }),
  })
  const rolesQuery = useQuery({ queryKey: ['roles'], queryFn: rolesApi.list })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['users'] })

  const { rowSelection, batchDeleteButton } = useBatchDelete<UserItem>({
    remove: usersApi.remove,
    invalidateKeys: [['users']],
    entityName: '用户',
    canDelete: hasPermission(permissions, 'users.update'),
  })

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
      message.error('数据已被他人修改，请刷新列表后重试')
      void invalidate()
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  type SimpleAction = 'enable' | 'disable' | 'unlock' | 'force_logout' | 'delete'
  const simpleAction = useMutation({
    mutationFn: ({ id, action }: { id: string; action: SimpleAction }) => {
      const map: Record<SimpleAction, (id: string) => Promise<unknown>> = {
        enable: usersApi.enable,
        disable: usersApi.disable,
        unlock: usersApi.unlock,
        force_logout: usersApi.forceLogout,
        delete: usersApi.remove,
      }
      return map[action](id)
    },
    onSuccess: () => {
      message.success('操作成功')
      void invalidate()
    },
    onError,
  })

  const resetMutation = useMutation({
    mutationFn: (id: string) => usersApi.resetPassword(id),
    onSuccess: (data) => {
      setTempPassword({ password: data.temporary_password, notice: data.notice })
      void invalidate()
    },
    onError,
  })

  const createMutation = useMutation({
    mutationFn: (body: CreateUserBody) => usersApi.create(body),
    onSuccess: (data) => {
      setCreateOpen(false)
      createForm.resetFields()
      setTempPassword({ password: data.temporary_password, notice: data.notice })
      void invalidate()
    },
    onError,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: { display_name: string; role_code: string; version: number } }) =>
      usersApi.update(id, body),
    onSuccess: () => {
      setEditing(null)
      message.success('保存成功')
      void invalidate()
    },
    onError,
  })

  const runAction = (action: SimpleAction | 'reset_password', record: UserItem) => {
    const exec = () => {
      if (action === 'reset_password') resetMutation.mutate(record.id)
      else simpleAction.mutate({ id: record.id, action })
    }
    const confirms: Partial<Record<typeof action, string>> = {
      disable: `确定停用用户「${record.username}」吗？停用后该用户将无法登录。`,
      delete: `确定删除用户「${record.username}」吗？删除后不可恢复。`,
      force_logout: `确定强制用户「${record.username}」下线吗？该用户的全部会话将被结束。`,
      reset_password: `确定重置用户「${record.username}」的密码吗？将生成新的临时密码。`,
    }
    const text = confirms[action]
    if (text) {
      modal.confirm({
        title: '操作确认',
        content: text,
        okButtonProps: action === 'delete' || action === 'disable' ? { danger: true } : undefined,
        onOk: exec,
      })
    } else {
      exec()
    }
  }

  const actionMenuItems = (record: UserItem): NonNullable<MenuProps['items']> => {
    const items: NonNullable<MenuProps['items']> = []
    const locked = isLocked(record)
    if (hasPermission(permissions, 'users.disable')) {
      if (record.status === 'ACTIVE') items.push({ key: 'disable', label: '停用', danger: true })
      if (record.status === 'DISABLED') items.push({ key: 'enable', label: '启用' })
    }
    if (locked && hasPermission(permissions, 'users.unlock')) {
      items.push({ key: 'unlock', label: '解锁' })
    }
    if (hasPermission(permissions, 'users.reset_password')) {
      items.push({ key: 'reset_password', label: '重置密码' })
    }
    if (hasPermission(permissions, 'users.force_logout')) {
      items.push({ key: 'force_logout', label: '强制下线' })
    }
    if (hasPermission(permissions, 'users.update') && record.id !== currentUserId) {
      items.push({ type: 'divider' }, { key: 'delete', label: '删除', danger: true })
    }
    return items
  }

  const columns: ColumnsType<UserItem> = [
    { title: '用户名', dataIndex: 'username', width: 140 },
    { title: '显示名', dataIndex: 'display_name', width: 140 },
    {
      title: '角色',
      dataIndex: 'roles',
      width: 160,
      render: (roles: UserItem['roles']) => (
        <Space wrap>
          {roles.map((r) => (
            <Tag color="blue" key={r.code}>
              {r.name}
            </Tag>
          ))}
        </Space>
      ),
    },
    {
      title: '状态',
      key: 'status',
      width: 100,
      render: (_, record) => <UserStatusTag status={record.status} lockedUntil={record.locked_until} />,
    },
    {
      title: '上次登录',
      key: 'last_login',
      width: 200,
      render: (_, record) => (
        <span>
          {formatDateTime(record.last_login_at)}
          {record.last_login_ip ? ` / ${record.last_login_ip}` : ''}
        </span>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 160,
      fixed: 'right',
      render: (_, record) => {
        const menuItems = actionMenuItems(record)
        return (
          <Space>
            {hasPermission(permissions, 'users.update') && (
              <Button
                type="link"
                size="small"
                onClick={() => {
                  setEditing(record)
                  editForm.setFieldsValue({
                    display_name: record.display_name,
                    role_code: record.roles[0]?.code,
                  })
                }}
              >
                编辑
              </Button>
            )}
            {menuItems.length > 0 && (
              <Dropdown
                menu={{
                  items: menuItems,
                  onClick: ({ key }) => runAction(key as SimpleAction | 'reset_password', record),
                }}
              >
                <Button type="link" size="small">
                  更多 <DownOutlined />
                </Button>
              </Dropdown>
            )}
          </Space>
        )
      },
    },
  ]

  return (
    <Card
      title="用户管理"
      extra={
        hasPermission(permissions, 'users.create') && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建用户
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="搜索用户名"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, username: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 140 }}
          options={[
            { value: 'ACTIVE', label: '正常' },
            { value: 'DISABLED', label: '已停用' },
            { value: 'LOCKED', label: '已锁定' },
          ]}
          onChange={(v) => {
            setFilters((f) => ({ ...f, status: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="角色"
          allowClear
          style={{ width: 160 }}
          loading={rolesQuery.isLoading}
          options={rolesQuery.data?.items.map((r) => ({ value: r.code, label: r.name }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, role_code: v }))
            setPage(1)
          }}
        />
        {batchDeleteButton}
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载用户列表失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<UserItem>
          storageKey="users"
          rowKey="id"
          rowSelection={rowSelection}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1100 }}
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

      <Modal
        title="新建用户"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => createForm.submit()}
        confirmLoading={createMutation.isPending}
        destroyOnHidden
      >
        <Form
          form={createForm}
          layout="vertical"
          onFinish={(values) => createMutation.mutate(values)}
        >
          <Form.Item
            name="username"
            label="用户名"
            rules={[
              { required: true, message: '请输入用户名' },
              { pattern: /^[a-zA-Z0-9_.-]{3,64}$/, message: '3-64 位字母、数字、下划线、点或短横线' },
            ]}
          >
            <Input placeholder="登录用户名" autoComplete="off" />
          </Form.Item>
          <Form.Item name="display_name" label="显示名" rules={[{ required: true, message: '请输入显示名' }]}>
            <Input placeholder="用户显示名称" />
          </Form.Item>
          <Form.Item name="role_code" label="角色" rules={[{ required: true, message: '请选择角色' }]}>
            <Select
              placeholder="选择角色"
              loading={rolesQuery.isLoading}
              options={rolesQuery.data?.items.map((r) => ({ value: r.code, label: r.name }))}
            />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={`编辑用户：${editing?.username ?? ''}`}
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
              body: { ...values, version: editing.version },
            })
          }}
        >
          <Form.Item name="display_name" label="显示名" rules={[{ required: true, message: '请输入显示名' }]}>
            <Input placeholder="用户显示名称" />
          </Form.Item>
          <Form.Item name="role_code" label="角色" rules={[{ required: true, message: '请选择角色' }]}>
            <Select
              placeholder="选择角色"
              loading={rolesQuery.isLoading}
              options={rolesQuery.data?.items.map((r) => ({ value: r.code, label: r.name }))}
            />
          </Form.Item>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="用户详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />

      <TempPasswordModal
        open={tempPassword !== null}
        password={tempPassword?.password ?? null}
        notice={tempPassword?.notice}
        onClose={() => setTempPassword(null)}
      />
    </Card>
  )
}
