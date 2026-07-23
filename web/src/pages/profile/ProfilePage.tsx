import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  Modal,
  Popconfirm,
  Space,
  Tabs,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { authApi } from '../../api/auth'
import { profileApi } from '../../api/profile'
import ChangePasswordForm from '../../components/ChangePasswordForm'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import type { LoginLogEntry, SessionItem } from '../../types'

const EVENT_TYPE_LABELS: Record<string, string> = {
  LOGIN_SUCCESS: '登录成功',
  LOGIN_FAILURE: '登录失败',
  CAPTCHA_FAILURE: '验证码错误',
  ACCOUNT_LOCKED: '账号锁定',
  LOGOUT: '登出',
  FORCE_LOGOUT: '强制下线',
  SESSION_EXPIRED: '会话过期',
  PASSWORD_CHANGE: '修改密码',
  PASSWORD_RESET: '重置密码',
  FIRST_CHANGE_PASSWORD: '首次改密',
}

function ProfilePanel() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const updateUser = useAuthStore((s) => s.updateUser)
  const [editOpen, setEditOpen] = useState(false)
  const [form] = Form.useForm<{ display_name: string }>()

  const profileQuery = useQuery({ queryKey: ['profile'], queryFn: profileApi.get })

  const updateMutation = useMutation({
    mutationFn: (body: { display_name: string; version: number }) => profileApi.update(body),
    onSuccess: (data) => {
      message.success('资料已更新')
      setEditOpen(false)
      void queryClient.invalidateQueries({ queryKey: ['profile'] })
      const current = useAuthStore.getState().user
      if (current) updateUser({ ...current, display_name: data.display_name })
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
        message.error('资料已被他人修改，请刷新后重试')
        void queryClient.invalidateQueries({ queryKey: ['profile'] })
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const profile = profileQuery.data
  const permissionGroups = useMemo(() => {
    const map = new Map<string, string[]>()
    for (const code of profile?.permissions ?? []) {
      const module = code.split('.')[0] || 'other'
      const arr = map.get(module) ?? []
      arr.push(code)
      map.set(module, arr)
    }
    return [...map.entries()].sort(([a], [b]) => a.localeCompare(b))
  }, [profile])

  if (profileQuery.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="加载个人资料失败"
        description={profileQuery.error instanceof ApiError ? profileQuery.error.message : undefined}
      />
    )
  }

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card
        title="基本资料"
        loading={profileQuery.isLoading}
        extra={
          <Button
            onClick={() => {
              form.setFieldsValue({ display_name: profile?.display_name ?? '' })
              setEditOpen(true)
            }}
          >
            修改显示名
          </Button>
        }
      >
        {profile && (
          <Descriptions column={2} size="small">
            <Descriptions.Item label="用户名">{profile.username}</Descriptions.Item>
            <Descriptions.Item label="显示名">{profile.display_name}</Descriptions.Item>
            <Descriptions.Item label="账号状态">
              {profile.status === 'ACTIVE' ? <Tag color="green">正常</Tag> : <Tag>{profile.status}</Tag>}
            </Descriptions.Item>
            <Descriptions.Item label="所属角色">
              <Space wrap>
                {profile.roles.map((r) => (
                  <Tag color="blue" key={r.code}>{r.name}</Tag>
                ))}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="上次登录时间">{formatDateTime(profile.last_login_at)}</Descriptions.Item>
            <Descriptions.Item label="上次登录 IP">{profile.last_login_ip || '-'}</Descriptions.Item>
            <Descriptions.Item label="密码到期时间">{formatDateTime(profile.password_expires_at)}</Descriptions.Item>
            <Descriptions.Item label="账号创建时间">{formatDateTime(profile.created_at)}</Descriptions.Item>
          </Descriptions>
        )}
      </Card>

      <Card title="我的权限" loading={profileQuery.isLoading}>
        <Space direction="vertical" style={{ width: '100%' }}>
          {permissionGroups.map(([module, codes]) => (
            <div key={module}>
              <Typography.Text strong>{module}</Typography.Text>
              <div style={{ marginTop: 8 }}>
                <Space wrap>
                  {codes.map((code) => (
                    <Tag key={code}>{code}</Tag>
                  ))}
                </Space>
              </div>
            </div>
          ))}
        </Space>
      </Card>

      <Modal
        title="修改显示名"
        open={editOpen}
        onCancel={() => setEditOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={updateMutation.isPending}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={(values) => {
            if (!profile) return
            updateMutation.mutate({ display_name: values.display_name, version: profile.version })
          }}
        >
          <Form.Item name="display_name" label="显示名" rules={[{ required: true, message: '请输入显示名' }]}>
            <Input />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}

function SessionsPanel() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const sessionsQuery = useQuery({ queryKey: ['my-sessions'], queryFn: authApi.sessions })

  const revokeMutation = useMutation({
    mutationFn: (id: string) => authApi.revokeSession(id),
    onSuccess: () => {
      message.success('会话已结束')
      void queryClient.invalidateQueries({ queryKey: ['my-sessions'] })
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '操作失败'),
  })

  const columns: ColumnsType<SessionItem> = [
    { title: '来源 IP', dataIndex: 'source_ip', width: 140 },
    { title: '终端', dataIndex: 'user_agent_summary', ellipsis: true },
    { title: '创建时间', dataIndex: 'created_at', width: 170, render: (v: string) => formatDateTime(v) },
    { title: '最近活跃', dataIndex: 'last_seen_at', width: 170, render: (v: string) => formatDateTime(v) },
    {
      title: '状态',
      key: 'state',
      width: 100,
      render: (_, record) => {
        if (record.revoked_at) return <Tag>已结束</Tag>
        if (record.is_current) return <Tag color="green">当前会话</Tag>
        return <Tag color="blue">活跃</Tag>
      },
    },
    {
      title: '操作',
      key: 'actions',
      width: 120,
      render: (_, record) =>
        !record.is_current && !record.revoked_at ? (
          <Popconfirm
            title="确定结束该会话吗？"
            onConfirm={() => revokeMutation.mutate(record.id)}
          >
            <Button type="link" size="small" danger>
              结束会话
            </Button>
          </Popconfirm>
        ) : null,
    },
  ]

  if (sessionsQuery.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="加载会话列表失败"
        description={sessionsQuery.error instanceof ApiError ? sessionsQuery.error.message : undefined}
      />
    )
  }

  return (
    <SmartTable<SessionItem>
      storageKey="profile"
      rowKey="id"
      loading={sessionsQuery.isLoading}
      columns={columns}
      dataSource={sessionsQuery.data?.items}
      pagination={false}
    />
  )
}

function MyLoginLogsPanel() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const logsQuery = useQuery({
    queryKey: ['my-login-logs', page, pageSize],
    queryFn: () => profileApi.loginLogs(page, pageSize),
  })

  const columns: ColumnsType<LoginLogEntry> = [
    { title: '时间', dataIndex: 'occurred_at', width: 170, render: (v: string) => formatDateTime(v) },
    { title: '来源 IP', dataIndex: 'source_ip', width: 140 },
    {
      title: '事件类型',
      dataIndex: 'event_type',
      width: 120,
      render: (v: string) => EVENT_TYPE_LABELS[v] ?? v,
    },
    {
      title: '结果',
      dataIndex: 'result',
      width: 90,
      render: (v: string) =>
        v === 'SUCCESS' ? <Tag color="green">成功</Tag> : <Tag color="red">失败</Tag>,
    },
    { title: '失败码', dataIndex: 'failure_code', render: (v?: string | null) => v || '-' },
  ]

  if (logsQuery.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="加载登录记录失败"
        description={logsQuery.error instanceof ApiError ? logsQuery.error.message : undefined}
      />
    )
  }

  return (
    <SmartTable<LoginLogEntry>
      storageKey="profile-login-logs"
      rowKey="id"
      loading={logsQuery.isLoading}
      columns={columns}
      dataSource={logsQuery.data?.items}
      pagination={{
        current: page,
        pageSize,
        total: logsQuery.data?.total ?? 0,
        showSizeChanger: true,
        showTotal: (t) => `共 ${t} 条`,
        onChange: (p, ps) => {
          setPage(p)
          setPageSize(ps)
        },
      }}
    />
  )
}

export default function ProfilePage() {
  const navigate = useNavigate()
  return (
    <Card title="个人中心">
      <Tabs
        defaultActiveKey="profile"
        items={[
          { key: 'profile', label: '个人资料', children: <ProfilePanel /> },
          {
            key: 'password',
            label: '修改密码',
            children: <ChangePasswordForm onSuccess={() => navigate('/login', { replace: true })} />,
          },
          { key: 'sessions', label: '登录会话', children: <SessionsPanel /> },
          { key: 'logs', label: '我的登录记录', children: <MyLoginLogsPanel /> },
        ]}
      />
    </Card>
  )
}
