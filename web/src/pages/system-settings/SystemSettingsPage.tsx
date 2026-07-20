import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App as AntdApp, Button, Card, Input, InputNumber, Switch, Table, Tabs, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { settingsApi } from '../../api/settings'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type { SettingItem } from '../../types'

const GROUP_TABS = [
  { key: 'password', label: '密码策略' },
  { key: 'login', label: '登录安全' },
  { key: 'session', label: '会话管理' },
  { key: 'display', label: '界面显示' },
]

function SettingGroupPanel({ group }: { group: string }) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'system_settings.update')
  // 每行的本地编辑值：key 为设置项 id
  const [drafts, setDrafts] = useState<Record<string, string>>({})

  const listQuery = useQuery({
    queryKey: ['settings', group],
    queryFn: () => settingsApi.list(group),
  })

  useEffect(() => {
    setDrafts({})
  }, [group])

  const updateMutation = useMutation({
    mutationFn: (item: SettingItem) =>
      settingsApi.update({
        setting_group: item.setting_group,
        setting_key: item.setting_key,
        setting_value: drafts[item.id] ?? item.setting_value,
        version: item.version,
      }),
    onSuccess: () => {
      message.success('保存成功')
      void queryClient.invalidateQueries({ queryKey: ['settings', group] })
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
        message.error('该设置已被他人修改，请刷新后重试')
        void queryClient.invalidateQueries({ queryKey: ['settings', group] })
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  const draftValue = (item: SettingItem) => drafts[item.id] ?? item.setting_value
  const isDirty = (item: SettingItem) =>
    drafts[item.id] !== undefined && drafts[item.id] !== item.setting_value

  const renderEditor = (item: SettingItem) => {
    if (item.is_sensitive) {
      return <Typography.Text type="secondary">********</Typography.Text>
    }
    const value = draftValue(item)
    const setValue = (v: string) => setDrafts((d) => ({ ...d, [item.id]: v }))
    if (!canUpdate) {
      return <Typography.Text>{value}</Typography.Text>
    }
    if (item.value_type === 'boolean') {
      return (
        <Switch
          checked={value === 'true'}
          onChange={(checked) => setValue(checked ? 'true' : 'false')}
        />
      )
    }
    if (item.value_type === 'integer') {
      return (
        <InputNumber
          value={Number(value)}
          onChange={(v) => setValue(String(v ?? 0))}
          style={{ width: 160 }}
        />
      )
    }
    return <Input value={value} onChange={(e) => setValue(e.target.value)} style={{ width: 280 }} />
  }

  const columns: ColumnsType<SettingItem> = [
    {
      title: '设置项',
      key: 'name',
      width: 320,
      render: (_, item) => (
        <div>
          <Typography.Text code>{item.setting_key}</Typography.Text>
          {item.is_sensitive && <Tag style={{ marginLeft: 8 }}>敏感</Tag>}
          <div style={{ color: '#888', fontSize: 12, marginTop: 4 }}>{item.description}</div>
        </div>
      ),
    },
    {
      title: '当前值',
      key: 'value',
      render: (_, item) => renderEditor(item),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    ...(canUpdate
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 100,
            render: (_: unknown, item: SettingItem) => (
              <Button
                type="link"
                size="small"
                disabled={item.is_sensitive || !isDirty(item)}
                loading={updateMutation.isPending && updateMutation.variables?.id === item.id}
                onClick={() => updateMutation.mutate(item)}
              >
                保存
              </Button>
            ),
          } satisfies ColumnsType<SettingItem>[number],
        ]
      : []),
  ]

  if (listQuery.isError) {
    return (
      <Alert
        type="error"
        showIcon
        message="加载系统设置失败"
        description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
      />
    )
  }

  return (
    <Table<SettingItem>
      rowKey="id"
      loading={listQuery.isLoading}
      columns={columns}
      dataSource={listQuery.data?.items}
      pagination={false}
    />
  )
}

export default function SystemSettingsPage() {
  return (
    <Card title="系统设置">
      <Tabs
        defaultActiveKey="password"
        items={GROUP_TABS.map((t) => ({
          key: t.key,
          label: t.label,
          children: <SettingGroupPanel group={t.key} />,
        }))}
      />
    </Card>
  )
}
