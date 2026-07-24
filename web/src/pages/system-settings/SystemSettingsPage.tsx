import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, App as AntdApp, Button, Card, Input, InputNumber, Select, Switch, Tabs, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import SmartTable from '../../components/SmartTable'
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
  { key: 'logging', label: '日志记录' },
]

/** 设置项前端扩展元数据：中文说明覆盖、数值范围约束与枚举选项（键为 setting_group:setting_key） */
const SETTING_META: Record<
  string,
  { description?: string; min?: number; max?: number; options?: { label: string; value: string }[]; placeholder?: string }
> = {
  'logging:access_log_enabled': {
    description: '记录所有经过网关的访问日志（总开关，关闭后不再产生访问日志）',
  },
  'logging:capture_request_headers': {
    description: '记录请求头（敏感头自动掩码）',
  },
  'logging:capture_request_body': {
    description: '记录请求体（敏感键值自动脱敏，超限截断）；开启会增加存储占用，建议排障时临时开启',
  },
  'logging:capture_response_headers': {
    description: '记录响应头（敏感头自动掩码）',
  },
  'logging:capture_response_body': {
    description: '记录响应体（仅文本类，超限截断）；开启会增加存储占用，建议排障时临时开启',
  },
  'logging:body_limit_kb': {
    description: '单条日志请求/响应头体最大记录长度（KB），超出部分截断',
    min: 1,
    max: 1024,
  },
  'logging:retention_days': {
    description: '访问日志保留天数，到期自动清理',
    min: 1,
    max: 90,
  },
  'logging:syslog_enabled': {
    description: 'syslog 外发总开关，关闭后不再向 syslog 服务器外发任何日志',
  },
  'logging:syslog_protocol': {
    description: 'syslog 传输协议',
    options: [
      { label: 'UDP', value: 'udp' },
      { label: 'TCP', value: 'tcp' },
    ],
  },
  'logging:syslog_address': {
    description: 'syslog 服务器地址（host:port）',
    placeholder: 'host:port，如 192.168.1.10:514',
  },
  'logging:syslog_facility': {
    description: 'RFC5424 facility，默认 1（user-level）',
    min: 0,
    max: 23,
  },
  'logging:syslog_forward_security_events': {
    description: '外发安全事件到 syslog',
  },
  'logging:syslog_forward_access_control_events': {
    description: '外发访问控制事件到 syslog',
  },
  'logging:syslog_forward_access_logs': {
    description: '外发全量访问日志到 syslog（数据量大，谨慎开启）',
  },
}

function SettingGroupPanel({ group }: { group: string }) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canUpdate = hasPermission(permissions, 'system_settings.update')
  const canSyslogTest = hasPermission(permissions, 'logging.syslog_test')
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

  const syslogTestMutation = useMutation({
    mutationFn: () => settingsApi.syslogTest(),
    onSuccess: (data) => {
      message.success(data.message)
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '发送测试消息失败')
    },
  })

  const draftValue = (item: SettingItem) => drafts[item.id] ?? item.setting_value
  const isDirty = (item: SettingItem) =>
    drafts[item.id] !== undefined && drafts[item.id] !== item.setting_value

  const renderEditor = (item: SettingItem) => {
    if (item.is_sensitive) {
      return <Typography.Text type="secondary">********</Typography.Text>
    }
    const meta = SETTING_META[`${item.setting_group}:${item.setting_key}`]
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
          min={meta?.min}
          max={meta?.max}
          onChange={(v) => setValue(String(v ?? 0))}
          style={{ width: 160 }}
        />
      )
    }
    if (meta?.options) {
      return (
        <Select
          value={value}
          options={meta.options}
          onChange={(v) => setValue(v)}
          style={{ width: 160 }}
        />
      )
    }
    return (
      <Input
        value={value}
        placeholder={meta?.placeholder}
        onChange={(e) => setValue(e.target.value)}
        style={{ width: 280 }}
      />
    )
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
          <div style={{ color: '#888', fontSize: 12, marginTop: 4 }}>
            {SETTING_META[`${item.setting_group}:${item.setting_key}`]?.description ??
              item.description}
          </div>
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
    <>
      {group === 'logging' && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="开启请求/响应体记录会显著增加存储占用，建议仅在排障时临时开启，用完及时关闭。"
        />
      )}
      {group === 'logging' && canSyslogTest && (
        <Button
          style={{ marginBottom: 16 }}
          loading={syslogTestMutation.isPending}
          onClick={() => syslogTestMutation.mutate()}
        >
          发送测试消息
        </Button>
      )}
      <SmartTable<SettingItem>
        storageKey="system-settings"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items}
        pagination={false}
      />
    </>
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
