import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, DatePicker, Input, Select, Space, Tag, Typography } from 'antd'
import SmartTable from '../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import ExportDropdown from '../../components/ExportDropdown'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import type dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { logsApi } from '../../api/logs'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type { LoginLogEntry } from '../../types'

const EVENT_TYPE_OPTIONS = [
  { value: 'LOGIN_SUCCESS', label: '登录成功' },
  { value: 'LOGIN_FAILURE', label: '登录失败' },
  { value: 'LOGIN_TOTP_CHALLENGE', label: '双因子挑战（TOTP）' },
  { value: 'CAPTCHA_FAILURE', label: '验证码错误' },
  { value: 'ACCOUNT_LOCKED', label: '账号锁定' },
  { value: 'LOGOUT', label: '登出' },
  { value: 'FORCE_LOGOUT', label: '强制下线' },
  { value: 'SESSION_EXPIRED', label: '会话过期' },
  { value: 'PASSWORD_CHANGE', label: '修改密码' },
  { value: 'PASSWORD_RESET', label: '重置密码' },
  { value: 'FIRST_CHANGE_PASSWORD', label: '首次改密' },
]

const EVENT_TYPE_LABELS: Record<string, string> = Object.fromEntries(
  EVENT_TYPE_OPTIONS.map((o) => [o.value, o.label]),
)

const FAILURE_CODE_LABELS: Record<string, string> = {
  CAPTCHA_REQUIRED: '需要验证码',
  CAPTCHA_INVALID: '验证码错误',
  BAD_CREDENTIALS: '用户名或密码错误',
  ACCOUNT_DISABLED: '账号已停用',
  ACCOUNT_LOCKED: '账号已锁定',
  MAX_FAILED_ATTEMPTS: '失败次数超限',
  PASSWORD_EXPIRED: '密码已过期',
  // TOTP 双因子（server/internal/auth/totp.go）：挑战令牌无效/过期/来源不匹配、动态令牌/恢复码错误
  TOTP_CHALLENGE_INVALID: '双因子挑战无效或过期',
  TOTP_CHALLENGE_EXPIRED: '双因子挑战已过期',
  TOTP_CHALLENGE_ORIGIN_MISMATCH: '双因子挑战来源不匹配',
  TOTP_INVALID: '动态令牌或恢复码错误',
}

interface Filters {
  username?: string
  result?: string
  event_type?: string
  start_time?: string
  end_time?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

export default function LoginLogsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<LoginLogEntry | null>(null)

  const listQuery = useQuery({
    queryKey: ['login-logs', filters, page, pageSize],
    queryFn: () => logsApi.loginLogs({ ...filters, page, page_size: pageSize }),
  })

  const onRangeChange = (range: RangeValue) => {
    setFilters((f) => ({
      ...f,
      start_time: range?.[0] ? range[0].startOf('day').toISOString() : undefined,
      end_time: range?.[1] ? range[1].endOf('day').toISOString() : undefined,
    }))
    setPage(1)
  }

  const columns: ColumnsType<LoginLogEntry> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    { title: '用户名', dataIndex: 'username', width: 130 },
    { title: '来源 IP', dataIndex: 'source_ip', width: 140 },
    {
      title: '事件类型',
      dataIndex: 'event_type',
      width: 110,
      render: (v: string) => EVENT_TYPE_LABELS[v] ?? v,
    },
    {
      title: '结果',
      dataIndex: 'result',
      width: 90,
      render: (v: string) =>
        v === 'SUCCESS' ? <Tag color="green">成功</Tag> : <Tag color="red">失败</Tag>,
    },
    {
      title: '失败码',
      dataIndex: 'failure_code',
      width: 150,
      render: (v?: string | null) => (v ? (FAILURE_CODE_LABELS[v] ?? v) : '-'),
    },
    {
      title: '请求 ID',
      dataIndex: 'request_id',
      render: (v?: string | null) =>
        v ? (
          <Typography.Text copyable={{ text: v }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
            {v.slice(0, 8)}…
          </Typography.Text>
        ) : (
          '-'
        ),
    },
  ]

  return (
    <Card
      title="登录日志"
      extra={
        hasPermission(permissions, 'login_logs.export') && (
          <ExportDropdown
            onExportFiltered={() => window.open(logsApi.loginLogsExportUrl(filters), '_blank')}
            onExportAll={() => window.open(logsApi.loginLogsExportUrl({}), '_blank')}
          />
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <DatePicker.RangePicker onChange={onRangeChange} />
        <Input.Search
          placeholder="用户名"
          allowClear
          style={{ width: 180 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, username: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="结果"
          allowClear
          style={{ width: 120 }}
          options={[
            { value: 'SUCCESS', label: '成功' },
            { value: 'FAILURE', label: '失败' },
          ]}
          onChange={(v) => {
            setFilters((f) => ({ ...f, result: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="事件类型"
          allowClear
          style={{ width: 150 }}
          options={EVENT_TYPE_OPTIONS}
          onChange={(v) => {
            setFilters((f) => ({ ...f, event_type: v }))
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载登录日志失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<LoginLogEntry>
          storageKey="login-logs"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
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
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="登录日志详情"
        record={detailRecord as Record<string, unknown> | null}
        valueLabels={{ event_type: EVENT_TYPE_LABELS, failure_code: FAILURE_CODE_LABELS }}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
