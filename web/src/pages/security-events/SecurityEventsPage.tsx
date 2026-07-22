import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  DatePicker,
  Input,
  Select,
  Space,
  Table,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined } from '@ant-design/icons'
import type dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { securityEventsApi } from '../../api/securityEvents'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  ATTACK_TYPE_META,
  ATTACK_TYPE_OPTIONS,
  DISPOSITION_STATUS_META,
  EVENT_ACTION_META,
  EVENT_SEVERITY_META,
} from '../../utils/stage4'
import EventDetailDrawer from './EventDetailDrawer'
import type { SecurityEventItem } from '../../types'

interface Filters {
  start_time?: string
  end_time?: string
  domain?: string
  client_ip?: string
  uri?: string
  method?: string
  attack_type?: string
  severity?: string
  action?: string
  disposition_status?: string
  request_id?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => ({
  value: m,
  label: m,
}))

export default function SecurityEventsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['security-events', filters, page, pageSize],
    queryFn: () => securityEventsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const setFilter = (patch: Partial<Filters>) => {
    setFilters((f) => ({ ...f, ...patch }))
    setPage(1)
  }

  const onRangeChange = (range: RangeValue) => {
    setFilter({
      start_time: range?.[0] ? range[0].startOf('day').toISOString() : undefined,
      end_time: range?.[1] ? range[1].endOf('day').toISOString() : undefined,
    })
  }

  const columns: ColumnsType<SecurityEventItem> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    { title: '客户端IP', dataIndex: 'client_ip', width: 125 },
    { title: '域名', dataIndex: 'domain', width: 170, ellipsis: true },
    { title: '方法', dataIndex: 'request_method', width: 70 },
    {
      title: '请求路径',
      dataIndex: 'request_uri',
      width: 260,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v} placement="topLeft">
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '攻击类型',
      dataIndex: 'attack_type',
      width: 140,
      render: (v: string) => <StatusTag value={v} map={ATTACK_TYPE_META} />,
    },
    {
      title: '风险',
      dataIndex: 'severity',
      width: 80,
      render: (v: string) => <StatusTag value={v} map={EVENT_SEVERITY_META} />,
    },
    { title: '评分', dataIndex: 'anomaly_score', width: 70, align: 'right' },
    {
      title: '动作',
      dataIndex: 'action',
      width: 80,
      render: (v: string) => <StatusTag value={v} map={EVENT_ACTION_META} />,
    },
    {
      title: '处置状态',
      dataIndex: 'disposition_status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={DISPOSITION_STATUS_META} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelectedId(record.id)}>
          详情
        </Button>
      ),
    },
  ]

  return (
    <Card
      title="安全事件"
      extra={
        hasPermission(permissions, 'security_events.export') && (
          <Button
            icon={<DownloadOutlined />}
            onClick={() =>
              window.open(
                securityEventsApi.exportUrl({
                  start_time: filters.start_time,
                  end_time: filters.end_time,
                  domain: filters.domain,
                  attack_type: filters.attack_type,
                  severity: filters.severity,
                }),
                '_blank',
              )
            }
          >
            导出 CSV
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <DatePicker.RangePicker onChange={onRangeChange} />
        <Input.Search
          placeholder="域名"
          allowClear
          style={{ width: 160 }}
          onSearch={(v) => setFilter({ domain: v || undefined })}
        />
        <Input.Search
          placeholder="客户端IP"
          allowClear
          style={{ width: 140 }}
          onSearch={(v) => setFilter({ client_ip: v || undefined })}
        />
        <Input.Search
          placeholder="请求路径"
          allowClear
          style={{ width: 150 }}
          onSearch={(v) => setFilter({ uri: v || undefined })}
        />
        <Select
          placeholder="方法"
          allowClear
          style={{ width: 100 }}
          options={METHOD_OPTIONS}
          onChange={(v) => setFilter({ method: v })}
        />
        <Select
          placeholder="攻击类型"
          allowClear
          showSearch
          style={{ width: 190 }}
          options={ATTACK_TYPE_OPTIONS}
          onChange={(v) => setFilter({ attack_type: v })}
        />
        <Select
          placeholder="风险"
          allowClear
          style={{ width: 100 }}
          options={Object.entries(EVENT_SEVERITY_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => setFilter({ severity: v })}
        />
        <Select
          placeholder="动作"
          allowClear
          style={{ width: 100 }}
          options={Object.entries(EVENT_ACTION_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => setFilter({ action: v })}
        />
        <Select
          placeholder="处置状态"
          allowClear
          style={{ width: 130 }}
          options={Object.entries(DISPOSITION_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => setFilter({ disposition_status: v })}
        />
        <Input.Search
          placeholder="请求 ID"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => setFilter({ request_id: v || undefined })}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载安全事件失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <Table<SecurityEventItem>
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1550 }}
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

      <EventDetailDrawer
        eventId={selectedId}
        onClose={() => setSelectedId(null)}
        onSelectEvent={(id) => setSelectedId(id)}
      />
    </Card>
  )
}
