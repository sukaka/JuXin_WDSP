import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Drawer,
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
import { accessControlEventsApi } from '../../api/accessControlEvents'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { AC_EVENT_ACTION_META, AC_EVENT_TYPE_META } from '../../utils/stage5'
import type { AccessControlEventItem } from '../../types'

interface Filters {
  start_time?: string
  end_time?: string
  event_type?: string
  client_ip?: string
  policy_id?: string
  request_id?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

export default function AccessControlEventsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canExport = hasPermission(permissions, 'access_control_events.export')
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailId, setDetailId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['access-control-events', filters, page, pageSize],
    queryFn: () => accessControlEventsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['access-control-event', detailId],
    queryFn: () => accessControlEventsApi.get(detailId as string),
    enabled: detailId !== null,
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

  const columns: ColumnsType<AccessControlEventItem> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '事件类型',
      dataIndex: 'event_type',
      width: 150,
      render: (v: string) => <StatusTag value={v} map={AC_EVENT_TYPE_META} />,
    },
    {
      title: '客户端IP',
      dataIndex: 'client_ip',
      width: 130,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '应用',
      dataIndex: 'application_code',
      width: 130,
      ellipsis: true,
      render: (v: string) => v || '全局',
    },
    { title: '域名', dataIndex: 'domain', width: 160, ellipsis: true, render: (v: string) => v || '-' },
    {
      title: '路径',
      dataIndex: 'request_path',
      width: 180,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v} placement="topLeft">
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '动作',
      dataIndex: 'action',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={AC_EVENT_ACTION_META} />,
    },
    {
      title: '计数/阈值',
      key: 'count',
      width: 100,
      render: (_, record) =>
        record.current_count != null ? (
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
            {record.current_count}
            {record.limit_value != null ? ` / ${record.limit_value}` : ''}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: 'RequestID',
      dataIndex: 'request_id',
      width: 110,
      render: (v: string) =>
        v ? <Typography.Text code>{v.slice(0, 8)}</Typography.Text> : '-',
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
          详情
        </Button>
      ),
    },
  ]

  const evt = detailQuery.data?.event

  return (
    <Card
      title="访问控制事件"
      extra={
        canExport && (
          <Button
            icon={<DownloadOutlined />}
            onClick={() =>
              window.open(
                accessControlEventsApi.exportUrl({
                  start_time: filters.start_time,
                  end_time: filters.end_time,
                  event_type: filters.event_type,
                  client_ip: filters.client_ip,
                  policy_id: filters.policy_id,
                  request_id: filters.request_id,
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
        <Select
          placeholder="事件类型"
          allowClear
          style={{ width: 190 }}
          options={Object.entries(AC_EVENT_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => setFilter({ event_type: v })}
        />
        <Input.Search
          placeholder="客户端IP"
          allowClear
          style={{ width: 150 }}
          onSearch={(v) => setFilter({ client_ip: v || undefined })}
        />
        <Input.Search
          placeholder="策略ID"
          allowClear
          style={{ width: 170 }}
          onSearch={(v) => setFilter({ policy_id: v || undefined })}
        />
        <Input.Search
          placeholder="RequestID"
          allowClear
          style={{ width: 170 }}
          onSearch={(v) => setFilter({ request_id: v || undefined })}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载访问控制事件失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <Table<AccessControlEventItem>
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1450 }}
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
        title="事件详情"
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={640}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载事件详情失败"
            description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          />
        ) : evt ? (
          <Descriptions column={2} size="small" bordered>
            <Descriptions.Item label="事件ID" span={2}>
              <Typography.Text code>{evt.id}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="RequestID" span={2}>
              <Typography.Text code>{evt.request_id || '-'}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="发生时间">{formatDateTime(evt.occurred_at)}</Descriptions.Item>
            <Descriptions.Item label="事件类型">
              <StatusTag value={evt.event_type} map={AC_EVENT_TYPE_META} />
            </Descriptions.Item>
            <Descriptions.Item label="动作">
              <StatusTag value={evt.action} map={AC_EVENT_ACTION_META} />
            </Descriptions.Item>
            <Descriptions.Item label="响应状态码">{evt.response_status ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="客户端IP">{evt.client_ip || '-'}</Descriptions.Item>
            <Descriptions.Item label="连接IP">{evt.connection_ip || '-'}</Descriptions.Item>
            <Descriptions.Item label="应用">
              {evt.application_code || '全局'}
              {evt.application_id && (
                <Typography.Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
                  {evt.application_id}
                </Typography.Text>
              )}
            </Descriptions.Item>
            <Descriptions.Item label="网关节点">{evt.gateway_node_id || '-'}</Descriptions.Item>
            <Descriptions.Item label="域名" span={2}>
              {evt.domain || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="请求方法">{evt.request_method || '-'}</Descriptions.Item>
            <Descriptions.Item label="请求路径" span={1}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                {evt.request_path || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="策略ID">{evt.policy_id ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="规则ID">{evt.access_rule_id ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="当前计数">{evt.current_count ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="阈值">{evt.limit_value ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="统计窗口">
              {evt.window_seconds != null ? `${evt.window_seconds} 秒` : '-'}
            </Descriptions.Item>
            <Descriptions.Item label="封禁到期">{formatDateTime(evt.block_expires_at)}</Descriptions.Item>
            <Descriptions.Item label="记录时间">{formatDateTime(evt.created_at)}</Descriptions.Item>
            <Descriptions.Item label="消息" span={2}>
              {evt.message || '-'}
            </Descriptions.Item>
          </Descriptions>
        ) : null}
      </Drawer>
    </Card>
  )
}
