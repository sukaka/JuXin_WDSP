import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, DatePicker, Input, InputNumber, Select, Space, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined } from '@ant-design/icons'
import type dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { accessLogsApi } from '../../api/accessLogs'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import AccessLogDetailDrawer from './AccessLogDetailDrawer'
import type { AccessLogItem } from '../../types'

interface Filters {
  start_time?: string
  end_time?: string
  domain?: string
  client_ip?: string
  method?: string
  uri?: string
  status?: number
  waf_action?: string
  request_id?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => ({
  value: m,
  label: m,
}))

// 网关仅对 403 推断 BLOCK，其余请求 waf_action 为空（放行）
const WAF_ACTION_OPTIONS = [{ value: 'BLOCK', label: '阻断' }]

export default function AccessLogsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['access-logs', filters, page, pageSize],
    queryFn: () => accessLogsApi.list({ ...filters, page, page_size: pageSize }),
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

  const columns: ColumnsType<AccessLogItem> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    { title: '客户端IP', dataIndex: 'client_ip', width: 125, render: (v: string) => v || '-' },
    { title: '域名', dataIndex: 'domain', width: 170, ellipsis: true },
    { title: '方法', dataIndex: 'request_method', width: 70 },
    {
      title: '请求路径',
      dataIndex: 'request_uri',
      width: 280,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v} placement="topLeft">
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '状态码',
      dataIndex: 'response_status',
      width: 80,
      align: 'right',
      render: (v: number) => (
        <Typography.Text type={v >= 500 ? 'danger' : v >= 400 ? 'warning' : undefined}>
          {v || '-'}
        </Typography.Text>
      ),
    },
    {
      title: '耗时',
      dataIndex: 'duration_ms',
      width: 90,
      align: 'right',
      render: (v: number) => `${v} ms`,
    },
    {
      title: '响应大小',
      dataIndex: 'bytes_out',
      width: 100,
      align: 'right',
      render: (v: number) => `${v} B`,
    },
    {
      title: 'WAF 动作',
      dataIndex: 'waf_action',
      width: 90,
      render: (v: string) => (v === 'BLOCK' ? <Tag color="red">阻断</Tag> : <Tag>放行</Tag>),
    },
    {
      title: '用户代理',
      dataIndex: 'user_agent_summary',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
  ]

  return (
    <Card
      title="访问日志"
      extra={
        hasPermission(permissions, 'access_logs.export') && (
          <Button
            icon={<DownloadOutlined />}
            onClick={() =>
              window.open(
                accessLogsApi.exportUrl({
                  start_time: filters.start_time,
                  end_time: filters.end_time,
                  domain: filters.domain,
                  client_ip: filters.client_ip,
                  method: filters.method,
                  uri: filters.uri,
                  status: filters.status,
                  waf_action: filters.waf_action,
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
        <InputNumber
          placeholder="状态码"
          min={100}
          max={599}
          style={{ width: 110 }}
          onChange={(v) => setFilter({ status: v ?? undefined })}
        />
        <Select
          placeholder="WAF 动作"
          allowClear
          style={{ width: 110 }}
          options={WAF_ACTION_OPTIONS}
          onChange={(v) => setFilter({ waf_action: v })}
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
          message="加载访问日志失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<AccessLogItem>
          storageKey="access-logs"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1400 }}
          onRow={(record) => ({
            onClick: () => setSelectedId(record.id),
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

      <AccessLogDetailDrawer logId={selectedId} onClose={() => setSelectedId(null)} />
    </Card>
  )
}
