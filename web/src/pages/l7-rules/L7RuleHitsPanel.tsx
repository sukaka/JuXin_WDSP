import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, DatePicker, Input, Select, Space, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { accessControlEventsApi } from '../../api/accessControlEvents'
import SmartTable from '../../components/SmartTable'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { AC_EVENT_ACTION_META, AC_EVENT_TYPE_META } from '../../utils/stage5'
import type { AccessControlEventItem } from '../../types'

/** L7 命中的四种事件类型（契约二） */
const L7_EVENT_TYPES = ['L7_RULE_ALLOW', 'L7_RULE_BLOCK', 'L7_RULE_REDIRECT', 'L7_RULE_CUSTOM']

interface Filters {
  start_time?: string
  end_time?: string
  event_type?: string
  client_ip?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

/** L7 规则命中日志：复用访问控制事件接口，按 L7_RULE_* 事件类型过滤 */
export default function L7RuleHitsPanel() {
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<AccessControlEventItem | null>(null)

  const listQuery = useQuery({
    queryKey: ['l7-rule-hits', filters, page, pageSize],
    queryFn: () => accessControlEventsApi.list({ ...filters, page, page_size: pageSize }),
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

  // 事件接口的 event_type 为单值精确匹配：选中具体类型时走服务端过滤；
  // 未选中时拉取全部事件并在当前页内筛选 L7_RULE_*（此时分页总数为全部事件的计数）
  const items = (listQuery.data?.items ?? []).filter(
    (item) => filters.event_type !== undefined || item.event_type.startsWith('L7_RULE_'),
  )

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
      width: 140,
      render: (v: string) => <StatusTag value={v} map={AC_EVENT_TYPE_META} />,
    },
    {
      title: '客户端IP',
      dataIndex: 'client_ip',
      width: 130,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
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
      width: 100,
      render: (v: string) => <StatusTag value={v} map={AC_EVENT_ACTION_META} />,
    },
    { title: '响应状态码', dataIndex: 'response_status', width: 100, render: (v?: number | null) => v ?? '-' },
    {
      title: '规则ID',
      dataIndex: 'access_rule_id',
      width: 110,
      render: (v?: string | null) => (v ? <Typography.Text code>{v.slice(0, 8)}</Typography.Text> : '-'),
    },
    {
      title: '请求 ID',
      dataIndex: 'request_id',
      width: 110,
      render: (v: string) => (v ? <Typography.Text code>{v.slice(0, 8)}</Typography.Text> : '-'),
    },
  ]

  return (
    <>
      <Space style={{ marginBottom: 16 }} wrap>
        <DatePicker.RangePicker onChange={onRangeChange} />
        <Select
          placeholder="事件类型（默认全部 L7）"
          allowClear
          style={{ width: 200 }}
          options={L7_EVENT_TYPES.map((value) => ({
            value,
            label: AC_EVENT_TYPE_META[value]?.label ?? value,
          }))}
          onChange={(v) => setFilter({ event_type: v })}
        />
        <Input.Search
          placeholder="客户端IP"
          allowClear
          style={{ width: 150 }}
          onSearch={(v) => setFilter({ client_ip: v || undefined })}
        />
      </Space>
      {!filters.event_type && (
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          未选择事件类型时仅展示当前页中的 L7 命中事件；选择具体类型后由服务端精确过滤，分页更准确。
        </Typography.Paragraph>
      )}
      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载命中日志失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<AccessControlEventItem>
          storageKey="l7-rule-hits"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={items}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
          scroll={{ x: 1300 }}
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
        title="命中事件详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
