import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, DatePicker, Select, Space, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type dayjs from 'dayjs'
import { useNavigate } from 'react-router-dom'
import { attackSessionsApi } from '../../api/attackSessions'
import type { AttackSessionItem } from '../../api/attackSessions'
import SmartTable from '../../components/SmartTable'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import AutomationSuspectedTag from '../../components/AutomationSuspectedTag'
import { formatDateTime, formatDuration } from '../../utils/format'
import { ATTACK_SESSION_STATUS_META, ATTACK_STAGE_META, RISK_LEVEL_META } from '../../utils/identitySecurity'

interface Filters {
  stage?: string
  risk_level?: string
  status?: string
  from?: string
  to?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

const optionsOf = (meta: Record<string, { label: string }>) =>
  Object.entries(meta).map(([value, m]) => ({ value, label: m.label }))

export default function AttackSessionsPage() {
  const navigate = useNavigate()
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const listQuery = useQuery({
    queryKey: ['attack-sessions', filters, page, pageSize],
    queryFn: () => attackSessionsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const setFilter = (patch: Partial<Filters>) => {
    setFilters((f) => ({ ...f, ...patch }))
    setPage(1)
  }

  const onRangeChange = (range: RangeValue) => {
    setFilter({
      from: range?.[0] ? range[0].startOf('day').toISOString() : undefined,
      to: range?.[1] ? range[1].endOf('day').toISOString() : undefined,
    })
  }

  const columns: ColumnsType<AttackSessionItem> = [
    {
      title: '会话号',
      dataIndex: 'session_key',
      width: 200,
      render: (v: string) => (
        <Typography.Text
          copyable={{ text: v, tooltips: ['复制会话号', '已复制'] }}
          style={{ fontFamily: 'monospace', fontSize: 12, maxWidth: 180 }}
          ellipsis={{ tooltip: <span style={{ fontFamily: 'monospace' }}>{v}</span> }}
        >
          {v}
        </Typography.Text>
      ),
    },
    {
      title: '身份',
      dataIndex: 'identity_id',
      width: 120,
      render: (v: string) =>
        v ? (
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '攻击阶段',
      dataIndex: 'attack_stage',
      width: 200,
      render: (v: string, record) => (
        <Space size={6} wrap>
          <StatusTag value={v} map={ATTACK_STAGE_META} />
          <AutomationSuspectedTag suspected={record.automation_suspected} basis={record.automation_basis} />
        </Space>
      ),
    },
    {
      title: '风险',
      dataIndex: 'risk_score',
      width: 130,
      render: (v: number, record) => (
        <Space size={6}>
          <Typography.Text strong={record.risk_level === 'HIGH' || record.risk_level === 'CRITICAL'}>
            {v}
          </Typography.Text>
          <StatusTag value={record.risk_level} map={RISK_LEVEL_META} />
        </Space>
      ),
    },
    { title: '事件数', dataIndex: 'event_count', width: 90 },
    { title: '请求数', dataIndex: 'request_count', width: 90 },
    {
      title: '开始时间',
      dataIndex: 'start_time',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '结束时间',
      dataIndex: 'end_time',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '持续时长',
      key: 'duration',
      width: 110,
      render: (_, record) => formatDuration(record.start_time, record.end_time),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ATTACK_SESSION_STATUS_META} />,
    },
  ]

  return (
    <Card title="攻击活动">
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="攻击阶段"
          allowClear
          style={{ width: 140 }}
          options={optionsOf(ATTACK_STAGE_META)}
          onChange={(v) => setFilter({ stage: v })}
        />
        <Select
          placeholder="风险等级"
          allowClear
          style={{ width: 120 }}
          options={optionsOf(RISK_LEVEL_META)}
          onChange={(v) => setFilter({ risk_level: v })}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 110 }}
          options={optionsOf(ATTACK_SESSION_STATUS_META)}
          onChange={(v) => setFilter({ status: v })}
        />
        <DatePicker.RangePicker onChange={onRangeChange} />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载攻击活动失败" />
      ) : (
        <SmartTable<AttackSessionItem>
          storageKey="attack-sessions"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1330 }}
          onRow={(record) => ({
            onClick: () => navigate(`/attack-sessions/${record.id}`),
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
    </Card>
  )
}
