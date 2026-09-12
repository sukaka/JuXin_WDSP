import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, DatePicker, Input, Select, Space, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type dayjs from 'dayjs'
import { useNavigate } from 'react-router-dom'
import { securityIdentitiesApi } from '../../api/securityIdentities'
import type { IdentityItem } from '../../api/securityIdentities'
import SmartTable from '../../components/SmartTable'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { IDENTITY_TYPE_META, RISK_LEVEL_META } from '../../utils/identitySecurity'

interface Filters {
  risk_level?: string
  identity_type?: string
  keyword?: string
  ip?: string
  from?: string
  to?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

const optionsOf = (meta: Record<string, { label: string }>) =>
  Object.entries(meta).map(([value, m]) => ({ value, label: m.label }))

/** 身份标识截断展示 + 完整值复制 */
function IdentityKeyCell({ value }: { value: string }) {
  return (
    <Typography.Text
      copyable={{ text: value, tooltips: ['复制标识', '已复制'] }}
      style={{ fontFamily: 'monospace', fontSize: 12, maxWidth: 200 }}
      ellipsis={{ tooltip: <span style={{ fontFamily: 'monospace' }}>{value}</span> }}
    >
      {value}
    </Typography.Text>
  )
}

export default function RiskIdentitiesPage() {
  const navigate = useNavigate()
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const listQuery = useQuery({
    queryKey: ['security-identities', filters, page, pageSize],
    queryFn: () => securityIdentitiesApi.list({ ...filters, page, page_size: pageSize }),
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

  const columns: ColumnsType<IdentityItem> = [
    {
      title: '身份标识',
      dataIndex: 'identity_key',
      width: 240,
      render: (v: string) => <IdentityKeyCell value={v} />,
    },
    {
      title: '类型',
      dataIndex: 'identity_type',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={IDENTITY_TYPE_META} />,
    },
    {
      title: '识别置信度',
      dataIndex: 'identity_confidence',
      width: 110,
      render: (v: number) => `${v ?? 0}%`,
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
    { title: '主IP', dataIndex: 'primary_ip', width: 130 },
    { title: 'IP数', dataIndex: 'ip_count', width: 80 },
    {
      title: '账号',
      dataIndex: 'account_id',
      width: 150,
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Tooltip title={v} placement="topLeft">
            <span>{v}</span>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    { title: '请求数', dataIndex: 'request_count', width: 100 },
    {
      title: '最近活跃',
      dataIndex: 'last_seen_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
  ]

  return (
    <Card title="风险身份">
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="风险等级"
          allowClear
          style={{ width: 120 }}
          options={optionsOf(RISK_LEVEL_META)}
          onChange={(v) => setFilter({ risk_level: v })}
        />
        <Select
          placeholder="身份类型"
          allowClear
          style={{ width: 130 }}
          options={optionsOf(IDENTITY_TYPE_META)}
          onChange={(v) => setFilter({ identity_type: v })}
        />
        <Input.Search
          placeholder="关键字（标识 / 账号）"
          allowClear
          style={{ width: 200 }}
          onSearch={(v) => setFilter({ keyword: v || undefined })}
        />
        <Input.Search
          placeholder="来源IP"
          allowClear
          style={{ width: 160 }}
          onSearch={(v) => setFilter({ ip: v || undefined })}
        />
        <DatePicker.RangePicker onChange={onRangeChange} />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载风险身份失败" />
      ) : (
        <SmartTable<IdentityItem>
          storageKey="risk-identities"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1215 }}
          onRow={(record) => ({
            onClick: () => navigate(`/risk-identities/${record.id}`),
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
