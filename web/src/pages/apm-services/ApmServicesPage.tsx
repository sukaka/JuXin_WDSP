import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, DatePicker, Input, Radio, Space, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apmApi } from '../../api/apm'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import { TREND_RANGE_OPTIONS } from '../../utils/stage6'
import {
  formatMs,
  formatPercent,
  resolveApmTimeRange,
  type ApmRangeValue,
} from '../../utils/apm'
import ApmServiceDetailDrawer from './ApmServiceDetailDrawer'
import type { ApmServiceItem } from '../../types'

const COLUMNS: ColumnsType<ApmServiceItem> = [
  {
    title: '应用',
    key: 'app',
    width: 220,
    ellipsis: true,
    render: (_, r) => (
      <>
        <div>{r.name || '-'}</div>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {r.app}
        </Typography.Text>
      </>
    ),
  },
  {
    title: '观测模式',
    dataIndex: 'observation_mode',
    width: 150,
    render: (v: ApmServiceItem['observation_mode'], r) =>
      v === 'agent' ? (
        <Tag color="green">
          Agent（在线 {r.agents_online ?? 0}/{r.agents_total ?? 0}）
        </Tag>
      ) : (
        <Tag color="blue">无 Agent</Tag>
      ),
  },
  { title: '请求量', dataIndex: 'requests', width: 100 },
  {
    title: '错误率',
    dataIndex: 'error_rate',
    width: 100,
    render: (v: number) => (
      <Typography.Text type={v >= 0.05 ? 'danger' : undefined}>{formatPercent(v)}</Typography.Text>
    ),
  },
  { title: 'P50', dataIndex: 'p50', width: 90, render: (v: number) => formatMs(v) },
  { title: 'P95', dataIndex: 'p95', width: 90, render: (v: number) => formatMs(v) },
  { title: 'P99', dataIndex: 'p99', width: 90, render: (v: number) => formatMs(v) },
  { title: '阻断量', dataIndex: 'blocked', width: 90 },
  {
    title: '数据时间',
    dataIndex: 'last_seen_at',
    width: 165,
    render: (v: string) => formatDateTime(v),
  },
]

/** 服务性能（无 Agent 模式）：应用级 RED 清单，行点击查看服务详情抽屉；30 秒自动刷新 */
export default function ApmServicesPage() {
  const [range, setRange] = useState('1h')
  const [customRange, setCustomRange] = useState<ApmRangeValue>(null)
  const [keyword, setKeyword] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const timeParams = useMemo(() => resolveApmTimeRange(range, customRange), [range, customRange])

  const listQuery = useQuery({
    queryKey: ['apm', 'services', timeParams, keyword, page, pageSize],
    queryFn: () =>
      apmApi.services({ ...timeParams, keyword, page, page_size: pageSize }),
    refetchInterval: 30000,
  })

  return (
    <Card
      title="服务性能"
      extra={
        <Space>
          <Tag color="blue">数据来源：无 Agent</Tag>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            30 秒自动刷新
          </Typography.Text>
        </Space>
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Radio.Group
          value={range}
          onChange={(e) => {
            setRange(String(e.target.value))
            setPage(1)
          }}
          options={[...TREND_RANGE_OPTIONS, { value: 'custom', label: '自定义' }]}
          optionType="button"
          size="small"
        />
        {range === 'custom' && (
          <DatePicker.RangePicker
            showTime
            value={customRange}
            onChange={(v) => {
              setCustomRange(v)
              setPage(1)
            }}
            size="small"
          />
        )}
        <Input.Search
          placeholder="应用名称 / 编码"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setKeyword(v || undefined)
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载服务性能列表失败" />
      ) : (
        <SmartTable<ApmServiceItem>
          storageKey="apm-services"
          rowKey="application_id"
          loading={listQuery.isLoading}
          columns={COLUMNS}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1100 }}
          onRow={(record) => ({
            onClick: () => setSelectedId(record.application_id),
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

      <ApmServiceDetailDrawer
        serviceId={selectedId}
        timeParams={timeParams}
        onClose={() => setSelectedId(null)}
      />
    </Card>
  )
}
