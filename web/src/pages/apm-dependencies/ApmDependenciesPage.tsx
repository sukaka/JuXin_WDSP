import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, App as AntdApp, Button, Card, DatePicker, Empty, Radio, Select, Space, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apmApi } from '../../api/apm'
import EChart from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { SEARCH_RANGE_OPTIONS } from '../../utils/stage6'
import { apmDependencyGraphOption } from '../../utils/apmCharts'
import {
  APM_DEPENDENCY_TARGET_TYPE_META,
  APM_SEARCH_WINDOW_HOURS,
  APM_TRACE_DATA_SOURCE_META,
  formatMs,
  formatPercent,
  isCustomRangeOverCap,
  resolveApmTimeRange,
  type ApmRangeValue,
} from '../../utils/apm'
import type { ApmDependencyEdge } from '../../types'

const COLUMNS: ColumnsType<ApmDependencyEdge> = [
  {
    title: '调用方（source）',
    dataIndex: 'source',
    width: 200,
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
    ),
  },
  {
    title: '被调方（target）',
    dataIndex: 'target',
    width: 200,
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
    ),
  },
  {
    title: '目标类型',
    dataIndex: 'target_type',
    width: 100,
    render: (v: string) => <StatusTag value={v} map={APM_DEPENDENCY_TARGET_TYPE_META} />,
  },
  { title: '调用数', dataIndex: 'calls', width: 90 },
  {
    title: '错误率',
    dataIndex: 'error_rate',
    width: 90,
    render: (v: number) => (
      <Typography.Text type={v >= 0.05 ? 'danger' : undefined}>{formatPercent(v)}</Typography.Text>
    ),
  },
  { title: '平均耗时', dataIndex: 'avg_ms', width: 100, render: (v: number) => formatMs(v) },
]

/** 依赖分析（权限 apm.services.read）：服务/DB/MQ/外部依赖边列表（默认表格视图，可切换关系图）；
 *  note 为后端口径说明（如"基于客户端 span 单视角派生"），如实展示 */
export default function ApmDependenciesPage() {
  const { message } = AntdApp.useApp()
  const [range, setRange] = useState('1h')
  const [customRange, setCustomRange] = useState<ApmRangeValue>(null)
  const [service, setService] = useState<string | undefined>()
  const [view, setView] = useState<'table' | 'graph'>('table')
  const [detailRecord, setDetailRecord] = useState<ApmDependencyEdge | null>(null)

  const timeParams = useMemo(() => resolveApmTimeRange(range, customRange), [range, customRange])

  // 服务下拉数据源：当前时间窗内的服务清单（上限 100）
  const servicesQuery = useQuery({
    queryKey: ['apm', 'services', 'dependency-filter-options', timeParams],
    queryFn: () => apmApi.services({ ...timeParams, page: 1, page_size: 100 }),
    retry: false,
  })

  const graphQuery = useQuery({
    queryKey: ['apm', 'dependencies', timeParams, service],
    queryFn: () => apmApi.dependencies({ ...timeParams, service }),
  })

  const data = graphQuery.data
  const dsMeta = data ? APM_TRACE_DATA_SOURCE_META[data.data_source] : undefined

  // 操作列提供可见的「查看」入口；双击仅作快捷方式
  const columns: ColumnsType<ApmDependencyEdge> = [
    ...COLUMNS,
    {
      title: '操作',
      key: 'actions',
      width: 70,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setDetailRecord(record)}>
          查看
        </Button>
      ),
    },
  ]

  return (
    <Card
      title="依赖分析"
      extra={
        <Space>
          {data && (
            <Tag color={dsMeta?.color ?? 'default'}>
              数据来源：{dsMeta?.label ?? data.data_source}
            </Tag>
          )}
          <Radio.Group
            value={view}
            onChange={(e) => setView(e.target.value as 'table' | 'graph')}
            options={[
              { value: 'table', label: '表格视图' },
              { value: 'graph', label: '关系图' },
            ]}
            optionType="button"
            size="small"
          />
        </Space>
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Radio.Group
          value={range}
          onChange={(e) => setRange(String(e.target.value))}
          options={[...SEARCH_RANGE_OPTIONS, { value: 'custom', label: '自定义' }]}
          optionType="button"
          size="small"
        />
        {range === 'custom' && (
          <DatePicker.RangePicker
            showTime
            value={customRange}
            onChange={(v) => {
              if (isCustomRangeOverCap(v, APM_SEARCH_WINDOW_HOURS)) {
                message.warning('查询窗口不能超过 24 小时')
                return
              }
              setCustomRange(v)
            }}
            size="small"
          />
        )}
        <Select
          placeholder="全部服务"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 220 }}
          loading={servicesQuery.isLoading}
          options={(servicesQuery.data?.items ?? []).map((s) => ({
            value: s.app,
            label: `${s.name || s.app}（${s.app}）`,
          }))}
          onChange={(v) => setService(v)}
        />
      </Space>

      {graphQuery.isError ? (
        <QueryErrorAlert error={graphQuery.error} message="加载依赖关系失败" />
      ) : (
        <>
          {data?.note && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message="口径说明"
              description={data.note}
            />
          )}
          {view === 'graph' ? (
            data && data.edges.length > 0 ? (
              <EChart option={apmDependencyGraphOption(data.edges)} height={520} ariaLabel="服务依赖关系图" />
            ) : (
              <Empty description="暂无依赖数据" style={{ padding: 48 }} />
            )
          ) : (
            <SmartTable<ApmDependencyEdge>
              storageKey="apm-dependencies"
              rowKey={(r) => `${r.source}->${r.target}`}
              loading={graphQuery.isLoading}
              columns={columns}
              dataSource={data?.edges}
              scroll={{ x: 880 }}
              locale={{ emptyText: '暂无数据' }}
              onRow={(record) => ({
                onDoubleClick: () => setDetailRecord(record),
                style: { cursor: 'pointer' },
              })}
              pagination={{ pageSize: 20, showTotal: (t) => `共 ${t} 条` }}
            />
          )}
        </>
      )}

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="依赖详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
