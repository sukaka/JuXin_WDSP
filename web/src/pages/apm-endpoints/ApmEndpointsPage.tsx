import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, DatePicker, Radio, Select, Space, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apmApi } from '../../api/apm'
import type { ApmEndpointSort } from '../../api/apm'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import { TREND_RANGE_OPTIONS } from '../../utils/stage6'
import {
  APM_ENDPOINT_OTHER,
  APM_ENDPOINT_UNCLASSIFIED,
  formatMs,
  formatPercent,
  resolveApmTimeRange,
  type ApmRangeValue,
} from '../../utils/apm'
import type { ApmEndpointItem } from '../../types'

const SORT_OPTIONS: { value: ApmEndpointSort; label: string }[] = [
  { value: 'p95', label: '按 P95 时延' },
  { value: 'requests', label: '按请求量' },
  { value: 'error_rate', label: '按错误率' },
]

/** 端点单元格：特殊聚合桶如实标注，避免误读为真实端点 */
function EndpointCell({ endpoint }: { endpoint: string }) {
  if (endpoint === APM_ENDPOINT_UNCLASSIFIED) {
    return (
      <Tooltip title="路径无法归一化，建议检查 API 资产治理">
        <Tag color="orange">未归类端点</Tag>
      </Tooltip>
    )
  }
  if (endpoint === APM_ENDPOINT_OTHER) {
    return <Tag>其它（超出 Top-N）</Tag>
  }
  return <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{endpoint}</Typography.Text>
}

const COLUMNS: ColumnsType<ApmEndpointItem> = [
  {
    title: '端点',
    dataIndex: 'endpoint',
    width: 240,
    ellipsis: true,
    render: (v: string) => <EndpointCell endpoint={v} />,
  },
  { title: '应用', dataIndex: 'app', width: 120, ellipsis: true },
  { title: '方法', dataIndex: 'method', width: 70 },
  {
    title: '路径模板',
    dataIndex: 'path_template',
    width: 200,
    ellipsis: true,
    render: (v: string) =>
      v ? (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Typography.Text>
      ) : (
        '-'
      ),
  },
  { title: '请求量', dataIndex: 'requests', width: 90 },
  {
    title: '错误率',
    dataIndex: 'error_rate',
    width: 90,
    render: (v: number) => (
      <Typography.Text type={v >= 0.05 ? 'danger' : undefined}>{formatPercent(v)}</Typography.Text>
    ),
  },
  { title: '阻断量', dataIndex: 'blocked', width: 80 },
  { title: 'P50', dataIndex: 'p50', width: 90, render: (v: number) => formatMs(v) },
  { title: 'P95', dataIndex: 'p95', width: 90, render: (v: number) => formatMs(v) },
  { title: 'P99', dataIndex: 'p99', width: 90, render: (v: number) => formatMs(v) },
  {
    title: '数据时间',
    dataIndex: 'last_seen_at',
    width: 165,
    render: (v: string) => formatDateTime(v),
  },
]

/** 端点性能（无 Agent 模式）：依赖全量访问日志的端点级 RED 列表 */
export default function ApmEndpointsPage() {
  const [range, setRange] = useState('1h')
  const [customRange, setCustomRange] = useState<ApmRangeValue>(null)
  const [applicationId, setApplicationId] = useState<string | undefined>()
  const [sort, setSort] = useState<ApmEndpointSort>('p95')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApmEndpointItem | null>(null)

  const timeParams = useMemo(() => resolveApmTimeRange(range, customRange), [range, customRange])

  // 应用下拉数据源：当前时间窗内的服务清单（上限 100）
  const appsQuery = useQuery({
    queryKey: ['apm', 'services', 'endpoint-filter-options', timeParams],
    queryFn: () => apmApi.services({ ...timeParams, page: 1, page_size: 100 }),
    retry: false,
  })

  const listQuery = useQuery({
    queryKey: ['apm', 'endpoints', timeParams, applicationId, sort, page, pageSize],
    queryFn: () =>
      apmApi.endpoints({
        ...timeParams,
        application_id: applicationId,
        sort,
        page,
        page_size: pageSize,
      }),
  })

  const data = listQuery.data

  // 操作列提供可见的「查看」入口；双击仅作快捷方式
  const columns: ColumnsType<ApmEndpointItem> = [
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
    <Card title="端点性能" extra={<Tag color="blue">数据来源：无 Agent</Tag>}>
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
        <Select
          placeholder="全部应用"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 240 }}
          loading={appsQuery.isLoading}
          options={(appsQuery.data?.items ?? []).map((s) => ({
            value: s.application_id,
            label: `${s.name || s.app}（${s.app}）`,
          }))}
          onChange={(v) => {
            setApplicationId(v)
            setPage(1)
          }}
        />
        <Select<ApmEndpointSort>
          value={sort}
          style={{ width: 140 }}
          options={SORT_OPTIONS}
          onChange={(v) => {
            setSort(v)
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载端点性能列表失败" />
      ) : data && data.access_log_enabled === false ? (
        <Alert
          type="warning"
          showIcon
          message="端点级数据需开启全量访问日志"
          description="当前未开启全量访问日志（logging.access_log_enabled），端点级性能数据不可用；请联系系统管理员在日志配置中开启后刷新本页。应用级指标请见「服务性能」页。"
        />
      ) : (
        <SmartTable<ApmEndpointItem>
          storageKey="apm-endpoints"
          rowKey={(r) => `${r.application_id}-${r.endpoint}`}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={data?.list}
          scroll={{ x: 1300 }}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
          pagination={{
            current: page,
            pageSize,
            total: data?.total ?? 0,
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
        title="端点详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
