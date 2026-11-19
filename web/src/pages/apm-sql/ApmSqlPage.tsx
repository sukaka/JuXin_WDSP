import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Alert, App as AntdApp, Button, Card, DatePicker, Input, Radio, Select, Space, Tag, Tooltip, Typography } from 'antd'
import dayjs from 'dayjs'
import type { ColumnsType } from 'antd/es/table'
import { apmApi, type ApmSqlSort } from '../../api/apm'
import ApmAvailabilityAlert from '../../components/ApmAvailabilityAlert'
import ApmSampleTraceLinks from '../../components/ApmSampleTraceLinks'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { SEARCH_RANGE_OPTIONS } from '../../utils/stage6'
import {
  APM_MATCH_MODE_META,
  APM_SEARCH_WINDOW_HOURS,
  APM_TRACE_DATA_SOURCE_META,
  APM_TRACE_ID_PATTERN,
  formatMs,
  isCustomRangeOverCap,
  parseApmUrlTimeWindow,
  resolveApmTimeRange,
  type ApmRangeValue,
} from '../../utils/apm'
import type { ApmSqlFingerprintItem } from '../../types'

const SORT_OPTIONS: { value: ApmSqlSort; label: string }[] = [
  { value: 'calls', label: '按调用数' },
  { value: 'avg_ms', label: '按平均耗时' },
  { value: 'p95_ms', label: '按 P95 耗时' },
]

const COLUMNS: ColumnsType<ApmSqlFingerprintItem> = [
  {
    title: 'SQL 指纹',
    dataIndex: 'sql_fingerprint',
    width: 220,
    ellipsis: true,
    // 只出指纹不出原始 SQL（APM 设计 §12 数据最小化）：缩略等宽展示 + Tooltip 全文
    render: (v: string) => (
      <Tooltip title={v}>
        <Typography.Text copyable={{ text: v }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {v && v.length > 16 ? `${v.slice(0, 16)}…` : v || '-'}
        </Typography.Text>
      </Tooltip>
    ),
  },
  { title: '数据库类型', dataIndex: 'db_system', width: 110, render: (v: string) => v || '-' },
  {
    title: '命名空间',
    dataIndex: 'namespace',
    width: 140,
    ellipsis: true,
    render: (v: string) => v || '-',
  },
  {
    title: '操作',
    dataIndex: 'operation',
    width: 160,
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
    ),
  },
  { title: '调用数', dataIndex: 'calls', width: 90 },
  {
    title: '错误数',
    dataIndex: 'error_count',
    width: 80,
    render: (v: number) => (
      <Typography.Text type={v > 0 ? 'danger' : undefined}>{v}</Typography.Text>
    ),
  },
  { title: '平均耗时', dataIndex: 'avg_ms', width: 100, render: (v: number) => formatMs(v) },
  { title: 'P95 耗时', dataIndex: 'p95_ms', width: 100, render: (v: number) => formatMs(v) },
  {
    title: '示例 Trace',
    key: 'sample_trace_ids',
    width: 170,
    render: (_, r) => <ApmSampleTraceLinks traceIds={r.sample_trace_ids} />,
  },
]

/** SQL 诊断（权限 apm.sql.read）：SQL 指纹聚合列表（调用数/错误数/avg/p95）+ 示例 trace 跳转；
 *  data_source=agentless 表示未接入 OTel 数据面，展示接入指引；页头如实标识数据来源。
 *  P1-01 A3：支持 URL 深链 ?trace_id=（与 start_time/end_time）做 Trace 级定位；
 *  match_mode=window_aggregate 时明确标注「同时间窗候选，未精确定位」，不写成已定位根因 */
export default function ApmSqlPage() {
  const { message } = AntdApp.useApp()
  const [searchParams] = useSearchParams()

  // URL 深链参数解析一次（非法值忽略并提示）：trace_id（32 hex）与 start_time/end_time 时间窗
  const [urlInit] = useState(() => {
    const warnings: string[] = []
    const tid = searchParams.get('trace_id')?.trim() ?? ''
    if (tid && !APM_TRACE_ID_PATTERN.test(tid)) {
      warnings.push('URL 参数 trace_id 格式非法（需 32 位十六进制），已忽略')
    }
    const win = parseApmUrlTimeWindow(searchParams.get('start_time'), searchParams.get('end_time'))
    if (win && 'error' in win) warnings.push(win.error)
    return {
      traceId: APM_TRACE_ID_PATTERN.test(tid) ? tid.toLowerCase() : undefined,
      customWindow: win && !('error' in win) ? win : null,
      warnings,
    }
  })

  const [range, setRange] = useState(urlInit.customWindow ? 'custom' : '1h')
  const [customRange, setCustomRange] = useState<ApmRangeValue>(() =>
    urlInit.customWindow
      ? [dayjs(urlInit.customWindow.start_time), dayjs(urlInit.customWindow.end_time)]
      : null,
  )
  const [traceId, setTraceId] = useState<string | undefined>(urlInit.traceId)
  const [service, setService] = useState<string | undefined>()
  const [dbSystem, setDbSystem] = useState<string | undefined>()
  const [sort, setSort] = useState<ApmSqlSort>('calls')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApmSqlFingerprintItem | null>(null)

  const warningsRef = useRef(urlInit.warnings)
  useEffect(() => {
    for (const w of warningsRef.current) message.warning(w)
    warningsRef.current = []
  }, [message])

  const timeParams = useMemo(() => resolveApmTimeRange(range, customRange), [range, customRange])

  // 服务下拉数据源：当前时间窗内的服务清单（上限 100）
  const servicesQuery = useQuery({
    queryKey: ['apm', 'services', 'sql-filter-options', timeParams],
    queryFn: () => apmApi.services({ ...timeParams, page: 1, page_size: 100 }),
    retry: false,
  })

  const listQuery = useQuery({
    queryKey: ['apm', 'sql', timeParams, traceId, service, dbSystem, sort, page, pageSize],
    queryFn: () =>
      apmApi.sql({
        ...timeParams,
        trace_id: traceId,
        service,
        db_system: dbSystem,
        sort,
        page,
        page_size: pageSize,
      }),
  })

  const data = listQuery.data
  const dsMeta = data ? APM_TRACE_DATA_SOURCE_META[data.data_source] : undefined
  const storageUnavailable = data?.availability?.query_state === 'UNAVAILABLE'

  // 操作列提供可见的「查看」入口；双击仅作快捷方式
  const columns: ColumnsType<ApmSqlFingerprintItem> = [
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

  // Trace 定位横幅：match_mode 如实标注定位语义；旧后端缺 match_mode 时按「状态信息不足」处理
  const matchMode = data?.match_mode
  const matchMeta = matchMode ? APM_MATCH_MODE_META[matchMode] : undefined

  return (
    <Card
      title="SQL 诊断"
      extra={
        data && (
          <Tag color={dsMeta?.color ?? 'default'}>数据来源：{dsMeta?.label ?? data.data_source}</Tag>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Radio.Group
          value={range}
          onChange={(e) => {
            setRange(String(e.target.value))
            setPage(1)
          }}
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
              setPage(1)
            }}
            size="small"
          />
        )}
        {traceId && (
          <Tag closable onClose={() => setTraceId(undefined)}>
            Trace：{traceId.slice(0, 8)}…
          </Tag>
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
          onChange={(v) => {
            setService(v)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="数据库类型（如 mysql）"
          allowClear
          style={{ width: 200 }}
          onSearch={(v) => {
            setDbSystem(v.trim() || undefined)
            setPage(1)
          }}
        />
        <Radio.Group
          value={sort}
          onChange={(e) => {
            setSort(e.target.value as ApmSqlSort)
            setPage(1)
          }}
          options={SORT_OPTIONS}
          optionType="button"
          size="small"
        />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载 SQL 指纹列表失败" />
      ) : storageUnavailable ? (
        <ApmAvailabilityAlert
          availability={data?.availability}
          onRetry={() => void listQuery.refetch()}
          retryLoading={listQuery.isFetching}
        />
      ) : data && data.data_source === 'agentless' && data.availability == null ? (
        <Alert
          type="warning"
          showIcon
          message="SQL 诊断需接入 OTel 数据面"
          description={
            data.message ||
            '当前未接入语言 Agent（OTel 数据面），SQL 指纹聚合不可用；请在「Agent 管理」页创建注册令牌并为服务接入 Agent 后刷新本页。'
          }
        />
      ) : (
        <>
          {traceId && data && (
            <Alert
              type={matchMode === 'trace_exact' ? 'info' : 'warning'}
              showIcon
              style={{ marginBottom: 12 }}
              message={
                matchMeta
                  ? `${matchMeta.label}：Trace ${traceId.slice(0, 8)}…`
                  : '状态信息不足：当前服务未返回定位语义，以下结果按时间窗聚合理解'
              }
              description={
                <Space direction="vertical" size={4}>
                  <span>
                    {data.match_note ||
                      (matchMode === 'trace_exact'
                        ? '以下结果仅来自该 Trace 的数据库调用 Span。'
                        : '以下结果为同时间窗聚合，与该请求无精确对应关系，不代表该请求的慢 SQL。')}
                  </span>
                  <span>
                    <Button size="small" onClick={() => setTraceId(undefined)}>
                      清除 Trace 定位
                    </Button>
                  </span>
                </Space>
              }
            />
          )}
          {data && data.data_source === 'agentless' && data.availability != null && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 12 }}
              message="SQL 诊断需接入 OTel 数据面"
              description={
                data.message ||
                '当前未接入语言 Agent（OTel 数据面），SQL 指纹聚合不可用；请在「Agent 管理」页创建注册令牌并为服务接入 Agent 后刷新本页。'
              }
            />
          )}
          {data && <ApmAvailabilityAlert availability={data.availability ?? null} />}
          {data?.message && !traceId && (
            <Alert type="info" showIcon style={{ marginBottom: 12 }} message={data.message} />
          )}
          <SmartTable<ApmSqlFingerprintItem>
            storageKey="apm-sql"
            rowKey={(r) => `${r.db_system}-${r.namespace}-${r.sql_fingerprint}`}
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={data?.list}
            scroll={{ x: 1250 }}
            locale={{ emptyText: '暂无数据' }}
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
        </>
      )}

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="SQL 指纹详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
