import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Alert, App as AntdApp, Button, Card, DatePicker, Radio, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import dayjs from 'dayjs'
import type { ColumnsType } from 'antd/es/table'
import { apmApi } from '../../api/apm'
import ApmAvailabilityAlert from '../../components/ApmAvailabilityAlert'
import ApmSampleTraceLinks from '../../components/ApmSampleTraceLinks'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import { SEARCH_RANGE_OPTIONS } from '../../utils/stage6'
import {
  APM_MATCH_MODE_META,
  APM_SEARCH_WINDOW_HOURS,
  APM_TRACE_DATA_SOURCE_META,
  APM_TRACE_ID_PATTERN,
  capApmPlainText,
  isCustomRangeOverCap,
  parseApmUrlTimeWindow,
  resolveApmTimeRange,
  type ApmRangeValue,
} from '../../utils/apm'
import type { ApmExceptionItem, ApmExceptionTraceItem } from '../../types'

const COLUMNS: ColumnsType<ApmExceptionItem> = [
  {
    title: '异常类型',
    dataIndex: 'exception_type',
    width: 220,
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
    ),
  },
  {
    title: '指纹',
    dataIndex: 'fingerprint',
    width: 180,
    ellipsis: true,
    // 指纹缩略等宽展示 + Tooltip 全文（聚合口径，不暴露原始堆栈）
    render: (v: string) => (
      <Tooltip title={v}>
        <Typography.Text copyable={{ text: v }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {v && v.length > 16 ? `${v.slice(0, 16)}…` : v || '-'}
        </Typography.Text>
      </Tooltip>
    ),
  },
  { title: '次数', dataIndex: 'count', width: 80 },
  {
    title: '影响服务',
    dataIndex: 'affected_services',
    width: 110,
    render: (v: string[] | null) =>
      v && v.length > 0 ? (
        <Tooltip title={v.join('、')}>
          <Tag>{`${v.length} 个服务`}</Tag>
        </Tooltip>
      ) : (
        '-'
      ),
  },
  {
    title: '首次出现',
    dataIndex: 'first_seen_at',
    width: 165,
    render: (v: string) => formatDateTime(v),
  },
  {
    title: '最近出现',
    dataIndex: 'last_seen_at',
    width: 165,
    render: (v: string) => formatDateTime(v),
  },
  {
    title: '示例 Trace',
    key: 'sample_trace_ids',
    width: 170,
    render: (_, r) => <ApmSampleTraceLinks traceIds={r.sample_trace_ids} />,
  },
]

/** trace 级异常明细列（trace_exact 模式）：消息/堆栈为后端已脱敏文本，一律按纯文本渲染并再限长 */
const TRACE_EXCEPTION_COLUMNS: ColumnsType<ApmExceptionTraceItem> = [
  {
    title: '发生时间',
    dataIndex: 'occurred_at',
    width: 165,
    render: (v: string) => formatDateTime(v),
  },
  { title: '服务', dataIndex: 'service_name', width: 140, ellipsis: true, render: (v: string) => v || '-' },
  {
    title: '异常类型',
    dataIndex: 'exception_type',
    width: 220,
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
    ),
  },
  {
    title: '异常消息（已脱敏）',
    dataIndex: 'exception_message',
    ellipsis: true,
    render: (v: string, r) => (
      <>
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
          {capApmPlainText(v, 500) || '-'}
        </Typography.Text>
        {r.message_truncated && <Tag color="orange">已截断</Tag>}
      </>
    ),
  },
  {
    title: '指纹',
    dataIndex: 'fingerprint',
    width: 140,
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
        {v ? `${v.slice(0, 12)}…` : '-'}
      </Typography.Text>
    ),
  },
]

/** 异常分析（权限 apm.traces.read）：异常指纹聚合列表（类型/次数/影响服务/首末出现）+ 示例 trace 跳转；
 *  data_source=agentless 表示未接入 OTel 数据面，如实降级提示。
 *  P1-01 A3：支持 URL 深链 ?trace_id=（与 start_time/end_time）做 Trace 级定位（trace_exceptions 明细，
 *  堆栈纯文本展示且有长度上限）；match_mode=window_aggregate 时明确标注「同时间窗候选，未精确定位」 */
export default function ApmExceptionsPage() {
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
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApmExceptionItem | null>(null)

  const warningsRef = useRef(urlInit.warnings)
  useEffect(() => {
    for (const w of warningsRef.current) message.warning(w)
    warningsRef.current = []
  }, [message])

  const timeParams = useMemo(() => resolveApmTimeRange(range, customRange), [range, customRange])

  // 服务下拉数据源：当前时间窗内的服务清单（上限 100）
  const servicesQuery = useQuery({
    queryKey: ['apm', 'services', 'exception-filter-options', timeParams],
    queryFn: () => apmApi.services({ ...timeParams, page: 1, page_size: 100 }),
    retry: false,
  })

  const listQuery = useQuery({
    queryKey: ['apm', 'exceptions', timeParams, traceId, service, page, pageSize],
    queryFn: () =>
      apmApi.exceptions({ ...timeParams, trace_id: traceId, service, page, page_size: pageSize }),
  })

  const data = listQuery.data
  const dsMeta = data ? APM_TRACE_DATA_SOURCE_META[data.data_source] : undefined
  const storageUnavailable = data?.availability?.query_state === 'UNAVAILABLE'

  // 操作列提供可见的「查看」入口；双击仅作快捷方式
  const columns: ColumnsType<ApmExceptionItem> = [
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
  const traceExact = traceId != null && matchMode === 'trace_exact'
  const traceExceptions = data?.trace_exceptions ?? []

  return (
    <Card
      title="异常分析"
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
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载异常指纹列表失败" />
      ) : storageUnavailable ? (
        <ApmAvailabilityAlert
          availability={data?.availability}
          onRetry={() => void listQuery.refetch()}
          retryLoading={listQuery.isFetching}
        />
      ) : (
        <>
          {traceId && data && (
            <Alert
              type={traceExact ? 'info' : 'warning'}
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
                      (traceExact
                        ? '以下结果仅来自该 Trace 的异常事件（已脱敏）。'
                        : '以下结果为同时间窗聚合，与该请求无精确对应关系，不代表该请求引发的异常。')}
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
          {data && <ApmAvailabilityAlert availability={data.availability ?? null} />}
          {data && data.data_source === 'agentless' && data.availability == null && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message="当前为无 Agent 数据来源"
              description="未接入语言 Agent（OTel 数据面），异常指纹聚合暂不可用；可在「Agent 管理」页创建注册令牌并为服务接入 Agent 后使用本页。"
            />
          )}
          {traceExact ? (
            traceExceptions.length === 0 ? (
              <Alert
                type="info"
                showIcon
                message="该 Trace 未记录应用异常"
                description="精确定位成功，但该 Trace 的 Span 中没有异常事件；WAF 阻断（403）不属于应用异常。"
              />
            ) : (
              <Table<ApmExceptionTraceItem>
                size="small"
                rowKey={(r) => `${r.span_id}-${r.occurred_at}`}
                pagination={false}
                dataSource={traceExceptions}
                columns={TRACE_EXCEPTION_COLUMNS}
                scroll={{ x: 1000 }}
                expandable={{
                  rowExpandable: (r) => Boolean(r.stacktrace),
                  expandedRowRender: (r) => (
                    <div>
                      {r.stacktrace_truncated && (
                        <Tag color="orange" style={{ marginBottom: 4 }}>
                          堆栈已在采集侧截断
                        </Tag>
                      )}
                      {/* 堆栈一律按纯文本渲染（React 默认转义，HTML/脚本不执行），前端再限长兜底 */}
                      <pre
                        style={{
                          margin: 0,
                          background: '#f5f5f5',
                          padding: 8,
                          borderRadius: 4,
                          fontSize: 12,
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                          maxHeight: 320,
                          overflow: 'auto',
                        }}
                      >
                        {capApmPlainText(r.stacktrace)}
                      </pre>
                    </div>
                  ),
                }}
              />
            )
          ) : (
            <SmartTable<ApmExceptionItem>
              storageKey="apm-exceptions"
              rowKey={(r) => `${r.exception_type}-${r.fingerprint}`}
              loading={listQuery.isLoading}
              columns={columns}
              dataSource={data?.list}
              scroll={{ x: 1150 }}
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
          )}
        </>
      )}

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="异常详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
