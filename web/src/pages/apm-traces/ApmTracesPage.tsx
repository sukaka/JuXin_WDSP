import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  DatePicker,
  Input,
  InputNumber,
  Radio,
  Space,
  Tag,
  Typography,
} from 'antd'
import dayjs from 'dayjs'
import type { ColumnsType } from 'antd/es/table'
import { apmApi } from '../../api/apm'
import ApmAvailabilityAlert, { ApmIngestWatermark } from '../../components/ApmAvailabilityAlert'
import ApmCorrelationNotice from '../../components/ApmCorrelationNotice'
import ApmTraceDrawer from '../../components/ApmTraceDrawer'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import { SEARCH_RANGE_OPTIONS } from '../../utils/stage6'
import {
  APM_APPLICATION_ID_PATTERN,
  APM_SEARCH_WINDOW_HOURS,
  APM_TRACE_DATA_SOURCE_META,
  APM_TRACE_ID_PATTERN,
  formatMs,
  isApmIngestionPending,
  isCustomRangeOverCap,
  nextApmIngestRetryDelay,
  parseApmUrlTimeWindow,
  resolveApmTimeRange,
  sanitizeApmReturnPath,
  type ApmRangeValue,
} from '../../utils/apm'
import type { ApmTraceSearchItem } from '../../types'

interface Filters {
  service?: string
  trace_id?: string
  request_id?: string
  application_id?: string
  min_duration_ms?: number
  error?: boolean
}

/** service 等自由文本 URL 参数的长度护栏（超长视为非法，忽略并提示） */
const URL_TEXT_PARAM_MAX = 128

const COLUMNS: ColumnsType<ApmTraceSearchItem> = [
  {
    title: 'Trace ID',
    dataIndex: 'trace_id',
    width: 130,
    render: (v: string) => (
      // 缩略展示 + 点击复制完整值；阻止冒泡避免触发行点击打开抽屉
      <span onClick={(e) => e.stopPropagation()}>
        <Typography.Text copyable={{ text: v }} style={{ fontFamily: 'monospace', fontSize: 12 }}>
          {v ? `${v.slice(0, 8)}…` : '-'}
        </Typography.Text>
      </span>
    ),
  },
  { title: '根服务', dataIndex: 'root_service', width: 140, ellipsis: true },
  {
    title: '根操作',
    dataIndex: 'root_operation',
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
    ),
  },
  {
    title: '开始时间',
    dataIndex: 'start_time',
    width: 165,
    render: (v: string) => formatDateTime(v),
  },
  { title: '耗时', dataIndex: 'duration_ms', width: 100, render: (v: number) => formatMs(v) },
  { title: 'Span 数', dataIndex: 'span_count', width: 90 },
  {
    title: '错误数',
    dataIndex: 'error_count',
    width: 80,
    render: (v: number) => (
      <Typography.Text type={v > 0 ? 'danger' : undefined}>{v}</Typography.Text>
    ),
  },
  {
    title: '涉及服务',
    dataIndex: 'services',
    width: 180,
    ellipsis: true,
    render: (v: string[] | null) => (v && v.length > 0 ? v.join('、') : '-'),
  },
]

/** 调用链检索（权限 apm.traces.read）：按时间窗/服务/trace/request/时延/错误筛选 OTel 调用链。
 *  五态缺数据 UX（P1-01 A3）：加载中 / 等待入库（PENDING 或 INGESTION_DELAY_CONFIRMED，最多自动等待 30 秒）/
 *  无匹配（EMPTY+NO_MATCH）/ 无权限（403，不泄露存储或数据是否存在）/ 存储不可用（UNAVAILABLE，可重试）；
 *  URL 预填识别 trace_id/request_id/service/application_id/start_time/end_time/from（非法值忽略并提示）；
 *  旧后端缺 availability/correlation 字段时显示「状态信息不足」，不编造原因 */
export default function ApmTracesPage() {
  const { message } = AntdApp.useApp()
  const [searchParams] = useSearchParams()

  // URL 预填解析一次（非法值忽略并记录提示文案；from 仅接受站内白名单路由，防开放重定向）
  const [urlInit] = useState(() => {
    const warnings: string[] = []
    const tid = searchParams.get('trace_id')?.trim() ?? ''
    if (tid && !APM_TRACE_ID_PATTERN.test(tid)) {
      warnings.push('URL 参数 Trace ID 格式非法（需 32 位十六进制），已忽略')
    }
    const svc = searchParams.get('service')?.trim() ?? ''
    if (svc && svc.length > URL_TEXT_PARAM_MAX) {
      warnings.push('URL 参数服务名超长，已忽略')
    }
    const appId = searchParams.get('application_id')?.trim() ?? ''
    if (appId && !APM_APPLICATION_ID_PATTERN.test(appId)) {
      warnings.push('URL 参数应用 ID 格式非法（需 UUID），已忽略')
    }
    const win = parseApmUrlTimeWindow(searchParams.get('start_time'), searchParams.get('end_time'))
    if (win && 'error' in win) warnings.push(win.error)
    const fromRaw = searchParams.get('from')
    const from = sanitizeApmReturnPath(fromRaw)
    if (fromRaw && !from) warnings.push('URL 参数返回地址不是允许的站内地址，已忽略')
    return {
      filters: {
        trace_id: APM_TRACE_ID_PATTERN.test(tid) ? tid.toLowerCase() : undefined,
        request_id: searchParams.get('request_id')?.trim() || undefined,
        service: svc && svc.length <= URL_TEXT_PARAM_MAX ? svc : undefined,
        application_id:
          appId && APM_APPLICATION_ID_PATTERN.test(appId) ? appId : undefined,
      } as Filters,
      customWindow: win && !('error' in win) ? win : null,
      warnings,
      from,
    }
  })

  const [range, setRange] = useState(urlInit.customWindow ? 'custom' : '1h')
  const [customRange, setCustomRange] = useState<ApmRangeValue>(() =>
    urlInit.customWindow
      ? [dayjs(urlInit.customWindow.start_time), dayjs(urlInit.customWindow.end_time)]
      : null,
  )
  const [filters, setFilters] = useState<Filters>(urlInit.filters)
  const [minDurationDraft, setMinDurationDraft] = useState<number | null>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null)

  // 非法 URL 参数提示仅在挂载时播报一次
  const warningsRef = useRef(urlInit.warnings)
  useEffect(() => {
    for (const w of warningsRef.current) message.warning(w)
    warningsRef.current = []
  }, [message])

  const timeParams = useMemo(() => resolveApmTimeRange(range, customRange), [range, customRange])

  const setFilter = (patch: Partial<Filters>) => {
    setFilters((f) => ({ ...f, ...patch }))
    setPage(1)
  }

  const searchTraceId = (value: string) => {
    const v = value.trim()
    if (!v) {
      setFilter({ trace_id: undefined })
      return
    }
    if (!APM_TRACE_ID_PATTERN.test(v)) {
      message.warning('Trace ID 格式不正确（应为 32 位十六进制字符）')
      return
    }
    setFilter({ trace_id: v.toLowerCase() })
  }

  const applyMinDuration = () => {
    setFilter({ min_duration_ms: minDurationDraft ?? undefined })
  }

  const listQuery = useQuery({
    queryKey: ['apm', 'trace-search', timeParams, filters, page, pageSize],
    queryFn: () =>
      apmApi.traceSearch({
        ...timeParams,
        service: filters.service,
        trace_id: filters.trace_id,
        request_id: filters.request_id,
        application_id: filters.application_id,
        min_duration_ms: filters.min_duration_ms,
        error: filters.error || undefined,
        page,
        page_size: pageSize,
      }),
  })

  const data = listQuery.data
  const dsMeta = data ? APM_TRACE_DATA_SOURCE_META[data.data_source] : undefined
  const availability = data?.availability ?? null
  // 旧后端缺 availability 字段：显示「状态信息不足」，走旧版 agentless 提示，不做状态推断
  const availabilityMissing = data != null && data.availability == null
  const storageUnavailable = availability?.query_state === 'UNAVAILABLE'
  const waiting = data != null && isApmIngestionPending(data)
  const noMatch =
    !waiting &&
    ((availability?.query_state === 'EMPTY' &&
      (availability.reason_codes ?? []).includes('NO_MATCH')) ||
      data?.correlation?.state === 'NOT_FOUND')

  // 等待入库的有界自动重试：每 5 秒一次、总计最多 30 秒，超时后只保留手动刷新；卸载即清理定时器
  const waitStartRef = useRef<number | null>(null)
  const [waitExhausted, setWaitExhausted] = useState(false)
  const refetch = listQuery.refetch
  const dataUpdatedAt = listQuery.dataUpdatedAt
  useEffect(() => {
    if (!waiting) {
      waitStartRef.current = null
      setWaitExhausted(false)
      return
    }
    if (waitStartRef.current === null) waitStartRef.current = Date.now()
    const delay = nextApmIngestRetryDelay(Date.now() - waitStartRef.current)
    if (delay === null) {
      setWaitExhausted(true)
      return
    }
    const timer = setTimeout(() => {
      void refetch()
    }, delay)
    return () => clearTimeout(timer)
  }, [waiting, dataUpdatedAt, refetch])

  return (
    <Card
      title="调用链检索"
      extra={dsMeta && <Tag color={dsMeta.color}>数据来源：{dsMeta.label}</Tag>}
    >
      <Space style={{ marginBottom: 16 }} wrap>
        {urlInit.from && (
          <Link to={urlInit.from.path}>
            <Button size="small">← {urlInit.from.label}</Button>
          </Link>
        )}
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
        <Input.Search
          placeholder="服务名"
          allowClear
          style={{ width: 180 }}
          defaultValue={filters.service}
          onSearch={(v) => setFilter({ service: v.trim() || undefined })}
        />
        <Input.Search
          placeholder="Trace ID（32 位十六进制）"
          allowClear
          style={{ width: 240 }}
          defaultValue={filters.trace_id}
          onSearch={searchTraceId}
        />
        <Input.Search
          placeholder="请求 ID"
          allowClear
          style={{ width: 200 }}
          defaultValue={filters.request_id}
          onSearch={(v) => setFilter({ request_id: v.trim() || undefined })}
        />
        {filters.application_id && (
          <Tag closable onClose={() => setFilter({ application_id: undefined })}>
            应用：{filters.application_id}
          </Tag>
        )}
        <InputNumber
          placeholder="最小时长 ms"
          min={0}
          style={{ width: 130 }}
          value={minDurationDraft}
          onChange={(v) => setMinDurationDraft(v)}
          onBlur={applyMinDuration}
          onPressEnter={applyMinDuration}
        />
        <Checkbox
          checked={filters.error === true}
          onChange={(e) => setFilter({ error: e.target.checked || undefined })}
        >
          仅错误链路
        </Checkbox>
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载调用链检索结果失败" />
      ) : storageUnavailable ? (
        <ApmAvailabilityAlert
          availability={availability}
          onRetry={() => void refetch()}
          retryLoading={listQuery.isFetching}
        />
      ) : (
        <>
          {availabilityMissing && <ApmAvailabilityAlert availability={null} />}
          {!availabilityMissing && availability && (
            <ApmAvailabilityAlert availability={availability} />
          )}
          {data && data.data_source === 'agentless' && availabilityMissing && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message="当前为无 Agent 数据来源"
              description="未配置 OTel 存储（DSN），调用链检索暂不可用；可在「性能总览」页按 Trace ID 检索网关访问记录，或接入 Agent 后使用本页。"
            />
          )}
          {waiting && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message={
                waitExhausted ? '数据尚未入库，自动等待已结束' : '数据可能仍在入库，正在自动等待'
              }
              description={
                <Space direction="vertical" size={6}>
                  <ApmIngestWatermark availability={availability} />
                  {data?.correlation?.reason && (
                    <Typography.Text style={{ fontSize: 12 }}>
                      {data.correlation.reason}
                    </Typography.Text>
                  )}
                  {!waitExhausted ? (
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      每 5 秒自动重试一次，最多自动等待 30 秒，之后请手动刷新。
                    </Typography.Text>
                  ) : (
                    <Space wrap>
                      <Button size="small" loading={listQuery.isFetching} onClick={() => void refetch()}>
                        手动刷新
                      </Button>
                      <Link to="/apm-agents">
                        <Button size="small" type="link">
                          前往「Agent 管理」排查数据面
                        </Button>
                      </Link>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        详细步骤见《APM 排障手册》
                      </Typography.Text>
                    </Space>
                  )}
                </Space>
              }
            />
          )}
          {noMatch && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message="未找到匹配的调用链"
              description={
                data?.correlation?.reason ||
                '在当前时间窗与筛选条件下没有匹配记录；如目标请求刚发生，可能尚未入库，可稍后重试。'
              }
            />
          )}
          {data?.correlation && data.correlation.state !== 'NOT_FOUND' && !waiting && (
            <ApmCorrelationNotice
              correlation={data.correlation}
              onSelectTrace={(id) => setSelectedTraceId(id)}
            />
          )}
          <SmartTable<ApmTraceSearchItem>
            storageKey="apm-traces"
            rowKey="trace_id"
            loading={listQuery.isLoading}
            columns={COLUMNS}
            dataSource={data?.list}
            scroll={{ x: 1100 }}
            locale={{ emptyText: '暂无数据' }}
            onRow={(record) => ({
              onClick: () => setSelectedTraceId(record.trace_id),
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

      <ApmTraceDrawer
        traceId={selectedTraceId}
        onClose={() => setSelectedTraceId(null)}
        context={{
          start_time: timeParams.start_time,
          end_time: timeParams.end_time,
          application_id: filters.application_id,
        }}
        onSelectTrace={(id) => setSelectedTraceId(id)}
      />
    </Card>
  )
}
