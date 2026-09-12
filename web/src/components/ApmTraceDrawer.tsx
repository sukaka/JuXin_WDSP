import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Drawer, Space, Spin, Table, Tag, Typography } from 'antd'
import { Link } from 'react-router-dom'
import type { ColumnsType } from 'antd/es/table'
import { apmApi } from '../api/apm'
import { ApiError } from '../api/client'
import ApmAvailabilityAlert from './ApmAvailabilityAlert'
import ApmCorrelationNotice from './ApmCorrelationNotice'
import QueryErrorAlert from './QueryErrorAlert'
import ApmTraceWaterfall from './ApmTraceWaterfall'
import { useAuthStore } from '../stores/auth'
import { formatDateTime } from '../utils/format'
import { hasPermission } from '../utils/permission'
import { APM_TRACE_DATA_SOURCE_META, APM_WAF_ACTION_META } from '../utils/apm'
import type { ApmTraceAccessLog, ApmTraceDetail, ApmTraceSecurityEvent } from '../types'

/** Trace 详情查询上下文（P1-01 A3）：详情与下钻携带相同时间窗；application_id 仅用于展示与下钻透传 */
export interface ApmTraceDrawerContext {
  start_time?: string
  end_time?: string
  application_id?: string
}

const TRACE_LOG_COLUMNS: ColumnsType<ApmTraceAccessLog> = [
  { title: '时间', dataIndex: 'occurred_at', width: 160, render: (v: string) => formatDateTime(v) },
  { title: '域名', dataIndex: 'domain', width: 150, ellipsis: true },
  { title: '方法', dataIndex: 'request_method', width: 70 },
  {
    title: '请求路径',
    dataIndex: 'request_path',
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
    ),
  },
  {
    title: '状态码',
    dataIndex: 'response_status',
    width: 80,
    render: (v: number) => (
      <Typography.Text type={v >= 500 ? 'danger' : v >= 400 ? 'warning' : undefined}>
        {v || '-'}
      </Typography.Text>
    ),
  },
  { title: '耗时', dataIndex: 'duration_ms', width: 90, render: (v: number) => `${v} ms` },
  { title: 'TTFB', dataIndex: 'ttfb_ms', width: 90, render: (v: number) => `${v} ms` },
  {
    title: 'WAF 动作',
    dataIndex: 'waf_action',
    width: 80,
    render: (v: string) => {
      const meta = APM_WAF_ACTION_META[v] ?? APM_WAF_ACTION_META.ALLOW
      return <Tag color={meta.color}>{meta.label}</Tag>
    },
  },
  { title: '端点', dataIndex: 'endpoint_key', width: 160, ellipsis: true },
]

const TRACE_EVENT_COLUMNS: ColumnsType<ApmTraceSecurityEvent> = [
  { title: '时间', dataIndex: 'occurred_at', width: 160, render: (v: string) => formatDateTime(v) },
  {
    title: '动作',
    dataIndex: 'action',
    width: 80,
    render: (v: string) => {
      const meta = APM_WAF_ACTION_META[v]
      return meta ? <Tag color={meta.color}>{meta.label}</Tag> : v
    },
  },
  { title: '命中规则', dataIndex: 'rule_id', width: 140, ellipsis: true },
  {
    title: '请求 ID',
    dataIndex: 'request_id',
    ellipsis: true,
    render: (v: string) => (
      <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
    ),
  },
]

/** Trace 详情内容：otel_spans 存在时渲染瀑布图，否则降级为「访问记录 + 关联 WAF 事件」视图；
 *  头部展示关联强度（correlation）与数据完整性（availability/partial），SQL/异常下钻携带相同时间窗且按权限裁剪 */
function TraceDetailContent({
  trace,
  context,
  onSelectTrace,
}: {
  trace: ApmTraceDetail
  context?: ApmTraceDrawerContext
  onSelectTrace?: (traceId: string) => void
}) {
  const permissions = useAuthStore((s) => s.user?.permissions)
  // 权限裁剪（P1-01 §5-6）：无 apm.sql.read 不展示 SQL 下钻入口（接口另有兜底校验）
  const canSqlDrill = hasPermission(permissions, 'apm.sql.read')
  const canExceptionDrill = hasPermission(permissions, 'apm.traces.read')

  // 运行时归一化：旧数据结构/异常载荷中 access_logs、security_events、otel_spans 可能为 null/缺失，
  // 一律归一为空数组，避免渲染崩溃（L27）
  const spans = Array.isArray(trace.otel_spans) ? trace.otel_spans : []
  const accessLogs = Array.isArray(trace.access_logs) ? trace.access_logs : []
  const securityEvents = Array.isArray(trace.security_events) ? trace.security_events : []
  const hasSpans = spans.length > 0
  const hasLogs = accessLogs.length > 0
  const hasEvents = securityEvents.length > 0
  const dsMeta = APM_TRACE_DATA_SOURCE_META[trace.data_source ?? 'agentless']

  // 下钻 SQL/异常携带相同 trace_id 与时间窗（无上下文窗口时下钻页按默认时间窗自查）
  const drillParams = new URLSearchParams()
  drillParams.set('trace_id', trace.trace_id)
  if (context?.start_time && context?.end_time) {
    drillParams.set('start_time', context.start_time)
    drillParams.set('end_time', context.end_time)
  }
  const drillQuery = drillParams.toString()

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Space wrap>
        <Typography.Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>
          trace_id：{trace.trace_id}
        </Typography.Text>
        {dsMeta && <Tag color={dsMeta.color}>数据来源：{dsMeta.label}</Tag>}
        {typeof trace.span_count === 'number' && (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            共 {trace.span_count} 个 span
          </Typography.Text>
        )}
        {canSqlDrill && (
          <Link to={`/apm-sql?${drillQuery}`}>
            <Button size="small">下钻 SQL 诊断</Button>
          </Link>
        )}
        {canExceptionDrill && (
          <Link to={`/apm-exceptions?${drillQuery}`}>
            <Button size="small">下钻异常分析</Button>
          </Link>
        )}
      </Space>
      {trace.correlation ? (
        <ApmCorrelationNotice
          correlation={trace.correlation}
          currentTraceId={trace.trace_id}
          onSelectTrace={onSelectTrace}
        />
      ) : (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          关联状态信息不足（当前服务未返回关联判定）
        </Typography.Text>
      )}
      <ApmAvailabilityAlert availability={trace.availability} />
      {(trace.partial || trace.note) && (
        <Alert
          type="warning"
          showIcon
          message={trace.note || '结果不完整（可能因采样或保留期截断）'}
        />
      )}
      {trace.truncated && (
        <Alert
          type="warning"
          showIcon
          message="span 数量超出返回上限，结果已截断，瀑布图仅展示部分链路"
        />
      )}
      {!hasSpans && !hasLogs && !hasEvents ? (
        trace.correlation?.state === 'NOT_EXPECTED' ? (
          <Alert
            type="info"
            showIcon
            message="该请求已在网关终止且未调用源站，无应用调用链为预期结果"
          />
        ) : (
          <Alert type="info" showIcon message="未命中，可能未采样或已超保留期" />
        )
      ) : (
        <>
          {hasSpans && (
            <div>
              <Typography.Title level={5}>调用链瀑布</Typography.Title>
              <ApmTraceWaterfall spans={spans} />
            </div>
          )}
          {hasLogs && (
            <div>
              <Typography.Title level={5}>访问记录（{accessLogs.length}）</Typography.Title>
              <Table<ApmTraceAccessLog>
                size="small"
                rowKey="id"
                pagination={false}
                dataSource={accessLogs}
                columns={TRACE_LOG_COLUMNS}
                scroll={{ x: 1000 }}
              />
            </div>
          )}
          {(hasEvents || !hasSpans) && (
            <div>
              <Typography.Title level={5}>
                关联 WAF 事件（{securityEvents.length}）
              </Typography.Title>
              {hasEvents ? (
                <Table<ApmTraceSecurityEvent>
                  size="small"
                  rowKey="id"
                  pagination={false}
                  dataSource={securityEvents}
                  columns={TRACE_EVENT_COLUMNS}
                />
              ) : (
                <Typography.Text type="secondary">无关联安全事件</Typography.Text>
              )}
            </div>
          )}
        </>
      )}
    </Space>
  )
}

/**
 * Trace 检索结果抽屉（overview 页 trace 检索与调用链检索页共用）：
 * 自带 trace 查询（携带调用方时间窗上下文）；404 视为未命中；otel_spans 存在时渲染瀑布图，否则降级为访问记录视图。
 */
export default function ApmTraceDrawer({
  traceId,
  onClose,
  context,
  onSelectTrace,
}: {
  traceId: string | null
  onClose: () => void
  context?: ApmTraceDrawerContext
  onSelectTrace?: (traceId: string) => void
}) {
  const traceQuery = useQuery({
    queryKey: ['apm', 'trace', traceId, context?.start_time, context?.end_time],
    queryFn: () =>
      apmApi.trace(traceId as string, {
        start_time: context?.start_time,
        end_time: context?.end_time,
      }),
    enabled: traceId !== null,
    retry: false,
  })

  const trace = traceQuery.data
  // 404 视为未命中（可能未采样或已超保留期），不按错误展示
  const traceMissed =
    traceQuery.isError && traceQuery.error instanceof ApiError && traceQuery.error.status === 404

  return (
    <Drawer title="Trace 检索结果" open={traceId !== null} onClose={onClose} width={900}>
      {traceQuery.isLoading ? (
        <div style={{ textAlign: 'center', padding: 48 }}>
          <Spin />
        </div>
      ) : traceMissed ? (
        <Alert type="info" showIcon message="未命中，可能未采样或已超保留期" />
      ) : traceQuery.isError ? (
        <QueryErrorAlert error={traceQuery.error} message="检索 Trace 失败" />
      ) : trace ? (
        <TraceDetailContent trace={trace} context={context} onSelectTrace={onSelectTrace} />
      ) : null}
    </Drawer>
  )
}
