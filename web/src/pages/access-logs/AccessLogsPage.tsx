import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Card, DatePicker, Input, InputNumber, Segmented, Select, Space, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs, { type Dayjs } from 'dayjs'
import ExportDropdown from '../../components/ExportDropdown'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { ApiError } from '../../api/client'
import { accessLogsApi, type AccessLogTrendParams } from '../../api/accessLogs'
import { applicationsApi } from '../../api/applications'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import AccessLogDetailDrawer from './AccessLogDetailDrawer'
import AccessLogTrend from './AccessLogTrend'
import AccessLogFlow from './AccessLogFlow'
import type { AccessLogItem } from '../../types'

type Filters = AccessLogTrendParams

type RangeValue = [Dayjs | null, Dayjs | null] | null

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map((m) => ({
  value: m,
  label: m,
}))

const WAF_ACTION_OPTIONS = [{ value: 'ALLOW', label: '放行' }, { value: 'BLOCK', label: '阻断' }]

type SearchDraft = {
  domain: string
  client_ip: string
  uri: string
  request_id: string
  trace_id: string
  identity_fingerprint: string
  rule_id: string
}

const EMPTY_SEARCH_DRAFT: SearchDraft = {
  domain: '',
  client_ip: '',
  uri: '',
  request_id: '',
  trace_id: '',
  identity_fingerprint: '',
  rule_id: '',
}

function defaultTimeRange(): Filters {
  return {
    start_time: dayjs().subtract(24, 'hour').toISOString(),
    end_time: dayjs().toISOString(),
  }
}

export default function AccessLogsPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canReadApps = hasPermission(permissions, 'applications.read')
  const [filters, setFilters] = useState<Filters>(defaultTimeRange)
  const [draft, setDraft] = useState<SearchDraft>(EMPTY_SEARCH_DRAFT)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [view, setView] = useState<'list' | 'flow'>('list')

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'access-log-audit-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: canReadApps,
  })
  const listQuery = useQuery({
    queryKey: ['access-logs', filters, page, pageSize],
    queryFn: () => accessLogsApi.list({ ...filters, page, page_size: pageSize }),
  })
  const trendQuery = useQuery({
    queryKey: ['access-logs-trend', filters],
    queryFn: () => accessLogsApi.trend(filters),
  })

  const setFilter = (patch: Partial<Filters>) => {
    setFilters((f) => ({ ...f, ...patch }))
    setPage(1)
  }

  const updateSearchDraft = (key: keyof SearchDraft, value: string) => {
    setDraft((prev) => ({ ...prev, [key]: value }))
  }

  const applyDrill = (next: Partial<Filters>) => {
    setFilter(next)
    setDraft((prev) => ({
      ...prev,
      domain: next.domain !== undefined ? next.domain ?? '' : prev.domain,
      client_ip: next.client_ip !== undefined ? next.client_ip ?? '' : prev.client_ip,
      uri: next.uri !== undefined ? next.uri ?? '' : prev.uri,
      request_id: next.request_id !== undefined ? next.request_id ?? '' : prev.request_id,
      trace_id: next.trace_id !== undefined ? next.trace_id ?? '' : prev.trace_id,
      identity_fingerprint:
        next.identity_fingerprint !== undefined ? next.identity_fingerprint ?? '' : prev.identity_fingerprint,
      rule_id: next.rule_id !== undefined ? next.rule_id ?? '' : prev.rule_id,
    }))
    setView('list')
  }

  const resetFilters = () => {
    setFilters(defaultTimeRange())
    setDraft(EMPTY_SEARCH_DRAFT)
    setPage(1)
  }

  /** 导出与列表、趋势共用同一筛选快照（后端上限 10000 行） */
  const exportFiltered = () => window.open(accessLogsApi.exportUrl({ ...filters }), '_blank')

  /** 导出全部：不带任何过滤条件（后端上限 10000 行） */
  const exportAll = () => window.open(accessLogsApi.exportUrl({}), '_blank')

  const onRangeChange = (range: RangeValue) => {
    setFilter({
      start_time: range?.[0]?.toISOString(),
      end_time: range?.[1]?.toISOString(),
    })
  }

  const columns: ColumnsType<AccessLogItem> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    { title: '客户端IP', dataIndex: 'client_ip', width: 125, render: (v: string) => v || '-' },
    { title: '域名', dataIndex: 'domain', width: 170, ellipsis: true },
    { title: '方法', dataIndex: 'request_method', width: 70 },
    {
      title: '请求路径',
      dataIndex: 'request_uri',
      width: 280,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v} placement="topLeft">
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v}</Typography.Text>
        </Tooltip>
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
    {
      title: '耗时',
      dataIndex: 'duration_ms',
      width: 90,
      render: (v: number) => `${v} ms`,
    },
    {
      title: '响应大小',
      dataIndex: 'bytes_out',
      width: 100,
      render: (v: number) => `${v} B`,
    },
    {
      title: 'WAF 动作',
      dataIndex: 'waf_action',
      width: 90,
      render: (v: string) => (v === 'BLOCK' ? <Tag color="red">阻断</Tag> : <Tag>放行</Tag>),
    },
    {
      title: '用户代理',
      dataIndex: 'user_agent_summary',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          onClick={(e) => {
            e.stopPropagation()
            setSelectedId(record.id)
          }}
        >
          详情
        </Button>
      ),
    },
  ]

  return (
    <Card
      title="访问日志"
      extra={
        hasPermission(permissions, 'access_logs.export') && (
          <ExportDropdown onExportFiltered={exportFiltered} onExportAll={exportAll} />
        )
      }
    >
      <Segmented
        aria-label="审计视图"
        value={view}
        onChange={(value) => setView(value as 'list' | 'flow')}
        options={[{ label: '请求列表', value: 'list' }, { label: '审计流向', value: 'flow' }]}
        style={{ marginBottom: 16 }}
      />
      <Space style={{ marginBottom: 16 }} wrap>
        <DatePicker.RangePicker
          showTime
          allowClear={false}
          value={filters.start_time && filters.end_time ? [dayjs(filters.start_time), dayjs(filters.end_time)] : null}
          onChange={onRangeChange}
        />
        {canReadApps && (
          <Select
            aria-label="应用"
            placeholder="应用"
            allowClear
            showSearch
            optionFilterProp="label"
            style={{ width: 190 }}
            value={filters.application_id}
            loading={applicationsQuery.isLoading}
            options={(applicationsQuery.data?.items ?? []).map((application) => ({
              value: application.id,
              label: `${application.name} (${application.code})`,
            }))}
            onChange={(value) => setFilter({ application_id: value || undefined })}
          />
        )}
        <Input.Search
          placeholder="域名"
          allowClear
          style={{ width: 160 }}
          value={draft.domain}
          onChange={(e) => updateSearchDraft('domain', e.target.value)}
          onSearch={(v) => setFilter({ domain: v || undefined })}
        />
        <Input.Search
          placeholder="客户端IP"
          allowClear
          style={{ width: 140 }}
          value={draft.client_ip}
          onChange={(e) => updateSearchDraft('client_ip', e.target.value)}
          onSearch={(v) => setFilter({ client_ip: v || undefined })}
        />
        <Input.Search
          placeholder="请求路径"
          allowClear
          style={{ width: 150 }}
          value={draft.uri}
          onChange={(e) => updateSearchDraft('uri', e.target.value)}
          onSearch={(v) => setFilter({ uri: v || undefined })}
        />
        <Select
          placeholder="方法"
          allowClear
          style={{ width: 100 }}
          value={filters.method}
          options={METHOD_OPTIONS}
          onChange={(v) => setFilter({ method: v })}
        />
        <InputNumber
          placeholder="状态码"
          min={100}
          max={599}
          style={{ width: 110 }}
          value={filters.status ?? null}
          onChange={(v) => setFilter({ status: v ?? undefined })}
        />
        <Select
          placeholder="处理结果"
          allowClear
          style={{ width: 110 }}
          value={filters.waf_action}
          options={WAF_ACTION_OPTIONS}
          onChange={(v) => setFilter({ waf_action: v })}
        />
        <Input.Search
          placeholder="请求 ID"
          allowClear
          maxLength={64}
          style={{ width: 210 }}
          value={draft.request_id}
          onChange={(e) => updateSearchDraft('request_id', e.target.value)}
          onSearch={(v) => setFilter({ request_id: v || undefined })}
        />
        <Input.Search
          placeholder="Trace ID"
          allowClear
          maxLength={32}
          style={{ width: 260 }}
          value={draft.trace_id}
          onChange={(e) => updateSearchDraft('trace_id', e.target.value)}
          onSearch={(v) => setFilter({ trace_id: v || undefined })}
        />
        <Input.Search
          placeholder="身份指纹"
          allowClear
          maxLength={128}
          style={{ width: 210 }}
          value={draft.identity_fingerprint}
          onChange={(e) => updateSearchDraft('identity_fingerprint', e.target.value)}
          onSearch={(v) => setFilter({ identity_fingerprint: v || undefined })}
        />
        <Input.Search
          placeholder="命中规则 ID"
          allowClear
          maxLength={128}
          style={{ width: 190 }}
          value={draft.rule_id}
          onChange={(e) => updateSearchDraft('rule_id', e.target.value)}
          onSearch={(v) => setFilter({ rule_id: v || undefined })}
        />
        <Button onClick={resetFilters}>重置筛选</Button>
      </Space>

      {(filters.request_ids || filters.field_path || filters.endpoint_key) && (
        <Space style={{ marginBottom: 12 }} wrap>
          {filters.request_ids && (
            <Tag
              color="blue"
              closable
              onClose={(e) => {
                e.preventDefault()
                setFilter({ request_ids: undefined })
              }}
            >
              请求集合（{filters.request_ids.split(',').filter(Boolean).length} 条）：{filters.request_ids}
            </Tag>
          )}
          {filters.field_path && (
            <Tag
              color="geekblue"
              closable
              onClose={(e) => {
                e.preventDefault()
                setFilter({ field_path: undefined, direction: undefined, data_type: undefined })
              }}
            >
              敏感字段：{filters.field_path}
            </Tag>
          )}
          {filters.endpoint_key && (
            <Tag
              color="cyan"
              closable
              onClose={(e) => {
                e.preventDefault()
                setFilter({ endpoint_key: undefined })
              }}
            >
              API：{filters.endpoint_key}
            </Tag>
          )}
        </Space>
      )}

      {canReadApps && <QueryErrorAlert error={applicationsQuery.error} message="加载应用列表失败" />}
      <QueryErrorAlert error={trendQuery.error} message="加载访问趋势失败" />
      <AccessLogTrend items={trendQuery.data?.items ?? []} loading={trendQuery.isLoading || trendQuery.isFetching} />

      {view === 'flow' ? (
        <AccessLogFlow filters={filters} onDrill={applyDrill} />
      ) : listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载访问日志失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<AccessLogItem>
          storageKey="access-logs"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1400 }}
          onRow={(record) => ({
            onClick: () => setSelectedId(record.id),
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

      <AccessLogDetailDrawer logId={selectedId} onClose={() => setSelectedId(null)} />
    </Card>
  )
}
