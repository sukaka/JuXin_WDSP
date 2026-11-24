import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Button,
  Card,
  Segmented,
  Select,
  Space,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  apiFindingsApi,
  type ApiFinding,
  type ApiFindingSummaryBucket,
  type ApiFindingSummaryGroupBy,
} from '../../api/apiSecurity'
import {
  ApiFindingActionModals,
  ApiFindingDetailDrawer,
  ApiFindingInlineActions,
  FindingTypeTag,
} from '../../components/ApiFindingHandling'
import { useApiFindingHandling } from '../../components/useApiFindingHandling'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import {
  API_FINDING_SEVERITY_FILTER_OPTIONS,
  API_FINDING_SEVERITY_META,
  API_FINDING_STATUS_META,
  API_FINDING_TYPE_META,
  API_SUBJECT_TYPE_META,
  formatApiFindingTitle,
  getApiFindingTypeMeta,
} from '../../utils/stage8'

/** 汇总三视图的中文名与首列标题 */
const SUMMARY_VIEW_META: Record<ApiFindingSummaryGroupBy, { label: string; column: string }> = {
  subject: { label: '按主体', column: '主体' },
  endpoint: { label: '按接口', column: '接口' },
  type: { label: '按类型', column: '类型' },
}

/** 汇总桶行 key：按视图取相应维度字段（匿名主体/未关联端点为空串，退化为稳定常量） */
function summaryRowKey(view: ApiFindingSummaryGroupBy, r: ApiFindingSummaryBucket): string {
  if (view === 'subject') return `${r.subject_type ?? ''}|${r.subject_id ?? ''}`
  if (view === 'endpoint') return r.endpoint_id ?? r.endpoint_key ?? ''
  return r.finding_type ?? ''
}

/** 汇总桶分组键展示：subject=主体标识（空为匿名主体）、endpoint=接口键（空为未关联）、type=风险类型标签 */
function SummaryKeyCell({ view, bucket }: { view: ApiFindingSummaryGroupBy; bucket: ApiFindingSummaryBucket }) {
  if (view === 'type') {
    return <FindingTypeTag value={bucket.finding_type ?? ''} />
  }
  if (view === 'endpoint') {
    return bucket.endpoint_key ? (
      <Typography.Text code>{bucket.endpoint_key}</Typography.Text>
    ) : (
      <Typography.Text type="secondary">未关联</Typography.Text>
    )
  }
  if (!bucket.subject_id) {
    return <Typography.Text type="secondary">匿名主体</Typography.Text>
  }
  return (
    <Space size={4}>
      {bucket.subject_type ? <StatusTag value={bucket.subject_type} map={API_SUBJECT_TYPE_META} /> : null}
      <Typography.Text code>{bucket.subject_id}</Typography.Text>
    </Space>
  )
}

/** API 风险发现（WDSP / 阶段8 + P0 风险中心）：风险列表、三视图降噪汇总与七态处置流转 */
export default function ApiFindingsPage() {
  const handling = useApiFindingHandling()

  const [findingType, setFindingType] = useState<string | undefined>()
  const [severity, setSeverity] = useState<string | undefined>()
  const [status, setStatus] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [summaryView, setSummaryView] = useState<ApiFindingSummaryGroupBy>('type')

  const listQuery = useQuery({
    queryKey: ['api-findings', findingType, severity, status, page, pageSize],
    queryFn: () =>
      apiFindingsApi.list({
        finding_type: findingType,
        severity,
        status,
        page,
        page_size: pageSize,
      }),
  })

  /** 汇总三视图一次拉取（无 group_by 参数），Segmented 仅做前端本地切换 */
  const summaryQuery = useQuery({
    queryKey: ['api-findings', 'summary'],
    queryFn: () => apiFindingsApi.summary(),
    enabled: handling.canViewRisk,
  })

  const summaryBuckets: ApiFindingSummaryBucket[] =
    summaryView === 'subject'
      ? (summaryQuery.data?.by_subject ?? [])
      : summaryView === 'endpoint'
        ? (summaryQuery.data?.by_endpoint ?? [])
        : (summaryQuery.data?.by_finding_type ?? [])

  /** 风险类型筛选下拉：合并静态全量类型与当前汇总中出现的动态类型（如 WAF_<规则号>），展示中文标签 */
  const findingTypeOptions = useMemo(() => {
    const seen = new Set<string>()
    const options: Array<{ value: string; label: string }> = []
    for (const bucket of summaryQuery.data?.by_finding_type ?? []) {
      const value = bucket.finding_type?.trim()
      if (!value || seen.has(value)) continue
      seen.add(value)
      options.push({ value, label: getApiFindingTypeMeta(value).label })
    }
    for (const [value, meta] of Object.entries(API_FINDING_TYPE_META)) {
      if (seen.has(value)) continue
      seen.add(value)
      options.push({ value, label: meta.label })
    }
    return options
  }, [summaryQuery.data?.by_finding_type])

  const summaryColumns: ColumnsType<ApiFindingSummaryBucket> = [
    {
      title: SUMMARY_VIEW_META[summaryView].column,
      key: 'key',
      ellipsis: true,
      render: (_, r) => <SummaryKeyCell view={summaryView} bucket={r} />,
    },
    { title: '风险条目', dataIndex: 'count', width: 100 },
    { title: '累计命中', dataIndex: 'hits', width: 100 },
    {
      title: '最高级别',
      dataIndex: 'max_severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
  ]

  const columns: ColumnsType<ApiFinding> = [
    {
      title: '类型',
      dataIndex: 'finding_type',
      width: 190,
      render: (v: string) => <FindingTypeTag value={v} />,
    },
    {
      title: '严重级别',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_STATUS_META} />,
    },
    {
      title: '标题',
      dataIndex: 'title',
      ellipsis: true,
      render: (v: string, record) => {
        const display = formatApiFindingTitle(v, {
          findingType: record.finding_type,
          detail: record.detail,
        })
        return display ? <Tooltip title={display}>{display}</Tooltip> : '-'
      },
    },
    {
      title: '接口',
      dataIndex: 'endpoint_key',
      width: 220,
      ellipsis: true,
      render: (v: string, record) =>
        v ? (
          <Tooltip title={`${v}（ID: ${record.endpoint_id ?? '-'}）`}>
            <Typography.Text code>{v}</Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '首次发现',
      dataIndex: 'first_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: handling.canHandle ? 200 : 80,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          <Button type="link" size="small" onClick={() => handling.setSelected(record)}>
            详情
          </Button>
          <ApiFindingInlineActions
            record={record}
            canHandle={handling.canHandle}
            onAction={handling.runAction}
          />
        </Space>
      ),
    },
  ]

  return (
    <Card title="API 风险发现">
      <Typography.Paragraph type="secondary">
        运行时识别出的 API 风险：影子/僵尸 API、对象级与功能级越权、模型偏离、敏感数据泄露等。支持按主体/接口/类型三维汇总，
        处置流转：确认 → 开始处置 → 解决/误报/忽略 → 归档（七态状态机，非法流转由后端拒绝）。
      </Typography.Paragraph>
      {handling.canViewRisk ? (
        <Card type="inner" size="small" title="风险汇总" style={{ marginBottom: 16 }}>
          <div style={{ marginBottom: 12 }}>
            <Segmented<ApiFindingSummaryGroupBy>
              value={summaryView}
              onChange={setSummaryView}
              options={(
                [
                  ['subject', '按主体'],
                  ['endpoint', '按接口'],
                  ['type', '按类型'],
                ] as Array<[ApiFindingSummaryGroupBy, string]>
              ).map(([value, label]) => ({ value, label }))}
            />
          </div>
          {summaryQuery.error ? (
            <div style={{ marginBottom: 12 }}>
              <QueryErrorAlert error={summaryQuery.error} />
            </div>
          ) : null}
          <SmartTable<ApiFindingSummaryBucket>
            storageKey="api-findings-summary"
            hideRefresh
            rowKey={(r) => summaryRowKey(summaryView, r)}
            size="small"
            loading={summaryQuery.isLoading}
            columns={summaryColumns}
            dataSource={summaryBuckets}
            scroll={{ x: 750 }}
            pagination={false}
            locale={{ emptyText: '暂无风险发现' }}
          />
        </Card>
      ) : null}
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="风险类型"
          allowClear
          showSearch
          optionFilterProp="label"
          popupMatchSelectWidth={false}
          style={{ width: 220 }}
          value={findingType}
          options={findingTypeOptions}
          onChange={(v) => {
            setFindingType(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="严重级别"
          allowClear
          style={{ width: 140 }}
          value={severity}
          options={API_FINDING_SEVERITY_FILTER_OPTIONS}
          onChange={(v) => {
            setSeverity(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="处置状态"
          allowClear
          style={{ width: 140 }}
          value={status}
          options={Object.entries(API_FINDING_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiFinding>
        storageKey="api-findings"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1200 }}
        onRow={(record) => ({
          onDoubleClick: () => handling.setSelected(record),
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
      <ApiFindingDetailDrawer
        finding={handling.selected}
        onClose={() => handling.setSelected(null)}
        canViewRisk={handling.canViewRisk}
        canHandle={handling.canHandle}
        onAction={handling.runAction}
      />
      <ApiFindingActionModals
        resolveTarget={handling.resolveTarget}
        onCloseResolve={() => handling.setResolveTarget(null)}
        resolveForm={handling.resolveForm}
        resolveLoading={handling.resolveMut.isPending}
        onSubmitResolve={(id, resolution) => handling.resolveMut.mutate({ id, resolution })}
        fpTarget={handling.fpTarget}
        onCloseFp={() => handling.setFpTarget(null)}
        fpForm={handling.fpForm}
        fpLoading={handling.falsePositiveMut.isPending}
        onSubmitFp={(id, reason) => handling.falsePositiveMut.mutate({ id, reason })}
      />
    </Card>
  )
}
