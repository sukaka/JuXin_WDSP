import { useMemo } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  Select,
  Space,
  Table,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ArrowLeftOutlined } from '@ant-design/icons'
import { securityRegressionApi } from '../../api/securityRegression'
import type { SecurityRegressionCase } from '../../api/securityRegression'
import StatusTag from '../../components/StatusTag'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import TableRefreshControl from '../../components/TableRefreshControl'
import { useBreadcrumbObjectName } from '../../stores/breadcrumb'
import { DIFF_SUMMARY_KEY_LABELS, REG_FAMILY_LABELS } from '../../utils/i18nLabels'
import {
  REG_CASE_STATUS_META,
  REG_CRITICALITY_META,
  REG_DIFF_KIND_META,
  REG_TRUTH_META,
  classifyCaseDiff,
  diffValueToText,
} from '../../utils/securityRegression'
import type { RegressionDiffKind } from '../../utils/securityRegression'

const CASE_STATUS_OPTIONS = Object.entries(REG_CASE_STATUS_META).map(([value, m]) => ({
  value,
  label: m.label,
}))
const DIFF_KIND_OPTIONS = Object.entries(REG_DIFF_KIND_META).map(([value, m]) => ({
  value,
  label: m.label,
}))

const DIFF_ACTION_LABELS: Record<string, string> = {
  BLOCK: '阻断',
  ALLOW: '放行',
  PASS: '放行',
  OBSERVE: '观察',
}
const DIFF_ACTION_KEYS = new Set(['expected_action', 'observed_action', 'action_change'])

function formatDiffValue(key: string, value: unknown): string {
  if (DIFF_ACTION_KEYS.has(key) && typeof value === 'string') {
    const trimmed = value.trim()
    if (DIFF_ACTION_LABELS[trimmed]) return DIFF_ACTION_LABELS[trimmed]
    if (trimmed.includes('->')) {
      return trimmed
        .split('->')
        .map((part) => {
          const p = part.trim()
          return DIFF_ACTION_LABELS[p] ?? p
        })
        .join(' → ')
    }
  }
  return diffValueToText(value)
}

/** 差异摘要纯文本视图：逐键字符串化展示（React 默认转义，不渲染任何标记——
 * REG-023 恶意 HTML 不执行）；长值受限展开（省略号 + 点击展开），不一次铺满。 */
function DiffSummaryView({ diff }: { diff?: Record<string, unknown> | null }) {
  const entries = Object.entries(diff ?? {})
  if (entries.length === 0) {
    return <Typography.Text type="secondary">无差异摘要（服务端未登记或已脱敏清理）</Typography.Text>
  }
  return (
    <Table
      size="small"
      rowKey={(r) => r[0]}
      pagination={false}
      dataSource={entries}
      columns={[
        {
          title: '差异项',
          dataIndex: 0,
          width: 200,
          render: (k: string) => (
            <Typography.Text strong>{DIFF_SUMMARY_KEY_LABELS[k] ?? k}</Typography.Text>
          ),
        },
        {
          title: '内容（脱敏摘要，纯文本）',
          dataIndex: 1,
          render: (v: unknown, row: [string, unknown]) => (
            <Typography.Paragraph
              style={{ marginBottom: 0, fontFamily: 'monospace', fontSize: 12, whiteSpace: 'pre-wrap' }}
              ellipsis={{ rows: 3, expandable: true, symbol: '展开' }}
            >
              {formatDiffValue(row[0], v)}
            </Typography.Paragraph>
          ),
        },
      ]}
    />
  )
}

/**
 * 用例差异页：状态筛选走服务端（API 契约）；类别/差异类型为当前页客户端筛选
 * （服务端暂不支持该过滤参数，界面如实标注，不冒充全量过滤）。筛选与页码挂
 * URL 查询串，返回/刷新不丢上下文。缺权限由服务端 403 兜底，页面不泄露样本内容。
 */
export default function SecurityRegressionCasesPage() {
  const { id = '' } = useParams()

  const [searchParams, setSearchParams] = useSearchParams()
  const parsePage = (raw: string | null, def: number) => {
    const n = Number(raw)
    return Number.isInteger(n) && n >= 1 ? n : def
  }
  const status = (searchParams.get('status') || undefined) as
    | SecurityRegressionCase['status']
    | undefined
  const family = searchParams.get('family') || undefined
  const diffKind = (searchParams.get('diff') || undefined) as RegressionDiffKind | undefined
  const page = parsePage(searchParams.get('page'), 1)
  const pageSize = parsePage(searchParams.get('page_size'), 20)
  const updateQuery = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams(searchParams)
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v)
      else next.delete(k)
    }
    setSearchParams(next, { replace: true })
  }

  const runQuery = useQuery({
    queryKey: ['security-regression', id],
    queryFn: () => securityRegressionApi.get(id),
    enabled: !!id,
  })
  const casesQuery = useQuery({
    queryKey: ['security-regression-cases', id, status, page, pageSize],
    queryFn: () => securityRegressionApi.listCases(id, { status, page, page_size: pageSize }),
    enabled: !!id,
  })
  useBreadcrumbObjectName(runQuery.data?.run.run_id)

  // 当前页数据的类别集合（客户端筛选选项来自真实数据，不虚构）
  const pageItems = useMemo(() => casesQuery.data?.items ?? [], [casesQuery.data])
  const familyOptions = useMemo(
    () =>
      Array.from(new Set(pageItems.map((c) => c.family)))
        .sort()
        .map((f) => ({ value: f, label: REG_FAMILY_LABELS[f] ?? f })),
    [pageItems],
  )
  const filtered = useMemo(
    () =>
      pageItems.filter((c) => {
        if (family && c.family !== family) return false
        if (diffKind && classifyCaseDiff(c) !== diffKind) return false
        return true
      }),
    [pageItems, family, diffKind],
  )

  const columns: ColumnsType<SecurityRegressionCase> = [
    {
      title: '用例',
      dataIndex: 'case_id',
      width: 200,
      render: (v: string, record) => (
        <Space size={4}>
          <Typography.Text code>{v}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            v{record.case_version}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '类别',
      dataIndex: 'family',
      width: 140,
      render: (v: string) => REG_FAMILY_LABELS[v] ?? v,
    },
    {
      title: '真值',
      dataIndex: 'truth',
      width: 80,
      render: (v: string) => <StatusTag value={v} map={REG_TRUTH_META} />,
    },
    {
      title: '强制级别',
      dataIndex: 'criticality',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={REG_CRITICALITY_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={REG_CASE_STATUS_META} />,
    },
    {
      title: '差异类型',
      key: 'diff_kind',
      width: 110,
      render: (_, record) => (
        <StatusTag value={classifyCaseDiff(record)} map={REG_DIFF_KIND_META} />
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title={`用例差异${runQuery.data ? `（${runQuery.data.run.run_id}）` : ''}`}
        extra={
          <Link to={`/security-regressions/${id}`}>
            <Button icon={<ArrowLeftOutlined />}>返回运行详情</Button>
          </Link>
        }
      >
        <Space wrap style={{ marginBottom: 16 }}>
          <Select
            allowClear
            placeholder="用例状态（服务端过滤）"
            style={{ width: 200 }}
            options={CASE_STATUS_OPTIONS}
            value={status}
            onChange={(v) => updateQuery({ status: v, page: undefined })}
          />
          <Select
            allowClear
            placeholder="类别（本页筛选）"
            style={{ width: 180 }}
            options={familyOptions}
            value={family}
            onChange={(v) => updateQuery({ family: v })}
          />
          <Select
            allowClear
            placeholder="差异类型（本页筛选）"
            style={{ width: 180 }}
            options={DIFF_KIND_OPTIONS}
            value={diffKind}
            onChange={(v) => updateQuery({ diff: v })}
          />
          <TableRefreshControl
            storageKey="security-regression-cases"
            loading={casesQuery.isFetching}
            onRefresh={() => Promise.all([casesQuery.refetch(), runQuery.refetch()])}
          />
        </Space>
        {(family || diffKind) && (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 12 }}
            message="类别/差异类型筛选仅作用于当前页数据（服务端暂不支持该过滤参数）；跨页定位请用状态筛选 + 翻页"
          />
        )}
        {casesQuery.isError ? (
          <QueryErrorAlert error={casesQuery.error} />
        ) : (
          <Table<SecurityRegressionCase>
            rowKey="id"
            size="small"
            loading={casesQuery.isLoading}
            columns={columns}
            dataSource={filtered}
            expandable={{
              expandedRowRender: (record) => <DiffSummaryView diff={record.diff_summary} />,
              rowExpandable: () => true,
            }}
            pagination={{
              current: page,
              pageSize,
              // 服务端过滤（状态）用真实总数；本页筛选命中数单独在表尾如实展示
              total: casesQuery.data?.total ?? 0,
              showTotal: (t) =>
                filtered.length === pageItems.length
                  ? `共 ${t} 条`
                  : `共 ${t} 条（本页筛选命中 ${filtered.length} 条）`,
              showSizeChanger: true,
              pageSizeOptions: [10, 20, 50, 100],
              onChange: (p, ps) =>
                updateQuery({
                  page: String(p),
                  page_size: ps === pageSize ? undefined : String(ps),
                }),
            }}
          />
        )}
      </Card>
    </Space>
  )
}
