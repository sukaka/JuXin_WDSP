import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Descriptions, Drawer, Input, Select, Space, Table, Tag, Tooltip, Typography } from 'antd'
import { QuestionCircleOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi } from '../../api/apiAssets'
import {
  apiIdentityProfilesApi,
  type ApiIdentityProfile,
  type ApiIdentityRiskAssessment,
  type ApiIdentityRuntimeEvent,
} from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { API_ACTION_META, API_AUTH_TYPE_META, API_FINDING_SEVERITY_META } from '../../utils/stage8'

/** 质量分色阶：越高越稳定 */
function qualityColor(score: number): string {
  if (score >= 80) return 'green'
  if (score >= 60) return 'blue'
  if (score >= 40) return 'orange'
  return 'default'
}

/** 质量分列头说明（与 server/internal/apisecurity/identity.go identityQualityScore 口径一致） */
const QUALITY_SCORE_TOOLTIP = (
  <div style={{ maxWidth: 360 }}>
    质量分（0-100）衡量身份“有多像稳定正常调用者”，仅用于 SOC 排序，不直接阻断：
    <br />
    基础分 40；有认证类型 +15；
    <br />
    请求量：≥5 / 10 / 20 / 50 / 100 / 500 / 1000 分别 +4 / 8 / 12 / 17 / 22 / 26 / 30；
    <br />
    存活跨度：&gt;1h / 6h / 24h / 72h / 7 天分别 +3 / 6 / 9 / 12 / 15。
  </div>
)

/** 风险级别色阶与中文名（五级矩阵：VERY_LOW…VERY_HIGH） */
const RISK_LEVELS: Record<string, { color: string; label: string }> = {
  VERY_LOW: { color: 'green', label: '很低' },
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中等' },
  HIGH: { color: 'red', label: '高' },
  VERY_HIGH: { color: 'magenta', label: '很高' },
}

function riskTag(level: string) {
  const meta = RISK_LEVELS[level] ?? { color: 'default', label: level }
  return <Tag color={meta.color}>{meta.label}</Tag>
}

/** 风险评估区块（GB/T 31509 修订稿矩阵法：可能性 × 严重程度） */
function RiskSection({ risk }: { risk: ApiIdentityRiskAssessment }) {
  const ind = risk.indicators
  return (
    <>
      <Descriptions
        title="风险评估（信号参考，不阻断）"
        size="small"
        column={3}
        bordered
        items={[
          { key: 'level', label: '风险级别', children: riskTag(risk.level) },
          { key: 'likelihood', label: '可能性（威胁频率）', children: `${risk.likelihood} / 5` },
          { key: 'severity', label: '严重程度', children: `${risk.severity} / 5` },
          { key: 'events_total', label: '事件总数', children: ind.events_total },
          { key: 'events_24h', label: '近24h事件', children: ind.events_24h },
          { key: 'risky', label: '高危事件', children: ind.risky_events_total },
          { key: 'blocked', label: '已拦截', children: ind.blocked_events_total },
          { key: 'endpoints', label: '触达 API 数', children: ind.distinct_endpoints },
          { key: 'max_score', label: '最高风险分', children: ind.max_risk_score },
        ]}
      />
      <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>
        {risk.summary}。评估口径：威胁频率分档（24h 密集上调、全数拦截消减）× 最高风险分五档，经 5×5
        矩阵定级（GB/T 31509 修订稿 5.3.3）。
      </Typography.Paragraph>
    </>
  )
}

/** 近期事件表（该指纹最近 10 条运行时事件） */
const eventColumns: ColumnsType<ApiIdentityRuntimeEvent> = [
  {
    title: '时间',
    dataIndex: 'occurred_at',
    width: 170,
    render: (v: string) => formatDateTime(v),
  },
  { title: 'API', dataIndex: 'endpoint_key', ellipsis: true, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
  { title: '风险分', dataIndex: 'risk_score', width: 80 },
  {
    title: '风险级',
    dataIndex: 'risk_level',
    width: 100,
    render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
  },
  {
    title: '动作',
    dataIndex: 'final_action',
    width: 110,
    render: (v: string) => <StatusTag value={v} map={API_ACTION_META} />,
  },
]

/** 站点列渲染（主域名优先，其次站点名称，未归属置灰占位；与接口资产页口径一致） */
function SiteCell({ row }: { row: { application_name?: string; application_domain?: string } }) {
  const text = row.application_domain || row.application_name
  return text ? <span>{text}</span> : <Typography.Text type="secondary">未归属</Typography.Text>
}

/** 身份画像（WDSP / 三微模型）：凭据指纹 × 端点聚合，不落明文凭据；点击行查看详情与风险评估 */
export default function ApiIdentityProfilesPage() {
  const [fingerprint, setFingerprint] = useState('')
  const [appliedFp, setAppliedFp] = useState('')
  const [applicationId, setApplicationId] = useState<string>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<ApiIdentityProfile | null>(null)

  /** 站点选择器数据源（各站点接口数汇总） */
  const siteSummaryQuery = useQuery({
    queryKey: ['api-endpoints', 'site-summary'],
    queryFn: () => apiEndpointsApi.siteSummary(),
  })

  const listQuery = useQuery({
    queryKey: ['api-identity-profiles', appliedFp, applicationId, page, pageSize],
    queryFn: () =>
      apiIdentityProfilesApi.list({
        page,
        page_size: pageSize,
        identity_fingerprint: appliedFp || undefined,
        application_id: applicationId || undefined,
      }),
  })

  const detailQuery = useQuery({
    queryKey: ['api-identity-profile-detail', selected?.identity_fingerprint, selected?.endpoint_id],
    queryFn: () =>
      apiIdentityProfilesApi.detail({
        identity_fingerprint: selected!.identity_fingerprint,
        endpoint_id: selected!.endpoint_id,
      }),
    enabled: selected !== null,
  })

  const columns: ColumnsType<ApiIdentityProfile> = [
    {
      title: '身份指纹',
      dataIndex: 'identity_fingerprint',
      ellipsis: true,
      render: (v: string) => <Typography.Text code copyable={{ text: v }}>{v}</Typography.Text>,
    },
    {
      title: 'API',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      width: 280,
      render: (v: string, r) =>
        v ? (
          <Typography.Text code>{v}</Typography.Text>
        ) : (
          <Typography.Text type="secondary">{r.endpoint_id.slice(0, 8)}…</Typography.Text>
        ),
    },
    {
      title: '站点',
      key: 'site',
      width: 150,
      ellipsis: true,
      render: (_, r) => <SiteCell row={r} />,
    },
    {
      title: '认证类型',
      dataIndex: 'auth_type',
      width: 140,
      render: (v: string) => (v ? <StatusTag value={v} map={API_AUTH_TYPE_META} /> : <Typography.Text type="secondary">—</Typography.Text>),
    },
    {
      title: '请求数',
      dataIndex: 'request_count',
      width: 100,
      sorter: (a, b) => a.request_count - b.request_count,
    },
    {
      title: (
        <Space size={4}>
          质量分
          <Tooltip title={QUALITY_SCORE_TOOLTIP}>
            <QuestionCircleOutlined style={{ color: 'rgba(0,0,0,0.45)' }} />
          </Tooltip>
        </Space>
      ),
      dataIndex: 'quality_score',
      width: 100,
      sorter: (a, b) => a.quality_score - b.quality_score,
      defaultSortOrder: 'descend',
      render: (v: number) => <Tag color={qualityColor(v)}>{v}</Tag>,
    },
    {
      title: '首见',
      dataIndex: 'first_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '最近见',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
  ]

  const profile = detailQuery.data?.profile ?? selected

  return (
    <Card title="身份模型">
      <Typography.Paragraph type="secondary">
        他是谁？这个调用者靠不靠谱
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Typography.Text>站点选择：</Typography.Text>
        <Select
          placeholder="全部站点"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 260 }}
          value={applicationId}
          onChange={(v) => {
            setApplicationId(v)
            setPage(1)
          }}
          loading={siteSummaryQuery.isLoading}
          options={(siteSummaryQuery.data?.items ?? []).map((s) => ({
            value: s.application_id,
            label: `${s.application_domain || s.application_name}（${s.endpoint_count}）`,
          }))}
        />
        <Input.Search
          placeholder="身份指纹（精确匹配）"
          allowClear
          style={{ width: 360 }}
          value={fingerprint}
          onChange={(e) => setFingerprint(e.target.value)}
          onSearch={(v) => {
            setAppliedFp(v.trim())
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiIdentityProfile>
        storageKey="api-identity-profiles"
        rowKey={(r) => `${r.identity_fingerprint}:${r.endpoint_id}`}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1200 }}
        onRow={(r) => ({ onClick: () => setSelected(r), style: { cursor: 'pointer' } })}
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
      <Drawer
        title="身份模型详情"
        width={860}
        open={selected !== null}
        onClose={() => setSelected(null)}
        destroyOnHidden
      >
        <QueryErrorAlert error={detailQuery.error} />
        {profile ? (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions
              title="画像信息"
              size="small"
              column={2}
              bordered
              items={[
                {
                  key: 'fp',
                  label: '身份指纹',
                  span: 2,
                  children: <Typography.Text code copyable={{ text: profile.identity_fingerprint }}>{profile.identity_fingerprint}</Typography.Text>,
                },
                {
                  key: 'ep',
                  label: 'API',
                  children: profile.endpoint_key ? (
                    <Typography.Text code>{profile.endpoint_key}</Typography.Text>
                  ) : (
                    <Typography.Text type="secondary">{profile.endpoint_id}</Typography.Text>
                  ),
                },
                { key: 'site', label: '站点', children: <SiteCell row={profile} /> },
                {
                  key: 'auth',
                  label: '认证类型',
                  children: profile.auth_type ? (
                    <StatusTag value={profile.auth_type} map={API_AUTH_TYPE_META} />
                  ) : (
                    '—'
                  ),
                },
                { key: 'count', label: '累计请求数', children: profile.request_count },
                {
                  key: 'quality',
                  label: '质量分',
                  children: <Tag color={qualityColor(profile.quality_score)}>{profile.quality_score}</Tag>,
                },
                { key: 'first', label: '首见', children: formatDateTime(profile.first_seen_at) },
                { key: 'last', label: '最近见', children: formatDateTime(profile.last_seen_at) },
              ]}
            />
            {detailQuery.data ? (
              <>
                <RiskSection risk={detailQuery.data.risk} />
                <Table<ApiIdentityRuntimeEvent>
                  title={() => '近期事件（最近 10 条）'}
                  size="small"
                  rowKey="id"
                  columns={eventColumns}
                  dataSource={detailQuery.data.recent_events ?? []}
                  pagination={false}
                />
              </>
            ) : (
              <Typography.Text type="secondary">{detailQuery.isLoading ? '加载详情…' : ''}</Typography.Text>
            )}
          </Space>
        ) : null}
      </Drawer>
    </Card>
  )
}
