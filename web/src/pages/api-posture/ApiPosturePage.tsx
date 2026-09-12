import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  Button,
  Card,
  Col,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Tooltip,
  Typography,
} from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import {
  apiPostureOverviewApi,
  type ApiPostureOverview,
  type ApiPostureSources,
  type ApiPostureTargets,
  type ApiPostureTrendPoint,
} from '../../api/apiPosture'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasAnyPermission } from '../../utils/permission'

const DAYS_OPTIONS = [
  { value: 7, label: '最近7天' },
  { value: 14, label: '最近14天' },
  { value: 30, label: '最近30天' },
]

/** 顶部核心指标卡片定义（key 对应 ApiPostureOverview 字段；danger>0 时红色；path 为钻取路由；
 * permissions 为钻取目标路由所需权限（与 router RequirePermission 一致），无权限时禁用钻取并提示） */
const METRIC_CARDS: {
  key: keyof ApiPostureOverview
  title: string
  danger?: boolean
  path?: string
  permissions?: string[]
}[] = [
  { key: 'traffic_24h', title: 'API访问量（24h）' },
  { key: 'protected_24h', title: '防护量（24h）' },
  { key: 'assets_total', title: '资产总数', path: '/api-endpoints' },
  { key: 'assets_new_24h', title: '新增API（24h）', path: '/api-endpoints' },
  {
    key: 'shadow_open',
    title: '影子 API',
    danger: true,
    path: '/api-shadow-zombie',
  },
  {
    key: 'zombie_total',
    title: '僵尸 API',
    danger: true,
    path: '/api-shadow-zombie',
  },
  {
    key: 'deprecated_total',
    title: '已下线 API',
    path: '/api-shadow-zombie',
  },
  {
    key: 'sensitive_endpoints',
    title: '涉敏API',
    path: '/api-sensitive-fields',
  },
  {
    key: 'high_risk_assets',
    title: '高风险API',
    danger: true,
    path: '/api-endpoints',
  },
  {
    key: 'unauthenticated_endpoints',
    title: '无认证API',
    danger: true,
    path: '/api-identity-profiles',
  },
  { key: 'models_pending', title: '待确认模型', path: '/api-models', permissions: ['api_model.read', 'api_model.edit'] },
  {
    key: 'schema_deviations_24h',
    title: 'Schema偏离（24h）',
    danger: true,
    path: '/api-violations',
  },
]

/** 单序列折线趋势配置（与站点访问趋势一致的配色习惯：平滑折线 + 浅色面积） */
function trendOption(
  points: ApiPostureTrendPoint[],
  series: { key: keyof ApiPostureTrendPoint; name: string; color: string }[],
): EChartOption {
  return {
    grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    tooltip: { trigger: 'axis' },
    legend: { top: 0 },
    xAxis: { type: 'category', data: points.map((p) => p.date) },
    yAxis: { type: 'value', min: 0, minInterval: 1 },
    series: series.map((s) => ({
      type: 'line',
      name: s.name,
      smooth: true,
      symbol: 'none',
      data: points.map((p) => Number(p[s.key]) || 0),
      lineStyle: { color: s.color, width: 1.5 },
      itemStyle: { color: s.color },
      areaStyle: { color: s.color, opacity: 0.08 },
    })),
  }
}

/** 访问与防护趋势（流量规模 vs 实际处置量） */
function TrafficTrendChart({ points }: { points: ApiPostureTrendPoint[] }) {
  const option = useMemo(
    () =>
      trendOption(points, [
        { key: 'traffic', name: '访问量', color: '#2f54eb' },
        { key: 'protected', name: '防护量', color: '#52c41a' },
      ]),
    [points],
  )
  return <EChart option={option} height={280} ariaLabel="API 访问量与防护量趋势" />
}

/** 风险与资产趋势（风险新增 / 新增API / Schema偏离 / 敏感数据命中） */
function RiskTrendChart({ points }: { points: ApiPostureTrendPoint[] }) {
  const option = useMemo(
    () =>
      trendOption(points, [
        { key: 'risk', name: '风险新增', color: '#f5222d' },
        { key: 'new_endpoints', name: '新增API', color: '#fa8c16' },
        { key: 'schema_deviations', name: 'Schema偏离', color: '#722ed1' },
        { key: 'sensitive_hits', name: '敏感数据命中', color: '#eb2f96' },
      ]),
    [points],
  )
  return <EChart option={option} height={280} ariaLabel="API 风险与资产变化趋势" />
}

/** 认证类型展示名（auth_type 空串 = 匿名流量；词表见迁移 000029） */
const AUTH_TYPE_LABELS: Record<string, string> = {
  '': '匿名',
  bearer_or_basic: 'Bearer/Basic',
  api_key: 'API Key',
  cookie_session: 'Cookie会话',
}

/** 地域归属分桶展示名（apigeo.Scope 词表） */
const GEO_SCOPE_LABELS: Record<string, string> = {
  HOME: '本土',
  FOREIGN: '境外',
  INTERNAL: '内网',
  UNKNOWN: '未知',
}

/** 横向条形排名图（Top 榜单统一形态：第一名在顶部，长标签截断） */
function rankBarOption(
  items: { name: string; value: number }[],
  color: string,
): EChartOption {
  const data = [...items].reverse()
  return {
    grid: { left: 8, right: 32, top: 8, bottom: 8, containLabel: true },
    tooltip: {},
    xAxis: { type: 'value', min: 0, minInterval: 1 },
    yAxis: {
      type: 'category',
      data: data.map((i) => i.name),
      axisLabel: { width: 180, overflow: 'truncate' },
    },
    series: [
      {
        type: 'bar',
        data: data.map((i) => i.value),
        itemStyle: { color },
        barMaxWidth: 16,
        label: { show: true, position: 'right' },
      },
    ],
  }
}

/** 排名卡片：有数据出横向条形图，无数据如实展示「暂无数据」 */
function RankCard({
  title,
  items,
  color,
}: {
  title: string
  items: { name: string; value: number }[]
  color: string
}) {
  const option = useMemo(() => rankBarOption(items, color), [items, color])
  return (
    <Card size="small" title={title}>
      {items.length > 0 ? (
        <EChart option={option} height={Math.max(160, items.length * 32 + 40)} ariaLabel={`${title}排名`} />
      ) : (
        <Typography.Text type="secondary">暂无数据</Typography.Text>
      )}
    </Card>
  )
}

/** W10-SEC 访问来源区块：客户端IP / 身份指纹 / 认证类型 / 地域（GeoIP 降级如实提示） */
function SourcesSection({ data }: { data: ApiPostureSources }) {
  return (
    <>
      <Typography.Title level={5} style={{ marginTop: 24 }}>
        访问来源（安全事件口径）
      </Typography.Title>
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <RankCard
            title="客户端 IP Top10（已脱敏）"
            color="#2f54eb"
            items={data.top_client_ips.map((i) => ({
              name: i.client_ip,
              value: i.count,
            }))}
          />
        </Col>
        <Col xs={24} lg={12}>
          <RankCard
            title="身份指纹 Top10（截断展示）"
            color="#13c2c2"
            items={data.top_identities.map((i) => ({
              name: i.fingerprint,
              value: i.count,
            }))}
          />
        </Col>
        <Col xs={24} lg={12}>
          <RankCard
            title="认证类型分布"
            color="#fa8c16"
            items={data.auth_types.map((i) => ({
              name: AUTH_TYPE_LABELS[i.auth_type] ?? i.auth_type,
              value: i.count,
            }))}
          />
        </Col>
        <Col xs={24} lg={12}>
          <Card size="small" title="访问地域（GeoIP）">
            {!data.geo_enabled ? (
              <Typography.Text type="secondary">
                GeoIP 数据源未启用，地域维度不可用
              </Typography.Text>
            ) : (
              <>
                {data.geo_truncated ? (
                  <Typography.Text type="secondary">
                     distinct 客户端 IP 超上限，地域统计已按事件数截取头部
                  </Typography.Text>
                ) : null}
                <EChart
                  option={rankBarOption(
                    data.geo_scopes.map((i) => ({
                      name: GEO_SCOPE_LABELS[i.scope] ?? i.scope,
                      value: i.count,
                    })),
                    '#52c41a',
                  )}
                  height={160}
                  ariaLabel="访问地域范围分布"
                />
                <EChart
                  option={rankBarOption(
                    data.top_countries.map((i) => ({
                      name: i.country,
                      value: i.count,
                    })),
                    '#722ed1',
                  )}
                  height={Math.max(120, data.top_countries.length * 32 + 40)}
                  ariaLabel="访问来源国家/地区 TOP 排名"
                />
              </>
            )}
          </Card>
        </Col>
      </Row>
    </>
  )
}

/** W10-SEC 访问目标排名区块：API 双口径 / 应用 / 涉敏 / 高风险 */
function TargetsSection({ data }: { data: ApiPostureTargets }) {
  return (
    <>
      <Typography.Title level={5} style={{ marginTop: 24 }}>
        访问目标排名
      </Typography.Title>
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <RankCard
            title="API 访问量 Top10"
            color="#2f54eb"
            items={data.top_by_traffic.map((i) => ({
              name: i.endpoint_key,
              value: i.request_count,
            }))}
          />
        </Col>
        <Col xs={24} lg={12}>
          <RankCard
            title="API 风险发现 Top10"
            color="#f5222d"
            items={data.top_by_findings.map((i) => ({
              name: i.endpoint_key,
              value: i.findings_count,
            }))}
          />
        </Col>
        <Col xs={24} lg={12}>
          <RankCard
            title="应用访问量 Top10"
            color="#13c2c2"
            items={data.top_applications.map((i) => ({
              name: i.application_name || '未分组',
              value: i.request_count,
            }))}
          />
        </Col>
        <Col xs={24} lg={12}>
          <RankCard
            title="涉敏 API 访问量 Top10"
            color="#eb2f96"
            items={data.top_sensitive.map((i) => ({
              name: `${i.endpoint_key}（敏感字段 ${i.sensitive_fields}）`,
              value: i.request_count,
            }))}
          />
        </Col>
        <Col xs={24} lg={12}>
          <RankCard
            title="高风险 API 访问量 Top10"
            color="#fa541c"
            items={data.top_high_risk.map((i) => ({
              name: `${i.endpoint_key} [${i.asset_value}]`,
              value: i.request_count,
            }))}
          />
        </Col>
      </Row>
    </>
  )
}

/**
 * API 安全态势（W9-P101 + W10-SEC，任务书 §6）：顶部 12 项核心指标 + 访问/防护/风险/新增/偏离/敏感
 * 按天趋势 + 访问来源（IP/身份/认证类型/地域）与访问目标排名（API 双口径/应用/涉敏/高风险）。
 * 数据源 GET /api-security/posture/overview、/posture/trends、/posture/sources、/posture/targets
 * （复用 api_runtime.read 权限）。
 */
export default function ApiPosturePage() {
  const navigate = useNavigate()
  const [days, setDays] = useState(7)
  const permissions = useAuthStore((s) => s.user?.permissions)

  const overviewQuery = useQuery({
    queryKey: ['api-posture', 'overview'],
    queryFn: () => apiPostureOverviewApi.overview(),
    refetchInterval: 30_000,
  })
  const trendsQuery = useQuery({
    queryKey: ['api-posture', 'trends', days],
    queryFn: () => apiPostureOverviewApi.trends(days),
    refetchInterval: 30_000,
  })
  // W10-SEC 访问来源 / 访问目标排名（与趋势共用 days 窗口）
  const sourcesQuery = useQuery({
    queryKey: ['api-posture', 'sources', days],
    queryFn: () => apiPostureOverviewApi.sources(days),
    refetchInterval: 30_000,
  })
  const targetsQuery = useQuery({
    queryKey: ['api-posture', 'targets', days],
    queryFn: () => apiPostureOverviewApi.targets(days),
    refetchInterval: 30_000,
  })

  const overview = overviewQuery.data
  const points = trendsQuery.data?.points ?? []
  const error =
    overviewQuery.error ??
    trendsQuery.error ??
    sourcesQuery.error ??
    targetsQuery.error

  return (
    <Card
      title="API 安全态势"
      extra={
        <Space wrap>
          {overview?.generated_at ? (
            <Typography.Text type="secondary">
              生成时间：{formatDateTime(overview.generated_at)}
            </Typography.Text>
          ) : null}
          <Select
            value={days}
            style={{ width: 120 }}
            options={DAYS_OPTIONS}
            onChange={(v) => setDays(v)}
          />
          <Button
            icon={<ReloadOutlined />}
            onClick={() => {
              void overviewQuery.refetch()
              void trendsQuery.refetch()
              void sourcesQuery.refetch()
              void targetsQuery.refetch()
            }}
            loading={
              overviewQuery.isFetching ||
              trendsQuery.isFetching ||
              sourcesQuery.isFetching ||
              targetsQuery.isFetching
            }
          >
            刷新
          </Button>
        </Space>
      }
    >
      <Typography.Paragraph type="secondary">
        汇总 API 资产、风险与运行时防护的核心指标及按天趋势（UTC 日界，每 30
        秒自动刷新）。 访问量为流量桶统计口径（留存 7
        天），防护量为实际处置动作计数。
      </Typography.Paragraph>
      <QueryErrorAlert error={error} />
      {/* 查询失败（如无权限）时隐藏对应区块，避免 0 值误导 */}
      <Spin spinning={overviewQuery.isLoading}>
        {!overviewQuery.error ? (
          <Row gutter={[16, 16]}>
            {METRIC_CARDS.map((m) => {
              const value = Number(overview?.[m.key] ?? 0)
              const danger = m.danger && value > 0
              // 钻取目标需额外权限（如 /api-models 需 api_model.read）：无权限禁用点击并提示，
              // 避免点击后落入 403 页
              const denied = !!m.permissions && !hasAnyPermission(permissions, m.permissions)
              const clickable = !!m.path && !denied
              const card = (
                <Card
                  size="small"
                  hoverable={clickable}
                  onClick={clickable ? () => navigate(m.path!) : undefined}
                >
                  <Statistic
                    title={m.title}
                    value={value}
                    styles={{
                      content: {
                        fontSize: 22,
                        color: danger ? '#f5222d' : undefined,
                      },
                    }}
                  />
                </Card>
              )
              return (
                <Col xs={12} sm={8} xl={6} xxl={4} key={m.key}>
                  {denied ? <Tooltip title="无权限查看钻取目标页面">{card}</Tooltip> : card}
                </Col>
              )
            })}
          </Row>
        ) : null}
      </Spin>
      <Spin spinning={trendsQuery.isLoading}>
        {!trendsQuery.error ? (
          <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
            <Col xs={24} lg={12}>
              <Card size="small" title="访问与防护趋势">
                <TrafficTrendChart points={points} />
              </Card>
            </Col>
            <Col xs={24} lg={12}>
              <Card size="small" title="风险与资产趋势">
                <RiskTrendChart points={points} />
              </Card>
            </Col>
          </Row>
        ) : null}
      </Spin>
      {/* W10-SEC 访问来源 / 访问目标排名（查询失败时隐藏对应区块，避免空榜误导） */}
      <Spin spinning={sourcesQuery.isLoading}>
        {!sourcesQuery.error && sourcesQuery.data ? (
          <SourcesSection data={sourcesQuery.data} />
        ) : null}
      </Spin>
      <Spin spinning={targetsQuery.isLoading}>
        {!targetsQuery.error && targetsQuery.data ? (
          <TargetsSection data={targetsQuery.data} />
        ) : null}
      </Spin>
    </Card>
  )
}
