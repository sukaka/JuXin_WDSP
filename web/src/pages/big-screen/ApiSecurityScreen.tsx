import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { apiFindingsApi, apiPostureApi } from '../../api/apiSecurity'
import {
  API_ACTION_META,
  API_ENDPOINT_STATUS_META,
  API_FINDING_SEVERITY_META,
  API_LEARNING_STATUS_META,
} from '../../utils/stage8'
import { BIG_SCREENS, REFRESH_INTERVAL } from './screens'
import ScreenFrame from './components/ScreenFrame'
import ScreenPanel from './components/ScreenPanel'
import ScreenChart from './components/ScreenChart'
import KpiCard from './components/KpiCard'
import EventTicker from './components/EventTicker'
import type { TickerItem } from './components/EventTicker'
import { donutOption, hBarOption, radarOption } from './components/options'
import { DEMO_API_FINDINGS, DEMO_API_POSTURE, DEMO_API_RUNTIME_STATS } from './components/demoApiSecurity'

const screen = BIG_SCREENS.find((s) => s.id === 'api-security')!

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#e040fb',
  HIGH: '#ff5252',
  MEDIUM: '#ffd54f',
  LOW: '#2979ff',
  INFO: '#8a97a8',
  NONE: '#8a97a8',
}

const columnStyle = { display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 } as const

function kvToItems(record?: Record<string, number>, labels?: Record<string, { label: string } | string>) {
  return Object.entries(record ?? {}).map(([name, value]) => {
    const meta = labels?.[name]
    const label = typeof meta === 'string' ? meta : meta?.label
    return { name: label ?? name, value }
  })
}

/** API 安全态势大屏（api_runtime.read，依赖 API 动态防护能力） */
export default function ApiSecurityScreen() {
  const postureQuery = useQuery({
    queryKey: ['big-screen', 'api-posture'],
    queryFn: () => apiPostureApi.posture(),
    refetchInterval: REFRESH_INTERVAL,
  })
  const statsQuery = useQuery({
    queryKey: ['big-screen', 'api-runtime-stats'],
    queryFn: () => apiPostureApi.runtimeStatistics(),
    refetchInterval: REFRESH_INTERVAL,
  })
  const findingsQuery = useQuery({
    queryKey: ['big-screen', 'api-findings'],
    queryFn: () => apiFindingsApi.list({ page: 1, page_size: 20 }),
    refetchInterval: REFRESH_INTERVAL,
  })

  // 查询失败：展示降级提示条，不静默切换演示数据（失败时展示真实空态，避免误导）；
  // 演示数据仅在查询成功且无真实数据（无接口资产/无运行时事件/无风险发现）时兜底，并明显标注
  const hasError = postureQuery.isError || statsQuery.isError || findingsQuery.isError
  const postureEmpty = postureQuery.isSuccess && (postureQuery.data?.endpoints.total ?? 0) === 0
  const statsEmpty = statsQuery.isSuccess && (statsQuery.data?.total ?? 0) === 0
  const findingsEmpty = findingsQuery.isSuccess && (findingsQuery.data?.items ?? []).length === 0
  const isDemo = postureEmpty || statsEmpty || findingsEmpty

  const posture = postureEmpty ? DEMO_API_POSTURE : postureQuery.data
  const stats = statsEmpty ? DEMO_API_RUNTIME_STATS : statsQuery.data

  const assetStatus = useMemo(() => donutOption(kvToItems(posture?.endpoints.by_asset_status, API_ENDPOINT_STATUS_META)), [posture])
  const learningStatus = useMemo(() => donutOption(kvToItems(posture?.endpoints.by_learning_status, API_LEARNING_STATUS_META), ['#00e5ff', '#ffd54f', '#2979ff', '#8a97a8']), [posture])

  const severityRadar = useMemo(() => {
    const bySeverity = posture?.findings.open_by_severity ?? {}
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    const max = Math.max(1, ...levels.map((l) => bySeverity[l] ?? 0))
    return radarOption(
      levels.map((l) => ({ name: API_FINDING_SEVERITY_META[l]?.label ?? l, max })),
      levels.map((l) => bySeverity[l] ?? 0),
      '#ff5252',
      '开放风险',
    )
  }, [posture])

  const finalActions = useMemo(
    () => donutOption(kvToItems(stats?.by_final_action, API_ACTION_META), ['#69f0ae', '#ff5252', '#ffd54f', '#2979ff', '#b388ff']),
    [stats],
  )

  const riskLevels = useMemo(
    () => hBarOption(kvToItems(stats?.by_risk_level, API_FINDING_SEVERITY_META), '#ff8a65'),
    [stats],
  )

  const topEndpoints = useMemo(
    () =>
      hBarOption(
        (stats?.top_endpoints ?? []).slice(0, 6).map((e) => ({ name: e.endpoint_key, value: e.count })),
        '#b388ff',
      ),
    [stats],
  )

  const tickerItems: TickerItem[] = useMemo(() => {
    const toItem = (f: { id: string; severity: string; last_seen_at: string; title: string }): TickerItem => ({
      key: f.id,
      color: SEVERITY_COLORS[f.severity] ?? '#8a97a8',
      time: dayjs(f.last_seen_at).format('MM-DD HH:mm'),
      content: f.title,
      tail: (
        <span style={{ color: SEVERITY_COLORS[f.severity] ?? '#8a97a8', flexShrink: 0 }}>
          {API_FINDING_SEVERITY_META[f.severity]?.label ?? f.severity}
        </span>
      ),
    })
    // 演示数据（查询成功但无真实数据时兜底）：风险发现为空时滚动演示发现
    return (findingsEmpty ? DEMO_API_FINDINGS : (findingsQuery.data?.items ?? [])).map(toItem)
  }, [findingsEmpty, findingsQuery.data])

  return (
    <ScreenFrame screen={screen}>
      {hasError && (
        <div className="bs-banner" role="alert">
          部分数据接口加载失败，当前为降级展示，系统将自动重试
        </div>
      )}
      {isDemo && <div className="bs-demo-badge">演示数据：当前无真实数据，以下为示例展示</div>}
      <div className="bs-kpi-row" style={{ gridTemplateColumns: 'repeat(6, 1fr)' }}>
        <KpiCard label="API 接口资产" value={posture?.endpoints.total ?? 0} accent="#b388ff" accentGlow="rgba(179,136,255,0.5)" />
        <KpiCard label="开放风险发现" value={posture?.findings.open_total ?? 0} accent="#ff5252" accentGlow="rgba(255,82,82,0.5)" />
        <KpiCard
          label="学习覆盖率"
          value={(posture?.learning_coverage ?? 0) * 100}
          suffix="%"
          formatter={(v) => v.toFixed(1)}
        />
        <KpiCard
          label="模型冻结率"
          value={(posture?.model_freeze_rate ?? 0) * 100}
          suffix="%"
          formatter={(v) => v.toFixed(1)}
          accent="#69f0ae"
          accentGlow="rgba(105,240,174,0.5)"
        />
        <KpiCard label="运行时事件" value={stats?.total ?? 0} accent="#ffd54f" accentGlow="rgba(255,213,79,0.5)" />
        <KpiCard label="模型版本总数" value={posture?.model_version_total ?? 0} accent="#2979ff" accentGlow="rgba(41,121,255,0.5)" />
      </div>
      <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '1fr 1.7fr 1fr', gap: 12 }}>
        <div style={columnStyle}>
          <ScreenPanel title="资产状态分布" style={{ flex: 1 }}>
            <ScreenChart option={assetStatus} />
          </ScreenPanel>
          <ScreenPanel title="学习状态分布" style={{ flex: 1 }}>
            <ScreenChart option={learningStatus} />
          </ScreenPanel>
        </div>
        <div style={columnStyle}>
          <div style={{ flex: 1.4, minHeight: 0, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <ScreenPanel title="开放风险等级雷达">
              <ScreenChart option={severityRadar} />
            </ScreenPanel>
            <ScreenPanel title="运行时处置分布">
              <ScreenChart option={finalActions} />
            </ScreenPanel>
          </div>
          <ScreenPanel title="最新风险发现" style={{ flex: 1 }}>
            <EventTicker items={tickerItems} empty="暂无风险发现" />
          </ScreenPanel>
        </div>
        <div style={columnStyle}>
          <ScreenPanel title="运行时风险等级" style={{ flex: 1 }}>
            <ScreenChart option={riskLevels} />
          </ScreenPanel>
          <ScreenPanel title="热点接口 TOP6" style={{ flex: 1 }}>
            <ScreenChart option={topEndpoints} />
          </ScreenPanel>
        </div>
      </div>
    </ScreenFrame>
  )
}
