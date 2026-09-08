import { useEffect, useMemo, useState, lazy, Suspense } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeftOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { analyticsApi } from '../../api/analytics'
import { ApiError } from '../../api/client'
import { securityEventsApi } from '../../api/securityEvents'
import { ATTACK_TYPE_META, EVENT_SEVERITY_META } from '../../utils/stage4'
import { REFRESH_INTERVAL } from './screens'
import ScreenChart from './components/ScreenChart'
import CountUp from './components/CountUp'
import EventTicker from './components/EventTicker'
import type { TickerItem } from './components/EventTicker'
import type { GlobeRoute } from './components/GlobeAttackMap'
import { donutOption, hBarOption } from './components/options'
import {
  DEMO_ATTACK_TYPES,
  DEMO_KPI,
  DEMO_RISK_LEVELS,
  DEMO_TICKER_EVENTS,
} from './components/demoGlobe'
import './big-screen.css'
import './globe-screen.css'

// WebGL 地球相关依赖（echarts-gl/d3/world-atlas/GeoIP 库）体积较大，按需异步加载
const GlobeAttackMap = lazy(() => import('./components/GlobeAttackMap'))

const SEVERITY_COLORS: Record<string, string> = {
  HIGH: '#ff5252',
  MEDIUM: '#ffd54f',
  LOW: '#2979ff',
  INFO: '#8a97a8',
}

/** 顶部副标题时钟（秒级刷新） */
function useNow() {
  const [now, setNow] = useState(() => dayjs())
  useEffect(() => {
    const timer = setInterval(() => setNow(dayjs()), 1000)
    return () => clearInterval(timer)
  }, [])
  return now
}

/**
 * 全球攻击态势感知大屏（analytics.security.read / security_events.read）。
 * 全屏沉浸式布局：3D 地球铺满整个视口，四角浮层展示攻击 KPI、风险等级分布、
 * 攻击类型 TOP5 与实时事件播报；数据与攻击监控大屏同源（30s 轮询）。
 * 查询失败时展示真实空态并在副标题给出降级提示（不静默切换演示数据）；
 * 演示数据仅在查询成功且无真实数据时兜底，并在副标题明显标注「演示数据」。
 * 仅持单一权限（分析或事件）导致的 403 属预期的受限视图，静默为空，不计入降级提示。
 */
export default function GlobeScreen() {
  const navigate = useNavigate()
  const now = useNow()
  const params = { range: '24h' }

  const trendQuery = useQuery({
    queryKey: ['big-screen', 'attack-trend'],
    queryFn: () => analyticsApi.securityEventTrend(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const riskQuery = useQuery({
    queryKey: ['big-screen', 'risk-levels'],
    queryFn: () => analyticsApi.riskLevels(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const typesQuery = useQuery({
    queryKey: ['big-screen', 'attack-types'],
    queryFn: () => analyticsApi.attackTypes(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const eventsQuery = useQuery({
    queryKey: ['big-screen', 'attack-live'],
    queryFn: () => securityEventsApi.list({ page: 1, page_size: 20 }),
    refetchInterval: REFRESH_INTERVAL,
    // 仅有分析权限而无事件权限（403）时静默降级为空流（属预期受限视图，不触发演示兜底与降级提示）
    retry: false,
  })

  const sum = (arr?: number[] | null) => (arr ?? []).reduce((s, n) => s + n, 0)

  // 攻击路线：最新事件源 IP → 离线 GeoIP 定位国家 → 国家质心聚合（GeoIP 库按需加载）
  const eventItems = eventsQuery.data?.items
  const routesQuery = useQuery({
    queryKey: [
      'big-screen',
      'attack-routes',
      (eventItems ?? []).map((e) => `${e.client_ip}:${e.severity}`).join('|'),
    ],
    queryFn: () => import('./attackRoutes').then((m) => m.buildAttackRoutes(eventItems ?? [])),
    enabled: !!eventItems,
    staleTime: Infinity,
  })
  const realRoutes: GlobeRoute[] = useMemo(
    () =>
      (routesQuery.data ?? []).map((r) => ({
        name: r.name ?? r.city ?? r.country,
        from: r.from,
        count: r.count,
        color: SEVERITY_COLORS[r.severity] ?? '#8a97a8',
      })),
    [routesQuery.data],
  )
  // 真实路线为空或过稀疏（<3 条）时切换演示路线兜底，副标题标注「演示数据」
  const needDemo = routesQuery.data !== undefined && realRoutes.length < 3
  const demoRoutesQuery = useQuery({
    queryKey: ['big-screen', 'attack-routes-demo'],
    queryFn: () => import('./attackRoutes').then((m) => m.buildDemoAttackRoutes()),
    enabled: needDemo,
    staleTime: Infinity,
  })
  const isDemoRoutes = needDemo && (demoRoutesQuery.data?.length ?? 0) > 0
  const routes: GlobeRoute[] = isDemoRoutes ? demoRoutesQuery.data! : realRoutes

  // KPI：查询成功但 24h 攻击总量为 0 时用演示数据兜底；查询失败展示真实空态（0），不静默切演示
  const totalEvents = sum(trendQuery.data?.series?.events)
  const totalBlocks = sum(trendQuery.data?.series?.blocks)
  const trendEmpty = trendQuery.isSuccess && totalEvents === 0
  const kpiAttacks = trendEmpty ? DEMO_KPI.totalAttacks : totalEvents
  const kpiBlocked = trendEmpty ? DEMO_KPI.blocked : totalBlocks
  // 涉及国家数与地球路线同源：路线为空（含查询失败）时如实显示 0
  const kpiCountries = routes.length

  // 查询失败（不含 403 权限受限）时给出降级提示；403 属仅持单一权限的预期受限视图，静默为空
  const isForbidden = (error: unknown) => error instanceof ApiError && error.status === 403
  const hasError =
    (trendQuery.isError && !isForbidden(trendQuery.error)) ||
    (riskQuery.isError && !isForbidden(riskQuery.error)) ||
    (typesQuery.isError && !isForbidden(typesQuery.error)) ||
    (eventsQuery.isError && !isForbidden(eventsQuery.error))

  // 风险等级分布迷你环图：查询成功但返回为空时用演示数据兜底；失败展示真实空态
  const riskReal = riskQuery.data ?? []
  const riskDemo =
    riskQuery.isSuccess && (riskReal.length === 0 || riskReal.every((i) => i.value === 0))
  const riskDonut = useMemo(() => {
    const real = riskQuery.data ?? []
    const source = riskDemo ? DEMO_RISK_LEVELS : real
    return donutOption(
      source.map((i) => ({
        name: EVENT_SEVERITY_META[i.key]?.label ?? i.key,
        value: i.value,
        itemStyle: { color: SEVERITY_COLORS[i.key] ?? '#8a97a8' },
      })),
      source.map((i) => SEVERITY_COLORS[i.key] ?? '#8a97a8'),
    )
  }, [riskDemo, riskQuery.data])

  // 攻击类型 TOP5 迷你横条：查询成功但返回为空时用演示数据兜底；失败展示真实空态
  const typeReal = useMemo(
    () => (typesQuery.data ?? []).map((i) => ({ key: i.key, value: i.value })),
    [typesQuery.data],
  )
  const typesDemo = typesQuery.isSuccess && typeReal.length === 0
  const typeTop5 = useMemo(() => {
    const source = typesDemo ? DEMO_ATTACK_TYPES : typeReal
    return hBarOption(
      source.slice(0, 5).map((i) => ({ name: ATTACK_TYPE_META[i.key]?.label ?? i.key, value: i.value })),
      '#00b0ff',
    )
  }, [typesDemo, typeReal])

  // 实时事件滚动条：查询成功但返回为空时用演示数据兜底；查询失败展示真实空流（不静默切演示）
  const tickerDemo = eventsQuery.isSuccess && (eventsQuery.data?.items ?? []).length === 0
  const tickerItems: TickerItem[] = useMemo(() => {
    const real = eventsQuery.data?.items ?? []
    if (eventsQuery.isSuccess && real.length > 0) {
      return real.map((e) => {
        const blocked = e.action === 'BLOCK'
        return {
          key: e.id,
          color: SEVERITY_COLORS[e.severity] ?? '#8a97a8',
          time: dayjs(e.occurred_at).format('HH:mm:ss'),
          content: `${e.client_ip} → ${e.domain}${e.request_path}（${
            ATTACK_TYPE_META[e.attack_type]?.label ?? e.attack_type
          }）`,
          tail: (
            <span style={{ color: blocked ? '#ff5252' : '#ffd54f', flexShrink: 0 }}>
              {blocked ? '已拦截' : '观察'}
            </span>
          ),
        }
      })
    }
    if (!tickerDemo) return []
    // 演示数据（查询成功但无真实数据时兜底）：时间按当前时刻回推
    const base = dayjs()
    return DEMO_TICKER_EVENTS.map((d) => {
      const blocked = d.action === 'BLOCK'
      return {
        key: d.id,
        color: SEVERITY_COLORS[d.severity] ?? '#8a97a8',
        time: base.subtract(d.secondsAgo, 'second').format('HH:mm:ss'),
        content: `${d.ip} → ${d.domain}${d.path}（${ATTACK_TYPE_META[d.attackType]?.label ?? d.attackType}）`,
        tail: (
          <span style={{ color: blocked ? '#ff5252' : '#ffd54f', flexShrink: 0 }}>
            {blocked ? '已拦截' : '观察'}
          </span>
        ),
      }
    })
  }, [eventsQuery.data, eventsQuery.isSuccess, tickerDemo])

  // 任一区域启用演示数据时在副标题明显标注
  const isDemo = isDemoRoutes || trendEmpty || riskDemo || typesDemo || tickerDemo

  return (
    <div className="bs-root bsg-root">
      {/* 星空背景层 */}
      <div className="bsg-stars" />
      {/* 全屏 3D 地球（无面板边框，铺满视口） */}
      <div className="bsg-globe">
        <Suspense fallback={<div className="bs-empty">正在加载全球攻击态势组件…</div>}>
          <GlobeAttackMap routes={routes} />
        </Suspense>
      </div>

      <button className="bs-back-btn bsg-back" onClick={() => navigate('/big-screen')}>
        <ArrowLeftOutlined /> 返回大厅
      </button>

      {/* 顶部居中大标题 + 副标题时间 */}
      <div className="bsg-title">
        <div className="bsg-title-main">全球攻击态势感知</div>
        <div className="bsg-title-sub">
          {now.format('YYYY-MM-DD HH:mm:ss')} · 每 {REFRESH_INTERVAL / 1000}s 自动刷新
          {hasError ? ' · 部分数据加载失败，已降级展示' : ''}
          {isDemo ? ' · 演示数据' : ''}
        </div>
      </div>

      {/* 左上：今日攻击概览 KPI 浮层 */}
      <div className="bsg-panel bsg-kpis">
        <div className="bsg-panel-title">今日攻击概览（24h）</div>
        <div className="bsg-kpi">
          <span className="bsg-kpi-label">攻击总量</span>
          <span
            className="bsg-kpi-value"
            style={{ color: '#ffd54f', textShadow: '0 0 16px rgba(255, 213, 79, 0.55)' }}
          >
            <CountUp value={kpiAttacks} />
          </span>
        </div>
        <div className="bsg-kpi">
          <span className="bsg-kpi-label">已拦截</span>
          <span
            className="bsg-kpi-value"
            style={{ color: '#ff5252', textShadow: '0 0 16px rgba(255, 82, 82, 0.55)' }}
          >
            <CountUp value={kpiBlocked} />
          </span>
        </div>
        <div className="bsg-kpi">
          <span className="bsg-kpi-label">涉及国家/地区</span>
          <span
            className="bsg-kpi-value"
            style={{ color: '#00b0ff', textShadow: '0 0 16px rgba(0, 176, 255, 0.55)' }}
          >
            <CountUp value={kpiCountries} />
          </span>
        </div>
      </div>

      {/* 右上：风险等级分布迷你环图 */}
      <div className="bsg-panel bsg-donut">
        <div className="bsg-panel-title">风险等级分布</div>
        <div className="bsg-panel-body">
          <ScreenChart option={riskDonut} />
        </div>
      </div>

      {/* 左下：攻击类型 TOP5 迷你横条 */}
      <div className="bsg-panel bsg-top5">
        <div className="bsg-panel-title">攻击类型 TOP5</div>
        <div className="bsg-panel-body">
          <ScreenChart option={typeTop5} />
        </div>
      </div>

      {/* 右下：实时攻击事件滚动条 */}
      <div className="bsg-panel bsg-ticker">
        <div className="bsg-panel-title">实时攻击事件</div>
        <div className="bsg-panel-body">
          <EventTicker items={tickerItems} empty="暂无攻击事件" />
        </div>
      </div>
    </div>
  )
}
