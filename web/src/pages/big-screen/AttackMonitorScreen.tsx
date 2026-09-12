import { useMemo, lazy, Suspense } from 'react'
import { useQuery } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { analyticsApi } from '../../api/analytics'
import { ApiError } from '../../api/client'
import { securityEventsApi } from '../../api/securityEvents'
import { ATTACK_TYPE_META } from '../../utils/stage4'
import { BIG_SCREENS, REFRESH_INTERVAL } from './screens'
import ScreenFrame from './components/ScreenFrame'
import ScreenPanel from './components/ScreenPanel'
import ScreenChart from './components/ScreenChart'
import KpiCard from './components/KpiCard'
import EventTicker from './components/EventTicker'
import type { TickerItem } from './components/EventTicker'
import type { GlobeRoute } from './components/GlobeAttackMap'
import { donutOption, hBarOption, trendOption } from './components/options'
import {
  DEMO_ATTACK_EVENTS,
  DEMO_ATTACK_IPS,
  DEMO_ATTACK_RULES,
  DEMO_ATTACK_TREND,
  DEMO_ATTACK_TYPES,
  DEMO_ATTACK_URIS,
} from './components/demoAttackMonitor'

// WebGL 地球相关依赖（echarts-gl/d3/world-atlas/GeoIP 库）体积较大，按需异步加载
const GlobeAttackMap = lazy(() => import('./components/GlobeAttackMap'))

const screen = BIG_SCREENS.find((s) => s.id === 'attack-monitor')!

const SEVERITY_COLORS: Record<string, string> = {
  HIGH: '#ff5252',
  MEDIUM: '#ffd54f',
  LOW: '#2979ff',
  INFO: '#8a97a8',
}

const columnStyle = { display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 } as const

/** 攻击监控大屏（analytics.security.read / security_events.read） */
export default function AttackMonitorScreen() {
  const params = { range: '24h' }
  const trendQuery = useQuery({
    queryKey: ['big-screen', 'attack-trend'],
    queryFn: () => analyticsApi.securityEventTrend(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const typesQuery = useQuery({
    queryKey: ['big-screen', 'attack-types'],
    queryFn: () => analyticsApi.attackTypes(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const ipsQuery = useQuery({
    queryKey: ['big-screen', 'attack-ips'],
    queryFn: () => analyticsApi.topSourceIps(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const urisQuery = useQuery({
    queryKey: ['big-screen', 'attack-uris'],
    queryFn: () => analyticsApi.topUris(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const rulesQuery = useQuery({
    queryKey: ['big-screen', 'attack-rules'],
    queryFn: () => analyticsApi.topRules(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const eventsQuery = useQuery({
    queryKey: ['big-screen', 'attack-live'],
    queryFn: () => securityEventsApi.list({ page: 1, page_size: 20 }),
    refetchInterval: REFRESH_INTERVAL,
    // 仅有分析权限而无事件权限时静默降级为空流
    retry: false,
  })

  // 查询失败：展示降级提示条，不静默切换演示数据（失败时展示真实空态，避免误导）；
  // 演示数据仅在查询成功且无真实数据时对图表区兜底，并明显标注；一旦有真实数据立即展示真实数据。
  // KPI 数字不参与演示兜底，恒为真实值（无数据为 0）。
  // 全球攻击路线的兜底在 GlobeAttackMap 组件内部完成，本屏不塞 routes。
  // 仅持分析权限而无事件权限（403）属预期受限视图，静默为空，不计入降级提示
  const isForbidden = (error: unknown) => error instanceof ApiError && error.status === 403
  const hasError =
    trendQuery.isError ||
    typesQuery.isError ||
    ipsQuery.isError ||
    urisQuery.isError ||
    rulesQuery.isError ||
    (eventsQuery.isError && !isForbidden(eventsQuery.error))
  const trendEmpty = trendQuery.isSuccess && (trendQuery.data?.series?.events ?? []).length === 0
  const typesEmpty = typesQuery.isSuccess && (typesQuery.data ?? []).length === 0
  const ipsEmpty = ipsQuery.isSuccess && (ipsQuery.data ?? []).length === 0
  const urisEmpty = urisQuery.isSuccess && (urisQuery.data ?? []).length === 0
  const rulesEmpty = rulesQuery.isSuccess && (rulesQuery.data ?? []).length === 0
  const eventsEmpty = eventsQuery.isSuccess && (eventsQuery.data?.items ?? []).length === 0
  const isDemo = trendEmpty || typesEmpty || ipsEmpty || urisEmpty || rulesEmpty || eventsEmpty

  const trendData = trendEmpty ? DEMO_ATTACK_TREND : trendQuery.data

  const sum = (arr?: number[] | null) => (arr ?? []).reduce((s, n) => s + n, 0)
  // KPI 数字恒为真实值（trendData 可能为演示兜底序列，KPI 不得引用）
  const realSeries = trendQuery.data?.series

  // 攻击路线：最新事件源 IP → 离线 GeoIP 定位国家 → 国家质心聚合（GeoIP 库按需加载）
  const eventItems = eventsQuery.data?.items
  const routesQuery = useQuery({
    queryKey: ['big-screen', 'attack-routes', (eventItems ?? []).map((e) => `${e.client_ip}:${e.severity}`).join('|')],
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
  // 真实路线为空或过稀疏（<3 条）时切换演示路线兜底，面板标注「演示数据」
  const needDemo = routesQuery.data !== undefined && realRoutes.length < 3
  const demoRoutesQuery = useQuery({
    queryKey: ['big-screen', 'attack-routes-demo'],
    queryFn: () => import('./attackRoutes').then((m) => m.buildDemoAttackRoutes()),
    enabled: needDemo,
    staleTime: Infinity,
  })
  const isDemoRoutes = needDemo && (demoRoutesQuery.data?.length ?? 0) > 0
  const routes: GlobeRoute[] = isDemoRoutes ? demoRoutesQuery.data! : realRoutes

  const trend = useMemo(() => {
    const s = trendData?.series
    return trendOption(trendData?.times ?? [], [
      { name: '安全事件', data: s?.events ?? [], color: '#ffd54f' },
      { name: '拦截', data: s?.blocks ?? [], color: '#ff5252' },
      { name: '观察', data: s?.observes ?? [], color: '#2979ff' },
    ])
  }, [trendData])

  const types = useMemo(
    () =>
      donutOption(
        (typesEmpty ? DEMO_ATTACK_TYPES : (typesQuery.data ?? [])).map((i) => ({
          name: ATTACK_TYPE_META[i.key]?.label ?? i.key,
          value: i.value,
        })),
      ),
    [typesEmpty, typesQuery.data],
  )

  const ips = useMemo(
    () =>
      hBarOption(
        (ipsEmpty ? DEMO_ATTACK_IPS : (ipsQuery.data ?? [])).slice(0, 8).map((i) => ({ name: i.ip, value: i.events })),
        '#ff5252',
      ),
    [ipsEmpty, ipsQuery.data],
  )

  const uris = useMemo(
    () =>
      hBarOption(
        (urisEmpty ? DEMO_ATTACK_URIS : (urisQuery.data ?? [])).slice(0, 8).map((i) => ({ name: i.path, value: i.events })),
        '#ff8a65',
      ),
    [urisEmpty, urisQuery.data],
  )

  const rules = useMemo(() => {
    // 演示数据（无真实数据时兜底）：演示分支带 CRS 风格中文规则名；真实分支保持「规则 + ID」
    if (rulesEmpty) {
      return hBarOption(
        DEMO_ATTACK_RULES.map((i) => ({ name: i.name, value: i.hits })),
        '#b388ff',
      )
    }
    return hBarOption(
      (rulesQuery.data ?? []).slice(0, 5).map((i) => ({ name: `规则 ${i.rule_id}`, value: i.hits })),
      '#b388ff',
    )
  }, [rulesEmpty, rulesQuery.data])

  const tickerItems: TickerItem[] = useMemo(() => {
    const toItem = (e: {
      id: string
      severity: string
      occurred_at: string
      client_ip: string
      domain: string
      request_path: string
      attack_type: string
      action: string
    }): TickerItem => {
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
    }
    // 演示数据（查询成功但无真实数据时兜底）：真实事件为空时滚动演示事件；查询失败展示真实空流
    return (eventsEmpty ? DEMO_ATTACK_EVENTS : (eventsQuery.data?.items ?? [])).map(toItem)
  }, [eventsEmpty, eventsQuery.data])

  return (
    <ScreenFrame screen={screen}>
      {hasError && (
        <div className="bs-banner" role="alert">
          部分数据接口加载失败，当前为降级展示，系统将自动重试
        </div>
      )}
      {isDemo && <div className="bs-demo-badge">演示数据：当前无真实数据，以下为示例展示</div>}
      <div className="bs-kpi-row" style={{ gridTemplateColumns: 'repeat(6, 1fr)' }}>
        {/* KPI 数字恒为真实值：无真实数据时保持 0，不做演示替换；演示兜底仅限下方图表区与事件流（保留演示角标） */}
        <KpiCard label="安全事件总数" value={sum(realSeries?.events)} accent="#ffd54f" accentGlow="rgba(255,213,79,0.5)" />
        <KpiCard label="拦截攻击" value={sum(realSeries?.blocks)} accent="#ff5252" accentGlow="rgba(255,82,82,0.5)" />
        <KpiCard label="观察事件" value={sum(realSeries?.observes)} accent="#2979ff" accentGlow="rgba(41,121,255,0.5)" />
        <KpiCard label="攻击源 IP" value={(ipsQuery.data ?? []).length} />
        <KpiCard label="被攻击 URI" value={(urisQuery.data ?? []).length} accent="#ff8a65" accentGlow="rgba(255,138,101,0.5)" />
        <KpiCard label="命中规则" value={(rulesQuery.data ?? []).length} accent="#b388ff" accentGlow="rgba(179,136,255,0.5)" />
      </div>
      <div style={{ flex: 1.6, minHeight: 0, display: 'grid', gridTemplateColumns: '1fr 1.7fr 1fr', gap: 12 }}>
        <div style={columnStyle}>
          <ScreenPanel title="攻击类型构成" style={{ flex: 1 }}>
            <ScreenChart option={types} />
          </ScreenPanel>
          <ScreenPanel title="命中规则 TOP5" style={{ flex: 1 }}>
            <ScreenChart option={rules} />
          </ScreenPanel>
        </div>
        <ScreenPanel title={`全球攻击路线（来源地 → 本站）${isDemoRoutes ? ' · 演示数据' : ''}`}>
          <Suspense fallback={<div className="bs-empty">正在加载全球攻击路线组件…</div>}>
            <GlobeAttackMap routes={routes} />
          </Suspense>
          <div className="bs-geo-attribution">
            <a href="https://db-ip.com" target="_blank" rel="noreferrer">IP Geolocation by DB-IP</a>
            {' / 数据来源含 NRO 统计（CC BY 4.0）'}
          </div>
        </ScreenPanel>
        <div style={columnStyle}>
          <ScreenPanel title="攻击源 IP TOP8" style={{ flex: 1 }}>
            <ScreenChart option={ips} />
          </ScreenPanel>
          <ScreenPanel title="被攻击 URI TOP8" style={{ flex: 1 }}>
            <ScreenChart option={uris} />
          </ScreenPanel>
        </div>
      </div>
      <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 12 }}>
        <ScreenPanel title="攻击事件趋势（24h）">
          <ScreenChart option={trend} />
        </ScreenPanel>
        <ScreenPanel title="实时攻击事件">
          <EventTicker items={tickerItems} empty="暂无攻击事件" />
        </ScreenPanel>
      </div>
    </ScreenFrame>
  )
}
