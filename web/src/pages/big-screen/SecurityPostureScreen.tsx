import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { dashboardsApi } from '../../api/dashboards'
import { ATTACK_TYPE_META, EVENT_SEVERITY_META } from '../../utils/stage4'
import { BIG_SCREENS, REFRESH_INTERVAL } from './screens'
import ScreenFrame from './components/ScreenFrame'
import ScreenPanel from './components/ScreenPanel'
import ScreenChart from './components/ScreenChart'
import KpiCard from './components/KpiCard'
import EventTicker from './components/EventTicker'
import type { TickerItem } from './components/EventTicker'
import { donutOption, hBarOption, trendOption } from './components/options'
import {
  DEMO_ATTACK_TYPES,
  DEMO_RISK_LEVELS,
  DEMO_SOURCE_IPS,
  DEMO_TICKER_EVENTS,
  DEMO_TODAY,
  DEMO_TOP_APPS,
  DEMO_TREND,
} from './components/demoSecurity'

const screen = BIG_SCREENS.find((s) => s.id === 'security-posture')!

const SEVERITY_COLORS: Record<string, string> = {
  HIGH: '#ff5252',
  MEDIUM: '#ffd54f',
  LOW: '#2979ff',
  INFO: '#8a97a8',
}

const columnStyle = { display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 } as const

/** 安全态势总览大屏（dashboard.security.read） */
export default function SecurityPostureScreen() {
  const postureQuery = useQuery({
    queryKey: ['big-screen', 'security-posture'],
    queryFn: () => dashboardsApi.securityOverview('24h'),
    refetchInterval: REFRESH_INTERVAL,
  })
  const { data } = postureQuery

  // 查询失败：展示降级提示条，不静默切换演示数据（失败时展示真实空态，避免误导）；
  // 演示数据仅在查询成功且无真实数据时兜底，并明显标注
  const hasError = postureQuery.isError
  const todayEmpty = postureQuery.isSuccess && !data?.today
  const riskLevelsEmpty = postureQuery.isSuccess && Object.keys(data?.trends?.risk_levels ?? {}).length === 0
  const trendEmpty = postureQuery.isSuccess && !(data?.trends?.times?.length)
  const attackTypesEmpty = postureQuery.isSuccess && !(data?.top?.attack_types?.length)
  const sourceIpsEmpty = postureQuery.isSuccess && !(data?.top?.source_ips?.length)
  const topAppsEmpty = postureQuery.isSuccess && !(data?.top?.applications?.length)
  const tickerEmpty = postureQuery.isSuccess && !(data?.risks?.high_unprocessed_events?.length)
  const isDemo =
    todayEmpty || riskLevelsEmpty || trendEmpty || attackTypesEmpty || sourceIpsEmpty || topAppsEmpty || tickerEmpty

  // 接口缺失 today（查询成功但返回为空）时使用演示数据兜底，真实数据优先；查询失败展示真实空态（0）
  const today = todayEmpty ? DEMO_TODAY : data?.today

  const riskPie = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实风险等级序列为空时启用；查询失败展示真实空态
    const levels = riskLevelsEmpty ? DEMO_RISK_LEVELS : (data?.trends?.risk_levels ?? {})
    const items = Object.entries(levels).map(([level, series]) => ({
      name: EVENT_SEVERITY_META[level]?.label ?? level,
      value: series.reduce((sum, n) => sum + n, 0),
      itemStyle: { color: SEVERITY_COLORS[level] ?? '#8a97a8' },
    }))
    return donutOption(items, Object.keys(levels).map((l) => SEVERITY_COLORS[l] ?? '#8a97a8'))
  }, [data, riskLevelsEmpty])

  const trend = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实趋势时间轴为空时启用；查询失败展示真实空态
    const useDemo = trendEmpty
    return trendOption(useDemo ? DEMO_TREND.times : (data?.trends?.times ?? []), [
      { name: '安全事件', data: useDemo ? DEMO_TREND.security_events : (data?.trends?.security_events ?? []), color: '#ffd54f' },
      { name: '拦截', data: useDemo ? DEMO_TREND.blocks : (data?.trends?.blocks ?? []), color: '#ff5252' },
      { name: '观察', data: useDemo ? DEMO_TREND.observes : (data?.trends?.observes ?? []), color: '#2979ff' },
    ])
  }, [data, trendEmpty])

  const attackTypes = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实攻击类型榜为空时启用；查询失败展示真实空态
    const list = attackTypesEmpty ? DEMO_ATTACK_TYPES : (data?.top?.attack_types ?? [])
    return hBarOption(
      list.slice(0, 5).map((i) => ({
        name: ATTACK_TYPE_META[i.key]?.label ?? i.key,
        value: i.value,
      })),
      '#ff8a65',
    )
  }, [data, attackTypesEmpty])

  const sourceIps = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实攻击源 IP 榜为空时启用；查询失败展示真实空态
    const list = sourceIpsEmpty ? DEMO_SOURCE_IPS : (data?.top?.source_ips ?? [])
    return hBarOption(
      list.slice(0, 5).map((i) => ({ name: i.ip, value: i.events })),
      '#ff5252',
    )
  }, [data, sourceIpsEmpty])

  const topApps = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实被攻击应用榜为空时启用；查询失败展示真实空态
    const list = topAppsEmpty ? DEMO_TOP_APPS : (data?.top?.applications ?? [])
    return hBarOption(
      list.slice(0, 5).map((i) => ({ name: i.key, value: i.value })),
      '#00e5ff',
    )
  }, [data, topAppsEmpty])

  const tickerItems: TickerItem[] = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实高危未处置事件为空时启用；查询失败展示真实空流
    const events = tickerEmpty ? DEMO_TICKER_EVENTS : (data?.risks?.high_unprocessed_events ?? [])
    return events.map((e) => ({
      key: e.id,
      color: SEVERITY_COLORS[e.severity] ?? '#ff5252',
      time: dayjs(e.occurred_at).format('HH:mm:ss'),
      content: `${e.client_ip} 攻击 ${e.application_name || e.request_path}（${
        ATTACK_TYPE_META[e.attack_type]?.label ?? e.attack_type
      }）`,
      tail: <span style={{ color: SEVERITY_COLORS[e.severity] ?? '#ff5252' }}>{EVENT_SEVERITY_META[e.severity]?.label ?? e.severity}</span>,
    }))
  }, [data, tickerEmpty])

  return (
    <ScreenFrame screen={screen}>
      {hasError && (
        <div className="bs-banner" role="alert">
          部分数据接口加载失败，当前为降级展示，系统将自动重试
        </div>
      )}
      {isDemo && <div className="bs-demo-badge">演示数据：当前无真实数据，以下为示例展示</div>}
      <div className="bs-kpi-row" style={{ gridTemplateColumns: 'repeat(6, 1fr)' }}>
        <KpiCard label="今日请求总量" value={today?.requests_total ?? 0} />
        <KpiCard label="WAF 安全事件" value={today?.waf_events ?? 0} accent="#ffd54f" accentGlow="rgba(255,213,79,0.5)" />
        <KpiCard label="已拦截攻击" value={today?.waf_blocks ?? 0} accent="#ff5252" accentGlow="rgba(255,82,82,0.5)" />
        <KpiCard label="仅观察事件" value={today?.waf_observes ?? 0} accent="#2979ff" accentGlow="rgba(41,121,255,0.5)" />
        <KpiCard label="CC 超限次数" value={today?.cc_exceeded ?? 0} accent="#b388ff" accentGlow="rgba(179,136,255,0.5)" />
        <KpiCard label="高危未处置" value={today?.unprocessed_high_events ?? 0} accent="#ff1744" accentGlow="rgba(255,23,68,0.55)" />
      </div>
      <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '1fr 1.7fr 1fr', gap: 12 }}>
        <div style={columnStyle}>
          <ScreenPanel title="风险等级分布" style={{ flex: 1 }}>
            <ScreenChart option={riskPie} />
          </ScreenPanel>
          <ScreenPanel title="攻击类型 TOP5" style={{ flex: 1 }}>
            <ScreenChart option={attackTypes} />
          </ScreenPanel>
        </div>
        <div style={columnStyle}>
          <ScreenPanel title="安全事件趋势（24h）" style={{ flex: 1.4 }}>
            <ScreenChart option={trend} />
          </ScreenPanel>
          <ScreenPanel title="高危未处置事件动态" style={{ flex: 1 }}>
            <EventTicker items={tickerItems} empty="当前无高危未处置事件" />
          </ScreenPanel>
        </div>
        <div style={columnStyle}>
          <ScreenPanel title="攻击源 IP TOP5" style={{ flex: 1 }}>
            <ScreenChart option={sourceIps} />
          </ScreenPanel>
          <ScreenPanel title="被攻击应用 TOP5" style={{ flex: 1 }}>
            <ScreenChart option={topApps} />
          </ScreenPanel>
        </div>
      </div>
    </ScreenFrame>
  )
}
