import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { analyticsApi } from '../../api/analytics'
import { BIG_SCREENS, REFRESH_INTERVAL } from './screens'
import ScreenFrame from './components/ScreenFrame'
import ScreenPanel from './components/ScreenPanel'
import ScreenChart from './components/ScreenChart'
import KpiCard from './components/KpiCard'
import { donutOption, gaugeOption, hBarOption, trendOption } from './components/options'
import { AC_EVENT_TYPE_META } from '../../utils/stage5'
import {
  DEMO_AC,
  DEMO_AC_RULE_HITS,
  DEMO_CC,
  DEMO_CC_BLOCK_TREND,
  DEMO_REQUEST_TREND,
  DEMO_TOP_APPS,
} from './components/demoTraffic'

const screen = BIG_SCREENS.find((s) => s.id === 'traffic-access')!

const columnStyle = { display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 } as const

/** 流量与访问控制大屏（analytics.security.read） */
export default function TrafficAccessScreen() {
  const params = { range: '24h' }
  const trendQuery = useQuery({
    queryKey: ['big-screen', 'traffic-trend'],
    queryFn: () => analyticsApi.requestTrend(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const ccQuery = useQuery({
    queryKey: ['big-screen', 'traffic-cc'],
    queryFn: () => analyticsApi.ccOverview(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const acQuery = useQuery({
    queryKey: ['big-screen', 'traffic-ac'],
    queryFn: () => analyticsApi.accessControlOverview(params),
    refetchInterval: REFRESH_INTERVAL,
  })
  const appsQuery = useQuery({
    queryKey: ['big-screen', 'traffic-apps'],
    queryFn: () => analyticsApi.topApplications(params),
    refetchInterval: REFRESH_INTERVAL,
  })

  const cc = ccQuery.data
  const ac = acQuery.data
  const reqSeries = trendQuery.data?.series

  // 查询失败：展示降级提示条，不静默切换演示数据（失败时展示真实空态，避免误导）；
  // 演示数据仅在查询成功且无真实数据时兜底，并明显标注
  const hasError = trendQuery.isError || ccQuery.isError || acQuery.isError || appsQuery.isError
  // 演示数据（查询成功但无真实数据时兜底）：真实趋势时间轴为空时启用；查询失败展示真实空态
  const useDemoTrend = trendQuery.isSuccess && !(trendQuery.data?.times?.length)
  const ccEmpty = ccQuery.isSuccess && !cc
  const blockTrendEmpty = ccQuery.isSuccess && !(cc?.temp_block_trend?.length)
  const ruleHitsEmpty = acQuery.isSuccess && !(ac?.rule_hits?.length)
  const appsEmpty = appsQuery.isSuccess && !(appsQuery.data?.length)

  const requestsTotal = useMemo(
    // KPI 数字恒为真实值：无真实数据时保持 0（演示兜底仅限下方图表区，见 isDemo 角标）
    () => (reqSeries?.requests ?? []).reduce((s, n) => s + n, 0),
    [reqSeries],
  )

  const trafficTrend = useMemo(
    () =>
      trendOption(useDemoTrend ? DEMO_REQUEST_TREND.times : (trendQuery.data?.times ?? []), [
        {
          name: '请求量',
          data: useDemoTrend ? DEMO_REQUEST_TREND.requests : (reqSeries?.requests ?? []),
          color: '#69f0ae',
        },
        {
          name: 'P95 时延(ms)',
          data: useDemoTrend ? DEMO_REQUEST_TREND.p95_ms : (reqSeries?.p95_ms ?? []),
          color: '#ffd54f',
          area: false,
        },
      ]),
    [trendQuery.data, reqSeries, useDemoTrend],
  )

  const blockTrend = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实临时封禁趋势为空时启用；查询失败展示真实空态
    const points = blockTrendEmpty ? DEMO_CC_BLOCK_TREND : (cc?.temp_block_trend ?? [])
    return trendOption(
      points.map((p) => p.time),
      [{ name: '新增临时封禁', data: points.map((p) => p.count), color: '#ff5252' }],
      'MM-DD HH:mm',
    )
  }, [cc, blockTrendEmpty])

  // 演示数据（查询成功但无真实数据时兜底）：查询成功但黑白名单命中全为 0（含无返回）时启用；查询失败展示真实空态
  const useDemoAc = acQuery.isSuccess && (!ac || ac.allow_matches + ac.deny_matches === 0)

  const isDemo = useDemoTrend || ccEmpty || useDemoAc || blockTrendEmpty || ruleHitsEmpty || appsEmpty

  const allowDeny = useMemo(
    () =>
      donutOption(
        [
          { name: '白名单放行', value: useDemoAc ? DEMO_AC.allow_matches : (ac?.allow_matches ?? 0) },
          { name: '黑名单拦截', value: useDemoAc ? DEMO_AC.deny_matches : (ac?.deny_matches ?? 0) },
        ],
        ['#69f0ae', '#ff5252'],
      ),
    [ac, useDemoAc],
  )

  const denyRatio = useMemo(() => {
    const allow = useDemoAc ? DEMO_AC.allow_matches : (ac?.allow_matches ?? 0)
    const deny = useDemoAc ? DEMO_AC.deny_matches : (ac?.deny_matches ?? 0)
    const total = allow + deny
    return total === 0 ? 0 : (deny / total) * 100
  }, [ac, useDemoAc])

  const ruleHits = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实规则命中榜为空时启用；查询失败展示真实空态
    const list = ruleHitsEmpty ? DEMO_AC_RULE_HITS : (ac?.rule_hits ?? [])
    return hBarOption(
      list.slice(0, 6).map((r) => ({
        name: AC_EVENT_TYPE_META[r.event_type]?.label ?? r.event_type,
        value: r.hits,
      })),
      '#00e5ff',
    )
  }, [ac, ruleHitsEmpty])

  const topApps = useMemo(() => {
    // 演示数据（查询成功但无真实数据时兜底）：真实受影响应用榜为空时启用；查询失败展示真实空态
    const list = appsEmpty ? DEMO_TOP_APPS : (appsQuery.data ?? [])
    return hBarOption(
      list.slice(0, 6).map((a) => ({ name: a.name || a.code, value: a.events })),
      '#69f0ae',
    )
  }, [appsQuery.data, appsEmpty])

  return (
    <ScreenFrame screen={screen}>
      {hasError && (
        <div className="bs-banner" role="alert">
          部分数据接口加载失败，当前为降级展示，系统将自动重试
        </div>
      )}
      {isDemo && <div className="bs-demo-badge">演示数据：当前无真实数据，以下为示例展示</div>}
      <div className="bs-kpi-row" style={{ gridTemplateColumns: 'repeat(6, 1fr)' }}>
        {/* KPI 数字恒为真实值：无真实数据时保持 0，不做演示替换；演示兜底仅限下方图表区（保留演示角标） */}
        <KpiCard label="请求总量（24h）" value={requestsTotal} accent="#69f0ae" accentGlow="rgba(105,240,174,0.5)" />
        <KpiCard label="CC 超限次数" value={cc?.threshold_exceeded ?? 0} accent="#ffd54f" accentGlow="rgba(255,213,79,0.5)" />
        <KpiCard label="CC 拦截请求" value={cc?.requests_rejected ?? 0} accent="#ff5252" accentGlow="rgba(255,82,82,0.5)" />
        <KpiCard label="黑名单命中" value={ac?.deny_matches ?? 0} accent="#ff8a65" accentGlow="rgba(255,138,101,0.5)" />
        <KpiCard label="白名单命中" value={ac?.allow_matches ?? 0} />
        <KpiCard label="活跃临时封禁" value={ac?.active_temp_blocks ?? 0} accent="#b388ff" accentGlow="rgba(179,136,255,0.5)" />
      </div>
      <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '1fr 1.7fr 1fr', gap: 12 }}>
        <div style={columnStyle}>
          <ScreenPanel title="黑白名单命中分布" style={{ flex: 1 }}>
            <ScreenChart option={allowDeny} />
          </ScreenPanel>
          <ScreenPanel title="访问控制规则命中 TOP" style={{ flex: 1 }}>
            <ScreenChart option={ruleHits} />
          </ScreenPanel>
        </div>
        <div style={columnStyle}>
          <ScreenPanel title="请求趋势与时延（24h）" style={{ flex: 1.4 }}>
            <ScreenChart option={trafficTrend} />
          </ScreenPanel>
          <ScreenPanel title={`CC 临时封禁趋势（${dayjs(ccEmpty ? DEMO_CC.start : cc?.start).format('MM-DD')} 起）`} style={{ flex: 1 }}>
            <ScreenChart option={blockTrend} />
          </ScreenPanel>
        </div>
        <div style={columnStyle}>
          <ScreenPanel title="访问控制拦截占比" style={{ flex: 1 }}>
            <ScreenChart option={gaugeOption(denyRatio, '拦截占比', '#ff5252')} />
          </ScreenPanel>
          <ScreenPanel title="受影响应用 TOP6" style={{ flex: 1 }}>
            <ScreenChart option={topApps} />
          </ScreenPanel>
        </div>
      </div>
    </ScreenFrame>
  )
}
