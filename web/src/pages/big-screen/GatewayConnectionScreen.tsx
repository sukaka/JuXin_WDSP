import { useMemo, useState, type CSSProperties } from 'react'
import { useQuery } from '@tanstack/react-query'
import { systemHealthApi } from '../../api/systemHealth'
import { escapeHtml, formatBytesPerSecond, pickBandwidthScale, splitBandwidthRate } from '../../utils/format'
import type { GatewayTrendRange, GatewayTrendSource } from '../../types'
import { BIG_SCREENS } from './screens'
import ScreenFrame from './components/ScreenFrame'
import ScreenPanel from './components/ScreenPanel'
import ScreenChart from './components/ScreenChart'
import KpiCard from './components/KpiCard'
import { donutOption, dualAxisTrendOption, gaugeOption, hBarOption, trendOption } from './components/options'
import { buildDemoGatewayTrend } from './components/demoGatewayConnections'

const screen = BIG_SCREENS.find((s) => s.id === 'gateway-connections')!

const columnStyle = { display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 } as const

const RANGE_OPTIONS: { value: GatewayTrendRange; label: string; refreshMs: number; timeFormat: string }[] = [
  { value: '10m', label: '实时 10m', refreshMs: 5_000, timeFormat: 'HH:mm:ss' },
  { value: '1h', label: '近 1h', refreshMs: 30_000, timeFormat: 'HH:mm' },
  { value: '6h', label: '近 6h', refreshMs: 30_000, timeFormat: 'HH:mm' },
  { value: '24h', label: '近 24h', refreshMs: 30_000, timeFormat: 'MM-DD HH:mm' },
]

const SOURCE_LABELS: Record<GatewayTrendSource, { label: string; fallback?: boolean }> = {
  gateway_live: { label: '实时 2s 采样' },
  database: { label: '历史 30s 采样' },
  database_fallback: { label: '历史降级 30s 采样', fallback: true },
}

const BYPASS_REASONS: Record<string, string> = {
  CPU_THRESHOLD: 'CPU 超过阈值',
  MEMORY_THRESHOLD: '内存超过阈值',
  CPU_AND_MEMORY_THRESHOLD: 'CPU 与内存超过阈值',
  MIN_HOLD_OR_SAMPLE_UNAVAILABLE: '最短保持期/采样异常',
}

const DEFAULT_SESSION_CAPACITY = 10000

/** 网关连接与会话大屏（big_screen.runtime.read） */
export default function GatewayConnectionScreen() {
  const [range, setRange] = useState<GatewayTrendRange>('10m')
  const activeRange = RANGE_OPTIONS.find((item) => item.value === range) ?? RANGE_OPTIONS[0]

  const trendQuery = useQuery({
    queryKey: ['big-screen', 'gateway-connections', range],
    queryFn: () => systemHealthApi.gatewayTrend(range),
    refetchInterval: activeRange.refreshMs,
  })

  // 查询失败：展示降级提示条，绝不静默切换演示数据（失败时展示真实空态，避免误导）；
  // 演示数据仅在查询成功且 points 为空时用于下方图表区兜底，顶部 KPI 恒保持真实值
  const hasError = trendQuery.isError
  const isDemo = trendQuery.isSuccess && (trendQuery.data?.points?.length ?? 0) === 0
  const demo = useMemo(() => buildDemoGatewayTrend(range), [range])

  const realData = trendQuery.data
  const realCurrent = realData?.current ?? null

  const chartPoints = useMemo(
    () => (isDemo ? demo.points : (realData?.points ?? [])),
    [isDemo, demo.points, realData?.points],
  )
  const chartCurrent = isDemo ? (demo.current ?? null) : realCurrent
  const chartSummary = isDemo ? (demo.summary ?? null) : (realData?.summary ?? null)
  const chartApps = useMemo(
    () => (isDemo ? demo.applications : (realData?.applications ?? [])),
    [isDemo, demo.applications, realData?.applications],
  )

  const times = useMemo(() => chartPoints.map((p) => p.taken_at), [chartPoints])

  const tcpTrend = useMemo(
    () =>
      dualAxisTrendOption(
        times,
        [
          {
            name: '并发连接',
            data: chartPoints.map((p) => p.tcp_connections_active),
            color: '#26c6da',
            yAxisIndex: 0,
          },
          {
            name: '新建连接/秒',
            data: chartPoints.map((p) => Number(p.tcp_connections_accepted_per_second.toFixed(2))),
            color: '#ffd54f',
            area: false,
            yAxisIndex: 1,
          },
        ],
        {
          leftAxisName: '并发连接',
          rightAxisName: '新建/s',
          timeFormat: activeRange.timeFormat,
        },
      ),
    [times, chartPoints, activeRange.timeFormat],
  )

  const sessionQpsTrend = useMemo(
    () =>
      dualAxisTrendOption(
        times,
        [
          {
            name: '活跃会话',
            data: chartPoints.map((p) => p.http_sessions_active),
            color: '#b388ff',
            yAxisIndex: 0,
          },
          {
            name: '实时 QPS',
            data: chartPoints.map((p) => Number(p.http_requests_per_second.toFixed(2))),
            color: '#69f0ae',
            area: false,
            yAxisIndex: 1,
          },
          {
            name: '新建会话/秒',
            data: chartPoints.map((p) => Number(p.http_sessions_new_per_second.toFixed(2))),
            color: '#00b0ff',
            area: false,
            dashed: true,
            yAxisIndex: 1,
          },
        ],
        {
          leftAxisName: '活跃会话',
          rightAxisName: '速率(/s)',
          timeFormat: activeRange.timeFormat,
        },
      ),
    [times, chartPoints, activeRange.timeFormat],
  )

  const { bandwidthOption, bandwidthUnit } = useMemo(() => {
    const maxBps = chartPoints.reduce(
      (max, p) => Math.max(max, p.bytes_in_per_second, p.bytes_out_per_second),
      0,
    )
    const { unit, divisor } = pickBandwidthScale(maxBps)
    const option = trendOption(
      times,
      [
        {
          name: `入站 (${unit})`,
          data: chartPoints.map((p) => Number((p.bytes_in_per_second / divisor).toFixed(2))),
          color: '#00e5ff',
        },
        {
          name: `出站 (${unit})`,
          data: chartPoints.map((p) => Number((p.bytes_out_per_second / divisor).toFixed(2))),
          color: '#69f0ae',
        },
      ],
      activeRange.timeFormat,
      unit,
    )
    return { bandwidthOption: option, bandwidthUnit: unit }
  }, [times, chartPoints, activeRange.timeFormat])

  const statusDonut = useMemo(
    () =>
      donutOption(
        [
          { name: '2xx', value: chartCurrent?.status_2xx_total ?? 0 },
          { name: '3xx', value: chartCurrent?.status_3xx_total ?? 0 },
          { name: '4xx', value: chartCurrent?.status_4xx_total ?? 0 },
          { name: '5xx', value: chartCurrent?.status_5xx_total ?? 0 },
        ],
        ['#69f0ae', '#00e5ff', '#ffd54f', '#ff5252'],
      ),
    [chartCurrent],
  )

  const tcpStatesBar = useMemo(() => {
    const states = chartCurrent?.tcp_states
    if (!states) return null
    return hBarOption(
      [
        { name: 'ESTABLISHED', value: states.established },
        { name: 'TIME_WAIT', value: states.time_wait },
        { name: 'FIN_WAIT', value: states.fin_wait },
        { name: 'SYN_RECV', value: states.syn_recv },
        { name: 'LISTEN', value: states.listen },
        { name: 'CLOSE_WAIT', value: states.close_wait },
        { name: 'OTHER', value: states.other },
      ],
      '#26c6da',
    )
  }, [chartCurrent?.tcp_states])

  const topAppsChart = useMemo(() => {
    if (chartApps.length === 0) return null
    const top = chartApps.slice(0, 6)
    const useInFlight = top.every((a) => a.requests_per_second <= 0)
    return hBarOption(
      top.map((app) => {
        const displayName = app.app_name || app.app_code || app.app_id
        const detail = [
          `<b>${escapeHtml(displayName)}</b>`,
          `实时 QPS：${app.requests_per_second.toFixed(2)} req/s`,
          `在途并发：${app.requests_in_flight}`,
          `累计请求：${app.requests_total.toLocaleString()}`,
          `入/出站：${formatBytesPerSecond(app.bytes_in_per_second)} / ${formatBytesPerSecond(app.bytes_out_per_second)}`,
          `4xx / 5xx：${app.status_4xx_total} / ${app.status_5xx_total}`,
        ].join('<br/>')
        return {
          name: displayName,
          value: useInFlight
            ? app.requests_in_flight
            : Number(app.requests_per_second.toFixed(1)),
          detail,
        }
      }),
      '#26c6da',
      {
        valueSuffix: useInFlight ? ' 并发' : '/s',
        tooltipFormatter: (item) => item.detail ?? escapeHtml(item.name),
      },
    )
  }, [chartApps])

  // KPI 恒使用真实当前快照值（不做演示替换）
  const realCapacity = realCurrent?.http_sessions_capacity ?? DEFAULT_SESSION_CAPACITY
  const realBytesIn = realCurrent?.bytes_in_per_second ?? 0
  const realBytesOut = realCurrent?.bytes_out_per_second ?? 0
  const realBandwidthSplit = splitBandwidthRate(realBytesIn + realBytesOut)
  const realBypass = realCurrent?.software_bypass
  const bypassActive = realBypass?.active === true
  const bypassEnabled = realBypass?.enabled === true

  const bypassLabel = bypassActive ? '旁路透传中' : bypassEnabled ? '自动保护中' : '未启用'
  const bypassAccent = bypassActive ? '#ff5252' : bypassEnabled ? '#69f0ae' : '#90a4ae'
  const bypassGlow = bypassActive
    ? 'rgba(255, 82, 82, 0.55)'
    : bypassEnabled
      ? 'rgba(105, 240, 174, 0.45)'
      : 'rgba(144, 164, 174, 0.35)'
  const bypassSub = bypassActive
    ? (realBypass?.reason ? (BYPASS_REASONS[realBypass.reason] ?? realBypass.reason) : '已触发阈值')
    : bypassEnabled
      ? `CPU>${realBypass?.cpu_threshold_percent ?? '-'}% / 内存>${realBypass?.memory_threshold_percent ?? '-'}%`
      : '常规检测链路'

  // 左列资源仪表盘（演示态展示演示水位，真实态展示真实水位）
  const gaugeCpu = chartCurrent?.cpu_percent ?? 0
  const gaugeMem = chartCurrent?.memory_percent ?? 0
  const chartCapacity = chartCurrent?.http_sessions_capacity ?? DEFAULT_SESSION_CAPACITY
  const sessionSlotPercent =
    chartCapacity > 0 ? Math.min(100, ((chartCurrent?.http_sessions_active ?? 0) / chartCapacity) * 100) : 0
  const hasFd = chartCurrent?.fd_usage_percent != null
  const thirdGaugeVal = hasFd ? (chartCurrent?.fd_usage_percent ?? 0) : sessionSlotPercent
  const thirdGaugeLabel = hasFd ? 'FD 水位' : '会话槽位'
  const cpuWarn = (chartCurrent?.software_bypass?.cpu_threshold_percent ?? 85)
  const memWarn = (chartCurrent?.software_bypass?.memory_threshold_percent ?? 85)

  const sourceInfo = realData?.source
    ? SOURCE_LABELS[realData.source]
    : hasError
      ? { label: '采样中断', fallback: true }
      : { label: '采样加载中...' }

  return (
    <ScreenFrame screen={screen} refreshIntervalMs={activeRange.refreshMs}>
      {hasError && (
        <div className="bs-banner" role="alert">
          部分数据接口加载失败，当前为降级展示，系统将自动重试
        </div>
      )}
      {isDemo && <div className="bs-demo-badge">演示数据：当前无真实采样数据，图表区以下为示例展示</div>}

      <div className="bs-toolbar">
        <div className="bs-range-group" role="group" aria-label="时间窗口切换">
          {RANGE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              className={`bs-range-btn${range === opt.value ? ' active' : ''}`}
              onClick={() => setRange(opt.value)}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <div className="bs-source-meta">
          <span className={`bs-source-pill${sourceInfo.fallback ? ' fallback' : ''}`}>
            <span className="bs-source-dot" />
            {sourceInfo.label}
          </span>
          {realData?.node && <span>节点：{realData.node}</span>}
        </div>
      </div>

      <div className="bs-kpi-row" style={{ gridTemplateColumns: 'repeat(7, 1fr)' }}>
        <KpiCard
          label="当前 TCP 连接"
          value={realCurrent?.tcp_connections_active ?? 0}
          accent="#26c6da"
          accentGlow="rgba(38,198,218,0.55)"
        />
        <KpiCard
          label="新建连接/秒"
          value={realCurrent?.tcp_connections_accepted_per_second ?? 0}
          suffix="/s"
          formatter={(v) => v.toFixed(1)}
          accent="#00e5ff"
          accentGlow="rgba(0,229,255,0.5)"
        />
        <KpiCard
          label="活跃 HTTP 会话"
          value={realCurrent?.http_sessions_active ?? 0}
          suffix={`/ ${realCapacity}`}
          accent="#b388ff"
          accentGlow="rgba(179,136,255,0.5)"
        />
        <KpiCard
          label="新建会话/秒"
          value={realCurrent?.http_sessions_new_per_second ?? 0}
          suffix="/s"
          formatter={(v) => v.toFixed(1)}
          accent="#2979ff"
          accentGlow="rgba(41,121,255,0.5)"
        />
        <KpiCard
          label="实时 QPS"
          value={realCurrent?.http_requests_per_second ?? 0}
          suffix="req/s"
          formatter={(v) => v.toFixed(1)}
          accent="#69f0ae"
          accentGlow="rgba(105,240,174,0.5)"
        />
        <div
          className="bs-kpi"
          style={
            {
              '--bs-accent': '#ffd54f',
              '--bs-accent-glow': 'rgba(255, 213, 79, 0.5)',
            } as CSSProperties
          }
        >
          <div className="bs-kpi-label">实时吞吐带宽</div>
          <div className="bs-kpi-value" style={{ fontSize: 24 }}>
            {realBandwidthSplit.value.toFixed(realBandwidthSplit.digits)}
            <small>{realBandwidthSplit.unit}</small>
          </div>
          <div className="bs-kpi-sub">
            入 {formatBytesPerSecond(realBytesIn)} · 出 {formatBytesPerSecond(realBytesOut)}
          </div>
        </div>
        <div
          className="bs-kpi"
          style={
            {
              '--bs-accent': bypassAccent,
              '--bs-accent-glow': bypassGlow,
            } as CSSProperties
          }
        >
          <div className="bs-kpi-label">软件旁路状态</div>
          <div className="bs-kpi-status">{bypassLabel}</div>
          <div className="bs-kpi-sub">{bypassSub}</div>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '1.05fr 1.7fr 1.05fr', gap: 12 }}>
        <div style={columnStyle}>
          <ScreenPanel title="资源水位与系统负载" style={{ flex: 1.05 }}>
            <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 4 }}>
              <ScreenChart
                option={gaugeOption(gaugeCpu, 'CPU', gaugeCpu >= cpuWarn ? '#ff5252' : '#26c6da', true)}
              />
              <ScreenChart
                option={gaugeOption(gaugeMem, '内存', gaugeMem >= memWarn ? '#ff5252' : '#ffd54f', true)}
              />
              <ScreenChart option={gaugeOption(thirdGaugeVal, thirdGaugeLabel, '#b388ff', true)} />
            </div>
            <div className="bs-resource-meta">
              <span>
                Load:{' '}
                {chartCurrent?.load1 != null
                  ? `${chartCurrent.load1.toFixed(2)} / ${(chartCurrent.load5 ?? 0).toFixed(2)} / ${(chartCurrent.load15 ?? 0).toFixed(2)}`
                  : '-'}
              </span>
              <span>
                会话槽位: {chartCurrent?.http_sessions_active ?? 0}/{chartCapacity} ({sessionSlotPercent.toFixed(1)}%)
              </span>
            </div>
          </ScreenPanel>

          <ScreenPanel title="HTTP 状态码分布" style={{ flex: 0.95 }}>
            <ScreenChart option={statusDonut} />
          </ScreenPanel>

          <ScreenPanel title="TCP 连接状态分布" style={{ flex: 1 }}>
            {tcpStatesBar ? (
              <ScreenChart option={tcpStatesBar} />
            ) : (
              <div className="bs-empty">当前节点未提供 TCP 状态细分</div>
            )}
          </ScreenPanel>
        </div>

        <div style={columnStyle}>
          <ScreenPanel
            title="TCP 并发连接与新建速率"
            extra={
              chartSummary
                ? `峰值 ${chartSummary.peak_tcp_connections_active} · 均值 ${chartSummary.avg_tcp_connections_active.toFixed(1)} · 峰值新建 ${chartSummary.peak_tcp_connections_accepted_per_second.toFixed(1)}/s`
                : undefined
            }
            style={{ flex: 1 }}
          >
            <ScreenChart option={tcpTrend} />
          </ScreenPanel>

          <ScreenPanel
            title="活跃会话、新建速率与实时 QPS"
            extra={
              chartSummary
                ? `峰值会话 ${chartSummary.peak_http_sessions_active} · 峰值新建 ${chartSummary.peak_http_sessions_new_per_second.toFixed(1)}/s · 峰值 QPS ${chartSummary.peak_http_requests_per_second.toFixed(1)}`
                : undefined
            }
            style={{ flex: 1 }}
          >
            <ScreenChart option={sessionQpsTrend} />
          </ScreenPanel>
        </div>

        <div style={columnStyle}>
          <ScreenPanel
            title={`实时进出站带宽吞吐（${bandwidthUnit}）`}
            extra={
              chartSummary
                ? `入峰 ${formatBytesPerSecond(chartSummary.peak_bytes_in_per_second)} · 出峰 ${formatBytesPerSecond(chartSummary.peak_bytes_out_per_second)}`
                : undefined
            }
            style={{ flex: 1.05 }}
          >
            <ScreenChart option={bandwidthOption} />
          </ScreenPanel>

          <ScreenPanel title="站点实时负载 TOP 排行" style={{ flex: 0.95 }}>
            {topAppsChart ? (
              <ScreenChart option={topAppsChart} />
            ) : (
              <div className="bs-empty">暂无按站点实时负载数据</div>
            )}
          </ScreenPanel>
        </div>
      </div>
    </ScreenFrame>
  )
}
