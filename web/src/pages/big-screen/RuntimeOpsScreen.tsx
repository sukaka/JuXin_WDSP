import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import dayjs from 'dayjs'
import { dashboardsApi } from '../../api/dashboards'
import { ApiError } from '../../api/client'
import { systemHealthApi } from '../../api/systemHealth'
import { COMPONENT_NAME_META, COMPONENT_STATUS_META } from '../../utils/stage6'
import { BIG_SCREENS, REFRESH_INTERVAL } from './screens'
import ScreenFrame from './components/ScreenFrame'
import ScreenPanel from './components/ScreenPanel'
import ScreenChart from './components/ScreenChart'
import KpiCard from './components/KpiCard'
import EventTicker from './components/EventTicker'
import type { TickerItem } from './components/EventTicker'
import { gaugeOption, hBarOption } from './components/options'
import { DEMO_COMPONENTS, DEMO_RUNTIME_OVERVIEW, DEMO_STORAGE } from './components/demoRuntimeOps'

const screen = BIG_SCREENS.find((s) => s.id === 'runtime-ops')!

const columnStyle = { display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 } as const

const bytesToGB = (bytes?: number | null) => (bytes ?? 0) / 1024 ** 3

/** 系统运行监控大屏（big_screen.runtime.read；运行总览无权限时静默降级） */
export default function RuntimeOpsScreen() {
  const healthQuery = useQuery({
    queryKey: ['big-screen', 'runtime-health'],
    queryFn: () => systemHealthApi.overview(),
    refetchInterval: REFRESH_INTERVAL,
  })
  const storageQuery = useQuery({
    queryKey: ['big-screen', 'runtime-storage'],
    queryFn: () => systemHealthApi.storage(),
    refetchInterval: REFRESH_INTERVAL,
  })
  const overviewQuery = useQuery({
    queryKey: ['big-screen', 'runtime-overview'],
    queryFn: () => dashboardsApi.runtimeOverview(),
    refetchInterval: REFRESH_INTERVAL,
    retry: false,
  })

  // 查询失败：展示降级提示条，不静默切换演示数据（失败时展示真实空态，避免误导）；
  // 演示数据仅在查询成功且无真实数据时兜底，并明显标注（存储以磁盘总量为 0 判定为空，
  // 运行总览以网关/发布/报告三块全缺判定为空）；一旦有真实数据立即展示真实数据。
  // 无运行总览权限（403）属预期受限视图，静默为空，不计入降级提示
  const isForbidden = (error: unknown) => error instanceof ApiError && error.status === 403
  const hasError =
    healthQuery.isError ||
    storageQuery.isError ||
    (overviewQuery.isError && !isForbidden(overviewQuery.error))
  const healthEmpty = healthQuery.isSuccess && (healthQuery.data?.components ?? []).length === 0
  const storageEmpty = storageQuery.isSuccess && (storageQuery.data?.disk_total_bytes ?? 0) <= 0
  const overviewEmpty =
    overviewQuery.isSuccess && !overviewQuery.data?.gateway && !overviewQuery.data?.publish && !overviewQuery.data?.reports
  const isDemo = healthEmpty || storageEmpty || overviewEmpty

  const storage = storageEmpty ? DEMO_STORAGE : storageQuery.data
  const overview = overviewEmpty ? DEMO_RUNTIME_OVERVIEW : overviewQuery.data

  const components = useMemo(
    () => (healthEmpty ? DEMO_COMPONENTS : (healthQuery.data?.components ?? [])),
    [healthEmpty, healthQuery.data],
  )
  const upCount = components.filter((c) => c.status === 'UP').length

  const diskUsage = storage && storage.disk_total_bytes > 0
    ? ((storage.disk_total_bytes - storage.disk_free_bytes) / storage.disk_total_bytes) * 100
    : 0
  const valkeyUsage = storage && storage.valkey_max_memory_bytes > 0
    ? (storage.valkey_used_memory_bytes / storage.valkey_max_memory_bytes) * 100
    : 0
  const publishRate = (overview?.publish?.success_rate ?? 0) * 100

  const storageBars = useMemo(
    () =>
      hBarOption(
        [
          { name: 'PostgreSQL', value: Number(bytesToGB(storage?.postgres_size_bytes).toFixed(2)) },
          { name: 'Valkey 内存', value: Number(bytesToGB(storage?.valkey_used_memory_bytes).toFixed(2)) },
          { name: '报告文件', value: Number(bytesToGB(storage?.reports_size_bytes).toFixed(2)) },
          { name: '备份文件', value: Number(bytesToGB(storage?.backups_size_bytes).toFixed(2)) },
        ],
        '#ffd54f',
      ),
    [storage],
  )

  const issueItems: TickerItem[] = useMemo(() => {
    const issues: TickerItem[] = components
      .filter((c) => c.status !== 'UP')
      .map((c) => ({
        key: c.component,
        color: '#ff5252',
        time: c.taken_at ? dayjs(c.taken_at).format('HH:mm:ss') : '--:--:--',
        content: `${COMPONENT_NAME_META[c.component] ?? c.component} 状态异常：${COMPONENT_STATUS_META[c.status]?.label ?? c.status}${c.message ? `（${c.message}）` : ''}`,
      }))
    // 演示数据（查询成功但无真实数据时兜底）：演示组件全部 UP，异常动态自然为空（显示"全部组件运行正常"）
    for (const name of healthEmpty ? [] : (healthQuery.data?.missing_components ?? [])) {
      issues.push({
        key: `missing-${name}`,
        color: '#ffd54f',
        time: '--:--:--',
        content: `${COMPONENT_NAME_META[name] ?? name} 缺少健康快照`,
      })
    }
    return issues
  }, [components, healthEmpty, healthQuery.data])

  return (
    <ScreenFrame screen={screen}>
      {hasError && (
        <div className="bs-banner" role="alert">
          部分数据接口加载失败，当前为降级展示，系统将自动重试
        </div>
      )}
      {isDemo && <div className="bs-demo-badge">演示数据：当前无真实数据，以下为示例展示</div>}
      <div className="bs-kpi-row" style={{ gridTemplateColumns: 'repeat(6, 1fr)' }}>
        <KpiCard
          label="组件在线"
          value={upCount}
          suffix={`/ ${components.length}`}
          accent={upCount === components.length ? '#69f0ae' : '#ff5252'}
          accentGlow={upCount === components.length ? 'rgba(105,240,174,0.5)' : 'rgba(255,82,82,0.5)'}
        />
        <KpiCard
          label="网关运行时长"
          value={(overview?.gateway?.uptime_seconds ?? 0) / 3600}
          suffix="小时"
          formatter={(v) => v.toFixed(1)}
        />
        <KpiCard
          label="发布成功率"
          value={publishRate}
          suffix="%"
          formatter={(v) => v.toFixed(1)}
          accent="#69f0ae"
          accentGlow="rgba(105,240,174,0.5)"
        />
        <KpiCard
          label="报告成功率"
          value={(overview?.reports?.success_rate ?? 0) * 100}
          suffix="%"
          formatter={(v) => v.toFixed(1)}
          accent="#2979ff"
          accentGlow="rgba(41,121,255,0.5)"
        />
        <KpiCard label="磁盘使用率" value={diskUsage} suffix="%" formatter={(v) => v.toFixed(1)} accent="#ffd54f" accentGlow="rgba(255,213,79,0.5)" />
        <KpiCard
          label="数据库大小"
          value={bytesToGB(storage?.postgres_size_bytes)}
          suffix="GB"
          formatter={(v) => v.toFixed(2)}
          accent="#b388ff"
          accentGlow="rgba(179,136,255,0.5)"
        />
      </div>
      <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '1fr 1.7fr 1fr', gap: 12 }}>
        <div style={columnStyle}>
          <ScreenPanel title={`组件健康点阵（${upCount}/${components.length} 在线）`} style={{ flex: 1 }}>
            <div className="bs-status-grid">
              {components.map((c) => {
                const up = c.status === 'UP'
                return (
                  <div className="bs-status-cell" key={c.component}>
                    <span
                      className="bs-status-light"
                      style={{ background: up ? '#69f0ae' : '#ff5252', color: up ? '#69f0ae' : '#ff5252' }}
                    />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 13, color: '#d6e4ff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {COMPONENT_NAME_META[c.component] ?? c.component}
                      </div>
                      <div style={{ fontSize: 11, color: 'rgba(214,228,255,0.5)' }}>
                        {up
                          ? `正常${c.latency_ms != null ? ` · ${c.latency_ms}ms` : ''}`
                          : (COMPONENT_STATUS_META[c.status]?.label ?? c.status)}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </ScreenPanel>
        </div>
        <div style={columnStyle}>
          <div style={{ flex: 1, minHeight: 0, display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            <ScreenPanel title="磁盘水位">
              <ScreenChart option={gaugeOption(diskUsage, '磁盘使用率', '#ffd54f')} />
            </ScreenPanel>
            <ScreenPanel title="Valkey 内存水位">
              <ScreenChart option={gaugeOption(valkeyUsage, '内存使用率', '#00e5ff')} />
            </ScreenPanel>
            <ScreenPanel title="配置发布成功率">
              <ScreenChart option={gaugeOption(publishRate, '发布成功率', '#69f0ae')} />
            </ScreenPanel>
          </div>
          <ScreenPanel title="异常组件动态" style={{ flex: 1 }}>
            <EventTicker items={issueItems} empty="全部组件运行正常" />
          </ScreenPanel>
        </div>
        <div style={columnStyle}>
          <ScreenPanel title="存储占用分布（GB）" style={{ flex: 1 }}>
            <ScreenChart option={storageBars} />
          </ScreenPanel>
          <ScreenPanel title="运行总览" style={{ flex: 1 }}>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 14, padding: '0 8px' }}>
              {[
                {
                  label: '网关状态',
                  value: overview?.gateway?.status
                    ? (COMPONENT_STATUS_META[overview.gateway.status]?.label ?? overview.gateway.status)
                    : '未知',
                  color: overview?.gateway?.status === 'UP' ? '#69f0ae' : '#ffd54f',
                },
                { label: '近期待发布任务', value: `${overview?.publish?.total ?? 0} 个（失败 ${overview?.publish?.failed ?? 0}）`, color: '#d6e4ff' },
                { label: '近期报告任务', value: `${overview?.reports?.total ?? 0} 个（失败 ${overview?.reports?.failed ?? 0}）`, color: '#d6e4ff' },
                { label: '报表文件数', value: `${storage?.reports_file_count ?? 0} 个`, color: '#d6e4ff' },
                { label: '备份文件数', value: `${storage?.backups_file_count ?? 0} 个`, color: '#d6e4ff' },
                { label: '数据库连接数', value: `${storage?.db_connections ?? 0}`, color: '#d6e4ff' },
              ].map((row) => (
                <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, borderBottom: '1px dashed rgba(0,229,255,0.12)', paddingBottom: 8 }}>
                  <span style={{ color: 'rgba(214,228,255,0.6)' }}>{row.label}</span>
                  <span style={{ color: row.color, fontFamily: 'monospace' }}>{row.value}</span>
                </div>
              ))}
            </div>
          </ScreenPanel>
        </div>
      </div>
    </ScreenFrame>
  )
}
