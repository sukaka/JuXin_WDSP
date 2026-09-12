import dayjs from 'dayjs'
import type { RuntimeComponent, RuntimeOverviewData, StorageOverview } from '../../../types'

/**
 * 演示数据（无真实数据时兜底）
 *
 * 仅供演示：当接口查询成功但数据为空、或查询失败时，运行运维屏各数据区
 * （组件健康点阵、运行时长/成功率 KPI、磁盘与内存水位、存储占用、运行总览）
 * 使用本文件数据兜底；一旦接口返回真实数据立即替换，不影响真实数据路径。
 * 演示态下组件全部 UP（绿色），「异常组件动态」面板自然显示"全部组件运行正常"。
 */

const GB = 1024 ** 3

const now = dayjs()

/** 组件健康点阵（演示数据，无真实数据时兜底；八大核心组件全 UP 绿） */
export const DEMO_COMPONENTS: RuntimeComponent[] = [
  { component: '防护网关', status: 'UP', latency_ms: 2, taken_at: now.toISOString() },
  { component: 'WAF 检测引擎', status: 'UP', latency_ms: 3, taken_at: now.toISOString() },
  { component: 'PostgreSQL 数据库', status: 'UP', latency_ms: 5, taken_at: now.toISOString() },
  { component: 'Valkey 缓存', status: 'UP', latency_ms: 1, taken_at: now.toISOString() },
  { component: '安全事件采集器', status: 'UP', latency_ms: 4, taken_at: now.toISOString() },
  { component: '配置发布服务', status: 'UP', latency_ms: 2, taken_at: now.toISOString() },
  { component: '报表生成服务', status: 'UP', latency_ms: 6, taken_at: now.toISOString() },
  { component: '证书巡检服务', status: 'UP', latency_ms: 1, taken_at: now.toISOString() },
]

/** 存储容量（演示数据，无真实数据时兜底；磁盘 500GB 用量约 37%，Valkey 内存水位 30%） */
export const DEMO_STORAGE: StorageOverview = {
  postgres_size_bytes: Number((12.6 * GB).toFixed(0)),
  db_connections: 17,
  valkey_used_memory_bytes: Number((1.2 * GB).toFixed(0)),
  valkey_max_memory_bytes: 4 * GB,
  disk_total_bytes: 500 * GB,
  disk_free_bytes: 316 * GB,
  reports_size_bytes: Number((2.4 * GB).toFixed(0)),
  reports_file_count: 26,
  backups_size_bytes: Number((8.2 * GB).toFixed(0)),
  backups_file_count: 8,
  collected_at: now.toISOString(),
}

/** 运行总览（演示数据，无真实数据时兜底；网关已稳定运行约 14 天，发布/报告近 7 天统计） */
export const DEMO_RUNTIME_OVERVIEW: RuntimeOverviewData = {
  generated_at: now.toISOString(),
  gateway: { status: 'UP', uptime_seconds: 14.2 * 24 * 3600, snapshot_at: now.toISOString() },
  publish: { window_days: 7, total: 23, success: 22, failed: 1, success_rate: 22 / 23, avg_duration_seconds: 3.8 },
  reports: { window_days: 7, total: 14, success: 14, failed: 0, success_rate: 1 },
}
