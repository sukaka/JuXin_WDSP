import dayjs from 'dayjs'
import type { ApiPosture, ApiRuntimeStatistics } from '../../../api/apiSecurity'

/**
 * 演示数据（无真实数据时兜底）
 *
 * 仅供演示：当接口查询成功但数据为空、或查询失败时，API 安全屏各数据区
 * （接口资产/风险发现 KPI、资产与学习状态分布、风险等级雷达、运行时处置分布、
 * 热点接口、最新风险发现滚动）使用本文件数据兜底；一旦接口返回真实数据立即替换，
 * 不影响真实数据路径。状态/类型枚举与 server 端 apiassets / apifindings 一致。
 */

/** API 安全态势（演示数据，无真实数据时兜底） */
export const DEMO_API_POSTURE: ApiPosture = {
  endpoints: {
    total: 187,
    by_asset_status: { CONFIRMED: 128, DISCOVERED: 41, IGNORED: 12, DEPRECATED: 6 },
    by_learning_status: { LEARNED: 152, LEARNING: 21, NOT_STARTED: 10, PAUSED: 4 },
  },
  findings: {
    open_total: 23,
    open_by_severity: { HIGH: 4, MEDIUM: 9, LOW: 7, INFO: 3 },
  },
  learning_coverage: 0.813,
  learning_covered: 152,
  model_freeze_rate: 0.621,
  model_version_total: 214,
  model_version_frozen: 133,
}

/** API 运行时统计（演示数据，无真实数据时兜底；final_action/risk_level 与后端枚举一致） */
export const DEMO_API_RUNTIME_STATS: ApiRuntimeStatistics = {
  total: 1284,
  by_final_action: { ALLOW: 1102, LOG: 96, BLOCK: 86 },
  by_risk_level: { HIGH: 36, MEDIUM: 118, LOW: 214, INFO: 916 },
  top_endpoints: [
    { endpoint_key: 'POST /api/v1/users/login', count: 286 },
    { endpoint_key: 'GET /api/v1/orders/{id}', count: 231 },
    { endpoint_key: 'POST /api/v1/pay/callback', count: 184 },
    { endpoint_key: 'GET /api/v1/users/{id}/profile', count: 152 },
    { endpoint_key: 'PUT /api/v1/goods/{id}', count: 117 },
    { endpoint_key: 'POST /api/v1/files/upload', count: 96 },
  ],
}

/** 风险发现滚动条目（演示数据，无真实数据时兜底；字段为 ApiFinding 的展示子集） */
export interface DemoApiFinding {
  id: string
  severity: string
  title: string
  last_seen_at: string
}

/** 发现模板池：类型覆盖影子接口/越权/敏感泄露/模型偏离等（演示数据，无真实数据时兜底） */
const DEMO_FINDING_POOL: Omit<DemoApiFinding, 'id' | 'last_seen_at'>[] = [
  { severity: 'HIGH', title: '发现未登记的影子接口 /api/v1/internal/export' },
  { severity: 'HIGH', title: 'GET /api/v1/orders/{id} 存在对象级越权（BOLA）风险' },
  { severity: 'HIGH', title: 'PUT /api/v1/users/{id} 接受未定义字段 role（批量赋值）' },
  { severity: 'MEDIUM', title: '/api/v1/users/{id}/profile 响应携带未脱敏手机号' },
  { severity: 'MEDIUM', title: '僵尸接口 /api/v0/order/query 仍可被访问' },
  { severity: 'MEDIUM', title: 'POST /api/v1/pay/callback 请求体偏离已确认模型' },
  { severity: 'MEDIUM', title: '低权限身份调用管理端接口 /api/v1/admin/config（BFLA）' },
  { severity: 'MEDIUM', title: '发现未登记的影子接口 /api/v2/beta/coupon' },
  { severity: 'LOW', title: '/api/v1/search 调用频率偏离行为基线 3.2 倍' },
  { severity: 'LOW', title: '已下线接口 /api/v1/old-login 出现访问尝试' },
  { severity: 'LOW', title: 'GET /api/v1/goods 查询参数类型偏离学习基线' },
  { severity: 'INFO', title: '/api/v1/files/{id} 响应包含邮箱字段（已确认脱敏）' },
]

/** 最新风险发现滚动列表（演示数据，无真实数据时兜底；时间相对模块加载时刻） */
export const DEMO_API_FINDINGS: DemoApiFinding[] = DEMO_FINDING_POOL.map((f, i) => ({
  ...f,
  id: `demo-finding-${String(i + 1).padStart(2, '0')}`,
  last_seen_at: dayjs()
    .subtract(4 + i * 13 + (i % 4) * 7, 'minute')
    .toISOString(),
}))
