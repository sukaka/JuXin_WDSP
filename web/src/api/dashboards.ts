import { request } from './client'
import type { AuditOverviewData, RuntimeOverviewData, SecurityOverviewData } from '../types'

/** 态势总览（安全/运行/审计三视角，按角色权限调用） */
export const dashboardsApi = {
  /** 安全总览（dashboard.security.read），range: 1h/24h/7d/30d */
  securityOverview: (range?: string) =>
    request<SecurityOverviewData>('/dashboard/security-overview', { query: { range } }),
  /** 运行总览（dashboard.runtime.read） */
  runtimeOverview: () => request<RuntimeOverviewData>('/dashboard/runtime-overview'),
  /** 审计态势（dashboard.audit.read） */
  auditOverview: () => request<AuditOverviewData>('/dashboard/audit-overview'),
}
