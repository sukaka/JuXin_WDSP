import { describe, expect, it } from 'vitest'
import { filterMenusByRoles } from '../menu'

describe('filterMenusByRoles', () => {
  it('系统管理员：工作台/配置版本/网关状态/可信代理/系统告警/系统运维/用户管理/角色权限/系统设置/个人中心', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN']).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/config-versions',
      '/gateway-status',
      '/trusted-proxies',
      '/system-alerts',
      '/system-monitoring',
      '/storage',
      '/backup-restore',
      '/system-upgrade',
      '/delivery-check',
      '/ai/assistant',
      '/ai/report-summary',
      '/ai/tasks',
      '/ai/admin/models',
      '/ai/admin/agents',
      '/ai/admin/tools',
      '/ai/admin/prompts',
      '/ai/admin/memories',
      '/ai/admin/usage',
      '/ai/admin/audits',
      '/ai/admin/evaluations',
      '/users',
      '/roles',
      '/system-settings',
      '/profile',
    ])
  })

  it('审计管理员：工作台/配置版本/WAF策略/访问控制/事件中心只读菜单/统计分析/系统告警/报告任务/报告归档/交付检查/角色权限/登录日志/操作审计/个人中心', () => {
    const keys = filterMenusByRoles(['AUDIT_ADMIN']).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/config-versions',
      '/protection-policies',
      '/waf-rules',
      '/exceptions',
      '/trusted-proxies',
      '/access-rules',
      '/rate-limit',
      '/temporary-blocks',
      '/access-control-events',
      '/access-control-versions',
      '/security-events',
      '/event-statistics',
      '/analytics',
      '/system-alerts',
      '/reports',
      '/report-archives',
      '/delivery-check',
      '/ai/admin/usage',
      '/ai/admin/audits',
      '/ai/admin/evaluations',
      '/roles',
      '/login-logs',
      '/audits',
      '/profile',
    ])
  })

  it('安全管理员：工作台 + 应用防护/WAF策略/访问控制/事件中心 + 安全态势/报表中心全部菜单 + 个人中心', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN']).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/applications',
      '/certificates',
      '/config-publish',
      '/config-versions',
      '/gateway-status',
      '/protection-policies',
      '/waf-rules',
      '/custom-rules',
      '/exceptions',
      '/trusted-proxies',
      '/access-rules',
      '/rate-limit',
      '/temporary-blocks',
      '/access-control-events',
      '/access-control-versions',
      '/security-events',
      '/event-statistics',
      '/security-overview',
      '/analytics',
      '/system-alerts',
      '/reports',
      '/report-templates',
      '/report-archives',
      '/ai/assistant',
      '/ai/event-analysis',
      '/ai/attack-profile',
      '/ai/attack-chain',
      '/ai/policy-recommendation',
      '/ai/report-summary',
      '/ai/tasks',
      '/ai/admin/models',
      '/ai/admin/agents',
      '/ai/admin/tools',
      '/ai/admin/prompts',
      '/ai/admin/memories',
      '/ai/admin/usage',
      '/ai/admin/audits',
      '/ai/admin/evaluations',
      '/profile',
    ])
  })

  it('多角色取并集', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN', 'AUDIT_ADMIN']).map((m) => m.key)
    expect(keys).toContain('/login-logs')
    expect(keys).toContain('/dashboard')
    expect(keys).toContain('/applications')
    expect(keys).toContain('/access-rules')
    expect(keys).toContain('/reports')
    expect(keys).toContain('/delivery-check')
  })

  it('系统管理员无安全态势与报表中心菜单（三权隔离）', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN']).map((m) => m.key)
    expect(keys).not.toContain('/security-overview')
    expect(keys).not.toContain('/analytics')
    expect(keys).not.toContain('/reports')
    expect(keys).not.toContain('/report-templates')
    expect(keys).not.toContain('/report-archives')
  })

  it('安全管理员无系统运维菜单（不得执行系统升级）', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN']).map((m) => m.key)
    expect(keys).not.toContain('/system-monitoring')
    expect(keys).not.toContain('/storage')
    expect(keys).not.toContain('/backup-restore')
    expect(keys).not.toContain('/system-upgrade')
    expect(keys).not.toContain('/delivery-check')
  })

  it('无角色时只显示公共菜单', () => {
    const keys = filterMenusByRoles(null).map((m) => m.key)
    expect(keys).toEqual(['/dashboard', '/profile'])
  })
})
