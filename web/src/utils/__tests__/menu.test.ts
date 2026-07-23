import { describe, expect, it } from 'vitest'
import { filterMenusByRoles } from '../menu'

describe('filterMenusByRoles', () => {
  it('系统管理员菜单含运维与 API 端点只读入口', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN'], { apiDynamicProtection: true }).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/config-versions',
      '/gateway-status',
      '/trusted-proxies',
      '/api-endpoints',
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

  it('审计管理员菜单含 API 资产只读', () => {
    const keys = filterMenusByRoles(['AUDIT_ADMIN'], { apiDynamicProtection: true }).map((m) => m.key)
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
      '/api-endpoints',
      '/api-models',
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

  it('安全管理员菜单含 API 防护分组', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN'], { apiDynamicProtection: true }).map((m) => m.key)
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
      '/api-endpoints',
      '/api-models',
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
    const keys = filterMenusByRoles(
      ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
      { apiDynamicProtection: true },
    ).map((m) => m.key)
    expect(keys).toContain('/login-logs')
    expect(keys).toContain('/dashboard')
    expect(keys).toContain('/applications')
    expect(keys).toContain('/access-rules')
    expect(keys).toContain('/reports')
    expect(keys).toContain('/delivery-check')
    expect(keys).toContain('/api-endpoints')
  })

  it('系统管理员无安全态势与报表中心菜单（三权隔离）', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN'], { apiDynamicProtection: true }).map((m) => m.key)
    expect(keys).not.toContain('/security-overview')
    expect(keys).not.toContain('/analytics')
    expect(keys).not.toContain('/reports')
    expect(keys).not.toContain('/report-templates')
    expect(keys).not.toContain('/report-archives')
  })

  it('WAF 产品对所有管理员隐藏接口防护菜单', () => {
    for (const role of ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN']) {
      const menus = filterMenusByRoles([role], { apiDynamicProtection: false })
      expect(menus.map((m) => m.key)).not.toContain('/api-endpoints')
      expect(menus.map((m) => m.key)).not.toContain('/api-models')
      expect(menus.map((m) => m.group)).not.toContain('接口防护')
    }
  })
})
