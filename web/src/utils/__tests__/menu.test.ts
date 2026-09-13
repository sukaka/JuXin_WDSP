import { describe, expect, it } from 'vitest'
import { filterMenusByLicense, filterMenusByRoles } from '../menu'

describe('filterMenusByRoles', () => {
  it('系统管理员菜单：运维 + 智能能力管理 + 系统告警（不含六组安全功能）', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/big-screen',
      '/traffic-agents',
      '/system-alerts',
      '/system-monitoring',
      '/node-interfaces',
      '/network-config',
      '/network-tools',
      '/ha-groups',
      '/storage',
      '/backup-restore',
      '/system-upgrade',
      '/system-control',
      '/delivery-check',
      '/alert-notifications',
      '/license',
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

  it('审计管理员菜单：仅操作审计、登录日志与全角色公共入口', () => {
    const keys = filterMenusByRoles(['AUDIT_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
      apmEnabled: true,
    }).map((m) => m.key)
    expect(keys).toEqual(['/dashboard', '/login-logs', '/audits', '/profile'])
  })

  it('安全管理员菜单含六组安全功能，不含智能能力管理', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
      apmEnabled: true,
    }).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/big-screen',
      '/applications',
      '/site-discovery',
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
      '/l7-rules',
      '/rate-limit',
      '/temporary-blocks',
      '/access-control-events',
      '/access-control-versions',
      '/api-posture',
      '/api-endpoints',
      '/api-models',
      '/api-model-maturity',
      '/api-learning',
      '/api-identity-profiles',
      '/api-access-profiles',
      '/api-parameters',
      '/api-classifications',
      '/api-sensitive-fields',
      '/api-specs',
      '/api-graph',
      '/api-topology',
      '/api-findings',
      '/api-shadow-zombie',
      '/api-policy',
      '/api-weaknesses',
      '/api-sensitive-types',
      '/api-masking-rules',
      '/api-violations',
      '/api-runtime-events',
      '/api-runtime-policies',
      '/api-authz',
      '/api-flow-baselines',
      '/api-scan',
      '/api-ai-ops',
      '/api-llm',
      '/api-cross-border',
      '/api-service-assets',
      '/api-nodes',
      '/api-file-compliance',
      '/security-events',
      '/access-logs',
      '/event-statistics',
      '/site-access-trends',
      '/apm-overview',
      '/apm-services',
      '/apm-endpoints',
      '/apm-traces',
      '/apm-agents',
      '/apm-sql',
      '/apm-exceptions',
      '/apm-runtime',
      '/apm-dependencies',
      '/apm-slos',
      '/apm-diagnostics',
      '/traffic-agents',
      '/security-overview',
      '/analytics',
      '/system-alerts',
      '/reports',
      '/report-templates',
      '/report-archives',
      '/ha-groups',
      '/license',
      '/ai/assistant',
      '/ai/event-analysis',
      '/ai/attack-profile',
      '/ai/attack-chain',
      '/ai/policy-recommendation',
      '/ai/report-summary',
      '/ai/tasks',
      '/ai/noise-reduction',
      '/profile',
    ])
  })

  it('六组安全功能仅安全管理员可见（系统管理员、审计管理员均不可见）', () => {
    const sixGroups = [
      '/applications',
      '/config-versions',
      '/gateway-status',
      '/protection-policies',
      '/trusted-proxies',
      '/access-rules',
      '/l7-rules',
      '/rate-limit',
      '/api-endpoints',
      '/api-policy',
      '/security-events',
      '/access-logs',
      '/event-statistics',
      '/security-overview',
      '/analytics',
      '/ai/assistant',
      '/ai/noise-reduction',
    ]
    const caps = { apiDynamicProtection: true, webWafEnabled: true }
    const secKeys = filterMenusByRoles(['SECURITY_ADMIN'], [], caps).map(
      (m) => m.key,
    )
    for (const key of sixGroups) expect(secKeys).toContain(key)
    for (const role of ['SYSTEM_ADMIN', 'AUDIT_ADMIN']) {
      const keys = filterMenusByRoles([role], [], caps).map((m) => m.key)
      for (const key of sixGroups) expect(keys).not.toContain(key)
    }
  })

  it('智能能力管理仅系统管理员可见', () => {
    const adminKeys = [
      '/ai/admin/models',
      '/ai/admin/agents',
      '/ai/admin/tools',
      '/ai/admin/prompts',
      '/ai/admin/memories',
      '/ai/admin/usage',
      '/ai/admin/audits',
      '/ai/admin/evaluations',
    ]
    const sysKeys = filterMenusByRoles(['SYSTEM_ADMIN'], [], {}).map(
      (m) => m.key,
    )
    for (const key of adminKeys) expect(sysKeys).toContain(key)
    for (const role of ['SECURITY_ADMIN', 'AUDIT_ADMIN']) {
      const keys = filterMenusByRoles([role], [], {}).map((m) => m.key)
      for (const key of adminKeys) expect(keys).not.toContain(key)
    }
  })

  it('多角色取并集', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN', 'AUDIT_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(keys).toContain('/login-logs')
    expect(keys).toContain('/dashboard')
    expect(keys).toContain('/applications')
    expect(keys).toContain('/access-rules')
    expect(keys).toContain('/reports')
    expect(keys).toContain('/audits')
    expect(keys).toContain('/api-endpoints')
  })

  it('系统管理员无安全态势与报表中心菜单（系统告警除外）', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(keys).not.toContain('/security-overview')
    expect(keys).not.toContain('/analytics')
    expect(keys).not.toContain('/reports')
    expect(keys).not.toContain('/report-templates')
    expect(keys).not.toContain('/report-archives')
    // 系统告警对系统管理员保留（运维告警职责）
    expect(keys).toContain('/system-alerts')
  })

  it('权限点命中即显示（角色码不匹配时按权限点补显，与路由 RequirePermission 口径一致）', () => {
    // 自定义角色持有 ha.read：/ha-groups 可见（路由守卫为 ha.read）
    const auditKeys = filterMenusByRoles(['AUDIT_ADMIN'], ['ha.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(auditKeys).toContain('/ha-groups')

    // SECURITY_ADMIN 持有 notification.read：/alert-notifications 可见（路由守卫为 notification.read）
    const securityKeys = filterMenusByRoles(
      ['SECURITY_ADMIN'],
      ['notification.read'],
      {
        apiDynamicProtection: true,
        webWafEnabled: true,
      },
    ).map((m) => m.key)
    expect(securityKeys).toContain('/alert-notifications')

    // 自定义角色持有 l7rules.read：/l7-rules 可见（路由守卫为 l7rules.read）
    const customKeys = filterMenusByRoles(['CUSTOM_ROLE'], ['l7rules.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(customKeys).toContain('/l7-rules')
  })

  it('无角色码时权限点单独命中也可显示', () => {
    const keys = filterMenusByRoles([], ['ha.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(keys).toContain('/ha-groups')
    // 角色码与权限点均未命中的菜单不显示
    expect(keys).not.toContain('/users')
    expect(keys).not.toContain('/applications')
  })

  it('权限点补显仍受产品能力门控', () => {
    // api 产品形态（webWafEnabled=false）：即使持有 l7rules.read 也不显示 WAF 域菜单
    const keys = filterMenusByRoles(['SYSTEM_ADMIN'], ['l7rules.read'], {
      apiDynamicProtection: true,
      webWafEnabled: false,
    }).map((m) => m.key)
    expect(keys).not.toContain('/l7-rules')
  })

  it('WAF 产品对所有管理员隐藏 API 防护菜单', () => {
    for (const role of ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN']) {
      const menus = filterMenusByRoles([role], [], {
        apiDynamicProtection: false,
      })
      expect(menus.map((m) => m.key)).not.toContain('/api-endpoints')
      expect(menus.map((m) => m.key)).not.toContain('/api-models')
      expect(menus.map((m) => m.group)).not.toContain('API 防护')
    }
  })

  it('APM 能力门控：关闭时隐藏业务性能菜单；开启时仅安全管理员可见', () => {
    // 能力关闭或缺省（未初始化）：任何角色都不显示
    for (const role of ['SECURITY_ADMIN', 'SYSTEM_ADMIN']) {
      const keys = filterMenusByRoles([role], [], { apmEnabled: false }).map(
        (m) => m.key,
      )
      expect(keys).not.toContain('/apm-overview')
      expect(keys).not.toContain('/apm-services')
      expect(keys).not.toContain('/apm-endpoints')
      expect(keys).not.toContain('/apm-traces')
      expect(keys).not.toContain('/apm-agents')
      expect(keys).not.toContain('/apm-sql')
      expect(keys).not.toContain('/apm-exceptions')
      expect(keys).not.toContain('/apm-runtime')
      expect(keys).not.toContain('/apm-dependencies')
      expect(keys).not.toContain('/apm-slos')
      expect(keys).not.toContain('/apm-diagnostics')
      const keysDefault = filterMenusByRoles([role], []).map((m) => m.key)
      expect(keysDefault).not.toContain('/apm-overview')
    }
    // 开启：仅 SECURITY_ADMIN 可见（三权口径：SYSTEM_ADMIN/AUDIT_ADMIN 不含业务观测权限）
    const secKeys = filterMenusByRoles(['SECURITY_ADMIN'], [], {
      apmEnabled: true,
    }).map((m) => m.key)
    for (const key of [
      '/apm-overview',
      '/apm-services',
      '/apm-endpoints',
      '/apm-traces',
      '/apm-agents',
      '/apm-sql',
      '/apm-exceptions',
      '/apm-runtime',
      '/apm-dependencies',
      '/apm-slos',
      '/apm-diagnostics',
    ]) {
      expect(secKeys).toContain(key)
    }
    for (const role of ['SYSTEM_ADMIN', 'AUDIT_ADMIN']) {
      const keys = filterMenusByRoles([role], [], { apmEnabled: true }).map(
        (m) => m.key,
      )
      expect(keys).not.toContain('/apm-overview')
      expect(keys).not.toContain('/apm-traces')
      expect(keys).not.toContain('/apm-agents')
      expect(keys).not.toContain('/apm-sql')
      expect(keys).not.toContain('/apm-slos')
      expect(keys).not.toContain('/apm-diagnostics')
    }
    // 自定义角色无角色码命中时按权限点补显（与路由 RequirePermission 口径一致）
    const permKeys = filterMenusByRoles(
      [],
      ['apm.traces.read', 'apm.agents.manage'],
      {
        apmEnabled: true,
      },
    ).map((m) => m.key)
    expect(permKeys).toContain('/apm-traces')
    expect(permKeys).toContain('/apm-agents')
    // 阶段3 菜单同样按各自权限点补显（apm.traces.read 同时覆盖调用链与异常分析）
    expect(permKeys).toContain('/apm-exceptions')
    expect(permKeys).not.toContain('/apm-overview')
    expect(permKeys).not.toContain('/apm-sql')
    const stage3Keys = filterMenusByRoles(
      [],
      ['apm.sql.read', 'apm.runtime.read', 'apm.overview.read'],
      {
        apmEnabled: true,
      },
    ).map((m) => m.key)
    expect(stage3Keys).toContain('/apm-sql')
    expect(stage3Keys).toContain('/apm-runtime')
    expect(stage3Keys).toContain('/apm-slos')
    expect(stage3Keys).not.toContain('/apm-diagnostics')
    // /apm-overview 仅按角色码放行（无权限点补显），自定义角色不显示
    expect(stage3Keys).not.toContain('/apm-overview')
    // 阶段4 诊断中心按 apm.diagnostics.manage 权限点补显
    const diagKeys = filterMenusByRoles([], ['apm.diagnostics.manage'], {
      apmEnabled: true,
    }).map((m) => m.key)
    expect(diagKeys).toContain('/apm-diagnostics')
    expect(diagKeys).not.toContain('/apm-slos')
  })

  it('审计管理员不显示超出审计职责的四个菜单', () => {
    const keys = filterMenusByRoles(
      ['AUDIT_ADMIN'],
      [
        'audits.read',
        'login_logs.read',
        'reports.read_audit',
        'dashboard.security.read',
        'risk_policy.read',
        'attack_sessions.read',
        'traffic.agents.view',
        'license.read',
      ],
      { apiDynamicProtection: true, webWafEnabled: true },
    ).map((m) => m.key)

    expect(keys).not.toContain('/risk-policy')
    expect(keys).not.toContain('/attack-sessions')
    expect(keys).not.toContain('/traffic-agents')
    expect(keys).not.toContain('/license')
  })

  it('授权管理菜单仅对内置运维角色或持有 license.read 权限的用户可见', () => {
    const allowed = filterMenusByRoles(['SYSTEM_ADMIN'], ['license.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    const denied = filterMenusByRoles(['AUDIT_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)

    expect(allowed).toContain('/license')
    expect(denied).not.toContain('/license')
  })

  it('授权锁定态过滤：仅保留授权管理入口，有效时不过滤', () => {
    const menus = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(filterMenusByLicense(menus, false).map((m) => m.key)).toEqual([
      '/license',
    ])
    expect(filterMenusByLicense(menus, true)).toBe(menus)

    const auditMenus = filterMenusByRoles(['AUDIT_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(filterMenusByLicense(auditMenus, false).map((m) => m.key)).toEqual([
      '/license',
    ])
  })
})
