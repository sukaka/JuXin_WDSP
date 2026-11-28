import { describe, expect, it } from 'vitest'
import {
  API_MENU_SECTIONS,
  filterCoreMenus,
  filterMenusByLicense,
  filterMenusByRoles,
} from '../menu'

describe('filterMenusByRoles', () => {
  it('系统管理员菜单：运维 + 智能能力管理 + 账号系统设置（不含大屏与 7 大安全/业务菜单）', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/system-monitoring',
      '/node-interfaces',
      '/network-config',
      '/network-tools',
      '/xdp-acceleration',
      '/system-containers',
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

  it('系统管理员持有全部 71 项保留权限时，完整模式与核心模式均零漏出大屏与 7 大受限菜单', () => {
    const sysAdminRetainedPermissions = [
      // 基础与个人中心
      'dashboard.read_basic',
      'profile.read',
      'profile.update',
      'sessions.read_self',
      'sessions.revoke_self',
      // 用户/会话/角色只读
      'users.read',
      'users.create',
      'users.update',
      'users.disable',
      'users.unlock',
      'users.reset_password',
      'users.force_logout',
      'sessions.read',
      'sessions.revoke',
      'roles.read',
      'permissions.read',
      'login_logs.read_limited',
      // 系统设置
      'system_settings.read',
      'system_settings.update',
      'logging.syslog_test',
      // 系统运维
      'system_health.read',
      'dashboard.runtime.read',
      'network_tools.execute',
      'network_tools.download',
      'containers.read',
      'containers.logs',
      'containers.control',
      'containers.update',
      'ha.read',
      'ha.manage',
      'backups.read',
      'backups.create',
      'backups.delete',
      'backups.restore',
      'backups.verify',
      'upgrades.read',
      'upgrades.upload',
      'upgrades.apply',
      'upgrades.rollback',
      'system.reboot',
      'system.shutdown',
      'system.factory_reset',
      'request_pcap.capture_control',
      'delivery_checks.read',
      'delivery_checks.run',
      'notification.read',
      'notification.update',
      'notification.test',
      'license.read',
      'license.manage',
      // 智能能力管理
      'ai.models.read',
      'ai.models.manage',
      'ai.agents.read',
      'ai.agents.manage',
      'ai.tools.read',
      'ai.tools.manage',
      'ai.prompts.read',
      'ai.prompts.create',
      'ai.prompts.update',
      'ai.prompts.delete',
      'ai.prompts.publish',
      'ai.prompts.test',
      'ai.prompts.rollback',
      'ai.memories.read_own',
      'ai.memories.manage_own',
      'ai.usage.read',
      'ai.audits.read',
      'ai.evaluations.run',
      'ai.sessions.read_own',
      'ai.sessions.delete_own',
    ]
    const menus = filterMenusByRoles(['SYSTEM_ADMIN'], sysAdminRetainedPermissions, {
      apiDynamicProtection: true,
      webWafEnabled: true,
      apmEnabled: true,
    })
    const keys = menus.map((m) => m.key)
    const groups = new Set(menus.map((m) => m.group).filter(Boolean))

    expect(keys).not.toContain('/big-screen')
    for (const forbiddenGroup of [
      '应用防护',
      '应用防护策略',
      'API 防护',
      '安全风险',
      '数据接入',
      '安全态势',
      '安全运营',
    ]) {
      expect(groups.has(forbiddenGroup), `系统管理员不应看到分组「${forbiddenGroup}」`).toBe(false)
    }
    expect(filterCoreMenus(menus).map((m) => m.key)).toEqual([
      '/dashboard',
      '/system-monitoring',
      '/users',
      '/system-settings',
      '/license',
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

  it('运维管理员（SECURITY_ADMIN）菜单含全部业务安全防护、大屏与移交功能，不含智能能力管理', () => {
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
      '/waf/vuln-refs',
      '/exceptions',
      '/block-pages',
      '/trusted-proxies',
      '/access-rules',
      '/whitelists',
      '/l7-rules',
      '/rate-limit',
      '/temporary-blocks',
      '/access-control-events',
      '/access-control-versions',
      '/api-posture',
      '/api-endpoints',
      '/api-endpoint-groups',
      '/api-admission',
      '/api-models',
      '/api-model-maturity',
      '/api-learning',
      '/api-identity-profiles',
      '/api-access-profiles',
      '/api-parameters',
      '/api-classifications',
      '/api-sensitive-fields',
      '/api-specs',
      '/api-mcp',
      '/api-machine-identities',
      '/api-graph',
      '/api-topology',
      '/api-data-flow',
      '/api-group-control',
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
      '/api-file-assets',
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
      '/xdp-acceleration',
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
      '/whitelists',
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
    expect(keys).toContain('/whitelists')
    expect(keys).toContain('/reports')
    expect(keys).toContain('/audits')
    expect(keys).toContain('/api-endpoints')
  })

  it('系统管理员无大屏、安全态势、数据接入、安全运营与报表中心菜单', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(keys).not.toContain('/big-screen')
    expect(keys).not.toContain('/traffic-agents')
    expect(keys).not.toContain('/security-overview')
    expect(keys).not.toContain('/analytics')
    expect(keys).not.toContain('/system-alerts')
    expect(keys).not.toContain('/vuln-intel')
    expect(keys).not.toContain('/reports')
    expect(keys).not.toContain('/report-templates')
    expect(keys).not.toContain('/report-archives')
  })

  it('运维管理员持有移交权限时完整可见 7 大菜单与大屏展示', () => {
    const menus = filterMenusByRoles(
      ['SECURITY_ADMIN'],
      [
        'big_screen.runtime.read',
        'behavior_policy.read',
        'risk_policy.read',
        'security_identities.read',
        'attack_sessions.read',
        'traffic.agents.view',
        'system_alerts.read',
        'vuln_intel.read',
        'vuln_intel.manage',
      ],
      { apiDynamicProtection: true, webWafEnabled: true, apmEnabled: true },
    )
    const keys = menus.map((m) => m.key)
    const groups = new Set(menus.map((m) => m.group).filter(Boolean))
    expect(keys).toContain('/big-screen')
    expect(keys).toContain('/traffic-agents')
    expect(keys).toContain('/system-alerts')
    expect(keys).toContain('/vuln-intel')
    expect(keys).toContain('/behavior-policy')
    expect(keys).toContain('/risk-policy')
    expect(keys).toContain('/risk-identities')
    expect(keys).toContain('/attack-sessions')
    for (const requiredGroup of [
      '应用防护',
      '应用防护策略',
      'API 防护',
      '安全风险',
      '数据接入',
      '安全态势',
      '安全运营',
    ]) {
      expect(groups.has(requiredGroup), `运维管理员应可见分组「${requiredGroup}」`).toBe(true)
    }
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

  it('接口组菜单按 read 权限补显，并受 API 动态防护能力门控', () => {
    const visible = filterMenusByRoles(
      ['CUSTOM_ROLE'],
      ['api_endpoint_group.read'],
      { apiDynamicProtection: true },
    ).map((menu) => menu.key)
    expect(visible).toContain('/api-endpoint-groups')

    const manageOnly = filterMenusByRoles(
      ['CUSTOM_ROLE'],
      ['api_endpoint_group.manage'],
      { apiDynamicProtection: true },
    ).map((menu) => menu.key)
    expect(manageOnly).not.toContain('/api-endpoint-groups')

    const hidden = filterMenusByRoles(
      ['CUSTOM_ROLE'],
      ['api_endpoint_group.read'],
      { apiDynamicProtection: false },
    ).map((menu) => menu.key)
    expect(hidden).not.toContain('/api-endpoint-groups')
  })

  it('API 防护组内分类保留全部页面，仅减少直接展示的二级入口', () => {
    const apiMenus = filterMenusByRoles(['SECURITY_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).filter((menu) => menu.group === 'API 防护')
    const sectioned = apiMenus.filter((menu) => API_MENU_SECTIONS[menu.key])
    const direct = apiMenus.filter((menu) => !API_MENU_SECTIONS[menu.key])

    expect(apiMenus).toHaveLength(38)
    expect(sectioned).toHaveLength(32)
    expect(direct).toHaveLength(6)
    expect(
      new Set(sectioned.map((menu) => API_MENU_SECTIONS[menu.key])),
    ).toEqual(
      new Set([
        '资产与接入',
        '模型中心',
        '策略与授权',
        '数据安全',
        '关系与运行',
      ]),
    )
    for (const menu of sectioned) expect(menu.group).toBe('API 防护')
  })

  it('核心导航只保留安全工作流，并移除全部分组层级', () => {
    const menus = filterMenusByRoles(['SECURITY_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    const core = filterCoreMenus(menus)
    expect(core.map((menu) => menu.key)).toEqual([
      '/dashboard',
      '/applications',
      '/api-endpoints',
      '/traffic-agents',
      '/protection-policies',
      '/api-policy',
      '/api-posture',
      '/api-data-flow',
      '/security-events',
      '/license',
      '/profile',
    ])
    expect(core.every((menu) => menu.group === undefined)).toBe(true)
    expect(core.map((menu) => menu.key)).not.toContain('/api-models')
  })

  it('高级页面直达时仅补入当前页面且不重复', () => {
    const menus = filterMenusByRoles(['SECURITY_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    const core = filterCoreMenus(menus, '/api-models')
    expect(core).toHaveLength(12)
    expect(core.filter((menu) => menu.key === '/api-models')).toHaveLength(1)
    expect(core[core.length - 1]).toMatchObject({
      key: '/api-models',
      group: undefined,
    })
    expect(
      filterCoreMenus(menus, '/dashboard').filter(
        (menu) => menu.key === '/dashboard',
      ),
    ).toHaveLength(1)
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

  it('审计管理员不显示超出审计职责的五个菜单（含大屏展示）', () => {
    const keys = filterMenusByRoles(
      ['AUDIT_ADMIN'],
      [
        'audits.read',
        'login_logs.read',
        'reports.read_audit',
        'dashboard.security.read',
        'big_screen.runtime.read',
        'risk_policy.read',
        'attack_sessions.read',
        'traffic.agents.view',
        'license.read',
      ],
      { apiDynamicProtection: true, webWafEnabled: true },
    ).map((m) => m.key)

    expect(keys).not.toContain('/big-screen')
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

  it('持有 request_pcap.capture_control 权限的自定义角色可见系统控制菜单', () => {
    const keys = filterMenusByRoles(['CUSTOM_ROLE'], ['request_pcap.capture_control'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    }).map((m) => m.key)
    expect(keys).toContain('/system-control')
  })

  it('安全回归不作为常规侧边栏菜单展示（即使持有 security_regression.read 权限）', () => {
    for (const role of ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN', 'CUSTOM_ROLE']) {
      const keys = filterMenusByRoles([role], ['security_regression.read'], {
        apiDynamicProtection: true,
        webWafEnabled: true,
        apmEnabled: true,
      }).map((m) => m.key)
      expect(keys).not.toContain('/security-regressions')
    }
  })

  it('客户端供应链安全菜单按 client_side.read 权限门控并归属访问控制分组', () => {
    const visible = filterMenusByRoles(['SECURITY_ADMIN'], ['client_side.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    const entry = visible.find((m) => m.key === '/client-side-security')
    expect(entry).toMatchObject({
      key: '/client-side-security',
      label: '客户端供应链安全',
      group: '访问控制',
    })

    const auditVisible = filterMenusByRoles(['AUDIT_ADMIN'], ['client_side.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(auditVisible.map((m) => m.key)).toContain('/client-side-security')

    const hidden = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(hidden.map((m) => m.key)).not.toContain('/client-side-security')
  })

  it('Wasm 检测插件菜单按 wasm_plugins.read 权限门控并归属访问控制分组', () => {
    const visible = filterMenusByRoles(['SECURITY_ADMIN'], ['wasm_plugins.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    const entry = visible.find((m) => m.key === '/wasm-plugins')
    expect(entry).toMatchObject({
      key: '/wasm-plugins',
      label: 'Wasm 检测插件',
      group: '访问控制',
    })

    const auditVisible = filterMenusByRoles(['AUDIT_ADMIN'], ['wasm_plugins.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(auditVisible.map((m) => m.key)).toContain('/wasm-plugins')

    const hidden = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(hidden.map((m) => m.key)).not.toContain('/wasm-plugins')
  })

  it('A2A 与 AgBOM 治理菜单按 api_a2a.read 与 API 动态防护能力门控，并归属 API 防护 / 资产与接入', () => {
    const visible = filterMenusByRoles(['SECURITY_ADMIN'], ['api_a2a.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    const entry = visible.find((m) => m.key === '/api-a2a')
    expect(entry).toMatchObject({
      key: '/api-a2a',
      label: 'A2A 与 AgBOM 治理',
      group: 'API 防护',
      capability: 'api_dynamic_protection',
    })
    expect(API_MENU_SECTIONS['/api-a2a']).toBe('资产与接入')

    // 紧邻 MCP 工具目录
    const mcpIdx = visible.findIndex((m) => m.key === '/api-mcp')
    const a2aIdx = visible.findIndex((m) => m.key === '/api-a2a')
    expect(a2aIdx).toBe(mcpIdx + 1)

    // AUDIT_ADMIN 持有 api_a2a.read 时可见
    const auditVisible = filterMenusByRoles(['AUDIT_ADMIN'], ['api_a2a.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(auditVisible.map((m) => m.key)).toContain('/api-a2a')

    // 纯 WAF（apiDynamicProtection=false）即使持有 api_a2a.read 也隐藏
    const wafOnly = filterMenusByRoles(['SECURITY_ADMIN'], ['api_a2a.read'], {
      apiDynamicProtection: false,
      webWafEnabled: true,
    })
    expect(wafOnly.map((m) => m.key)).not.toContain('/api-a2a')

    // 无权限时隐藏
    const noPerm = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(noPerm.map((m) => m.key)).not.toContain('/api-a2a')
  })

  it('内核 XDP 加速菜单归属系统运维，面向系统/运维管理员及持有 xdp_accel.read 的角色可见', () => {
    for (const role of ['SYSTEM_ADMIN', 'SECURITY_ADMIN']) {
      const visible = filterMenusByRoles([role], [], {
        apiDynamicProtection: true,
        webWafEnabled: true,
      })
      const entry = visible.find((m) => m.key === '/xdp-acceleration')
      expect(entry).toMatchObject({
        key: '/xdp-acceleration',
        label: '内核 XDP 加速',
        group: '系统运维',
      })
    }

    // 紧邻网络工具
    const sysMenus = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    const netToolsIdx = sysMenus.findIndex((m) => m.key === '/network-tools')
    const xdpIdx = sysMenus.findIndex((m) => m.key === '/xdp-acceleration')
    expect(xdpIdx).toBe(netToolsIdx + 1)

    // 审计管理员持有 xdp_accel.read 时按权限点补显，未持有时隐藏
    const auditVisible = filterMenusByRoles(['AUDIT_ADMIN'], ['xdp_accel.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(auditVisible.map((m) => m.key)).toContain('/xdp-acceleration')

    const auditHidden = filterMenusByRoles(['AUDIT_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(auditHidden.map((m) => m.key)).not.toContain('/xdp-acceleration')
  })

  it('自定义拦截页面菜单按 SECURITY_ADMIN 或 block_pages.read 权限门控并归属应用防护策略分组', () => {
    const visible = filterMenusByRoles(['SECURITY_ADMIN'], ['block_pages.read'], {
      apiDynamicProtection: false,
      webWafEnabled: true,
    })
    const entry = visible.find((m) => m.key === '/block-pages')
    expect(entry).toMatchObject({
      key: '/block-pages',
      label: '拦截页面',
      group: '应用防护策略',
    })

    // 审计管理员持有 block_pages.read 时可见
    const auditVisible = filterMenusByRoles(['AUDIT_ADMIN'], ['block_pages.read'], {
      apiDynamicProtection: false,
      webWafEnabled: false,
    })
    expect(auditVisible.map((m) => m.key)).toContain('/block-pages')

    // 系统管理员无 block_pages.read 时不可见（遵循三权边界）
    const sysHidden = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(sysHidden.map((m) => m.key)).not.toContain('/block-pages')
  })

  it('IP 库与威胁情报菜单按 geoip.read 或 threat_intel.read 权限门控并归属访问控制分组', () => {
    const geoVisible = filterMenusByRoles(['SECURITY_ADMIN'], ['geoip.read'], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(geoVisible.find((m) => m.key === '/ip-libraries')).toMatchObject({
      key: '/ip-libraries',
      label: 'IP 库与威胁情报',
      group: '访问控制',
    })

    const threatVisible = filterMenusByRoles(['AUDIT_ADMIN'], ['threat_intel.read'], {
      apiDynamicProtection: false,
      webWafEnabled: false,
    })
    expect(threatVisible.map((m) => m.key)).toContain('/ip-libraries')

    const sysHidden = filterMenusByRoles(['SYSTEM_ADMIN'], [], {
      apiDynamicProtection: true,
      webWafEnabled: true,
    })
    expect(sysHidden.map((m) => m.key)).not.toContain('/ip-libraries')
  })
})
