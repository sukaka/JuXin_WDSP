export interface MenuDef {
  key: string
  label: string
  /** 允许看到该菜单的角色编码；与 permissions 为「或」关系；两者都缺省表示所有登录用户可见 */
  roles?: string[]
  /** 允许看到该菜单的权限点（任一命中即显示，与路由 RequirePermission 口径一致） */
  permissions?: string[]
  /** 纯审计管理员禁止访问，用于防御历史会话中残留的误授权限。 */
  denyAuditOnly?: boolean
  /** 依赖的产品能力；缺省表示所有产品形态可见 */
  capability?: 'api_dynamic_protection' | 'web_waf' | 'apm'
  /** 侧边栏分组名；缺省为顶层菜单 */
  group?: string
}

export interface ProductCapabilities {
  apiDynamicProtection: boolean
  /** Web 防护专属（策略/CC/访问控制）；API 包为 false */
  webWafEnabled: boolean
  /** APM 业务性能（无 Agent）；默认 false fail-safe */
  apmEnabled: boolean
}

export const MENU_ITEMS: MenuDef[] = [
  { key: '/dashboard', label: '工作台' },
  {
    key: '/big-screen',
    label: '大屏展示',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'],
  },
  {
    key: '/applications',
    label: '网站应用',
    roles: ['SECURITY_ADMIN'],
    group: '应用防护',
  },
  {
    key: '/site-discovery',
    label: '站点发现',
    roles: ['SECURITY_ADMIN'],
    group: '应用防护',
  },
  {
    key: '/certificates',
    label: 'HTTPS 证书',
    roles: ['SECURITY_ADMIN'],
    group: '应用防护',
  },
  {
    key: '/config-publish',
    label: '配置发布',
    roles: ['SECURITY_ADMIN'],
    group: '应用防护',
  },
  {
    key: '/config-versions',
    label: '配置版本',
    roles: ['SECURITY_ADMIN'],
    group: '应用防护',
  },
  // P1-04 R4a：安全回归证据与发布门禁（read 含 AUDIT_ADMIN，按权限点显隐）
  {
    key: '/security-regressions',
    label: '安全回归',
    permissions: ['security_regression.read'],
    group: '应用防护',
  },
  {
    key: '/gateway-status',
    label: '网关状态',
    roles: ['SECURITY_ADMIN'],
    group: '应用防护',
  },
  {
    key: '/protection-policies',
    label: '防护策略',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '应用防护策略',
  },
  {
    key: '/waf-rules',
    label: '防护规则库',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '应用防护策略',
  },
  {
    key: '/custom-rules',
    label: '自定义规则',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '应用防护策略',
  },
  // CNNVD 兼容性 P1：漏洞档案（角色码之外按权限点补显，路由按 waf_rules.read 放行）
  {
    key: '/waf/vuln-refs',
    label: '漏洞档案',
    roles: ['SECURITY_ADMIN'],
    permissions: ['waf_rules.read'],
    capability: 'web_waf',
    group: '应用防护策略',
  },
  {
    key: '/exceptions',
    label: '例外策略',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '应用防护策略',
  },
  // AI 自动化渗透防护 阶段1：行为检测策略（全局单例）
  {
    key: '/behavior-policy',
    label: '行为策略',
    permissions: ['behavior_policy.read'],
    group: '应用防护策略',
  },
  // AI 自动化渗透防护 阶段3：风险策略（全局单例）
  {
    key: '/risk-policy',
    label: '风险策略',
    permissions: ['risk_policy.read'],
    denyAuditOnly: true,
    group: '应用防护策略',
  },
  {
    key: '/trusted-proxies',
    label: '可信代理',
    roles: ['SECURITY_ADMIN'],
    group: '访问控制',
  },
  {
    key: '/access-rules',
    label: 'IP 黑名单',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '访问控制',
  },
  {
    key: '/whitelists',
    label: '白名单管理',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '访问控制',
  },
  {
    key: '/l7-rules',
    label: 'L7 访问控制',
    roles: ['SECURITY_ADMIN'],
    // 自定义角色持有 l7rules.read（路由按权限点放行），角色码之外按权限点补显
    permissions: ['l7rules.read'],
    capability: 'web_waf',
    group: '访问控制',
  },
  {
    key: '/rate-limit',
    label: '频率与 CC 防护',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '访问控制',
  },
  {
    key: '/temporary-blocks',
    label: '临时封禁',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '访问控制',
  },
  {
    key: '/access-control-events',
    label: '访问控制事件',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '访问控制',
  },
  {
    key: '/access-control-versions',
    label: '访问控制版本',
    roles: ['SECURITY_ADMIN'],
    capability: 'web_waf',
    group: '访问控制',
  },
  // 阶段8 / WDSP：API 动态防护
  {
    key: '/api-posture',
    label: 'API 态势',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-endpoints',
    label: 'API 接口资产',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-endpoint-groups',
    label: '业务功能分组',
    roles: ['SECURITY_ADMIN'],
    permissions: ['api_endpoint_group.read'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  // API 准入防护（docs/API_ADMISSION_CONTROL_DESIGN.md §6，读取权限 api_asset.read）
  {
    key: '/api-admission',
    label: 'API 准入防护',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-models',
    label: 'API 模型版本',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-model-maturity',
    label: '模型成熟度',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-learning',
    label: '学习中心',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-identity-profiles',
    label: '身份模型',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-access-profiles',
    label: '访问模型',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-parameters',
    label: '参数模型',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-classifications',
    label: '用途分类',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-sensitive-fields',
    label: '敏感数据',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-specs',
    label: '规范对比',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-mcp',
    label: 'MCP 工具目录',
    roles: ['SECURITY_ADMIN'],
    permissions: ['api_spec.read'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-machine-identities',
    label: '机器身份',
    roles: ['SECURITY_ADMIN'],
    permissions: ['jwt_trust.read'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-graph',
    label: '安全图谱',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-topology',
    label: '调用拓扑',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-data-flow',
    label: '数据流向',
    roles: ['SECURITY_ADMIN'],
    permissions: ['api_data_flow.read'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-group-control',
    label: '群控分析',
    roles: ['SECURITY_ADMIN'],
    permissions: ['api_runtime.read'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-findings',
    label: 'API 风险',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-shadow-zombie',
    label: '影子与僵尸 API',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-policy',
    label: 'API 策略',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-weaknesses',
    label: '弱点中心',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-sensitive-types',
    label: '敏感数据类型',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-masking-rules',
    label: '脱敏规则',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-violations',
    label: 'Schema 违例',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-runtime-events',
    label: '运行时事件',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-runtime-policies',
    label: '运行时策略',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-authz',
    label: '授权基线',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-flow-baselines',
    label: '流程基线',
    roles: ['SECURITY_ADMIN'],
    permissions: ['api_flow.read'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-scan',
    label: '主动扫描',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-ai-ops',
    label: 'AI 运营',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-llm',
    label: 'AI 大模型安全',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-cross-border',
    label: '数据出境',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-service-assets',
    label: '服务资产',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-nodes',
    label: '节点校验',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-file-compliance',
    label: '文件合规',
    roles: ['SECURITY_ADMIN'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/api-file-assets',
    label: '文件资产',
    roles: ['SECURITY_ADMIN'],
    permissions: ['api_data.read'],
    capability: 'api_dynamic_protection',
    group: 'API 防护',
  },
  {
    key: '/security-events',
    label: '安全事件',
    roles: ['SECURITY_ADMIN'],
    group: '事件中心',
  },
  {
    key: '/access-logs',
    label: '访问日志',
    roles: ['SECURITY_ADMIN'],
    group: '事件中心',
  },
  {
    key: '/event-statistics',
    label: '事件统计',
    roles: ['SECURITY_ADMIN'],
    group: '事件中心',
  },
  {
    key: '/site-access-trends',
    label: '网站访问趋势',
    roles: ['SECURITY_ADMIN'],
    group: '事件中心',
  },
  // AI 自动化渗透防护 阶段1：风险身份（新分组，位于事件中心之后）
  {
    key: '/risk-identities',
    label: '风险身份',
    permissions: ['security_identities.read'],
    group: '安全风险',
  },
  // AI 自动化渗透防护 阶段4：攻击活动（Attack Session，设计文档 #17/#26）
  {
    key: '/attack-sessions',
    label: '攻击活动',
    permissions: ['attack_sessions.read'],
    denyAuditOnly: true,
    group: '安全风险',
  },
  // APM 阶段1（无 Agent 模式）：共享底座能力，受 apm_enabled 开关门控
  {
    key: '/apm-overview',
    label: '性能总览',
    roles: ['SECURITY_ADMIN'],
    capability: 'apm',
    group: '业务性能',
  },
  {
    key: '/apm-services',
    label: '服务性能',
    roles: ['SECURITY_ADMIN'],
    capability: 'apm',
    group: '业务性能',
  },
  {
    key: '/apm-endpoints',
    label: '端点性能',
    roles: ['SECURITY_ADMIN'],
    capability: 'apm',
    group: '业务性能',
  },
  {
    key: '/apm-traces',
    label: '调用链检索',
    roles: ['SECURITY_ADMIN'],
    // 自定义角色持有 apm.traces.read（路由按权限点放行），角色码之外按权限点补显
    permissions: ['apm.traces.read'],
    capability: 'apm',
    group: '业务性能',
  },
  {
    key: '/apm-agents',
    label: 'Agent 管理',
    roles: ['SECURITY_ADMIN'],
    // 自定义角色持有 apm.agents.manage（路由按权限点放行），角色码之外按权限点补显
    permissions: ['apm.agents.manage'],
    capability: 'apm',
    group: '业务性能',
  },
  // APM 阶段3：SQL / 异常 / 运行时 / 依赖 / SLO
  {
    key: '/apm-sql',
    label: 'SQL 诊断',
    roles: ['SECURITY_ADMIN'],
    // 自定义角色持有 apm.sql.read（路由按权限点放行），角色码之外按权限点补显
    permissions: ['apm.sql.read'],
    capability: 'apm',
    group: '业务性能',
  },
  {
    key: '/apm-exceptions',
    label: '异常分析',
    roles: ['SECURITY_ADMIN'],
    permissions: ['apm.traces.read'],
    capability: 'apm',
    group: '业务性能',
  },
  {
    key: '/apm-runtime',
    label: '运行时指标',
    roles: ['SECURITY_ADMIN'],
    permissions: ['apm.runtime.read'],
    capability: 'apm',
    group: '业务性能',
  },
  {
    key: '/apm-dependencies',
    label: '依赖分析',
    roles: ['SECURITY_ADMIN'],
    permissions: ['apm.services.read'],
    capability: 'apm',
    group: '业务性能',
  },
  {
    key: '/apm-slos',
    label: 'SLO 管理',
    roles: ['SECURITY_ADMIN'],
    permissions: ['apm.overview.read'],
    capability: 'apm',
    group: '业务性能',
  },
  // APM 阶段4：诊断中心（深度诊断会话创建/停止 + 全局 kill switch，写操作权限点）
  {
    key: '/apm-diagnostics',
    label: '诊断中心',
    roles: ['SECURITY_ADMIN'],
    permissions: ['apm.diagnostics.manage'],
    capability: 'apm',
    group: '业务性能',
  },
  // WDSP 流量采集 Agent（阶段8，契约 docs/agents/WDSP_AGENT_PHASE1_CONTRACT.md §4/§7）：
  // view 授 SYSTEM_ADMIN/SECURITY_ADMIN；自定义角色持有 traffic.agents.view 按权限点补显
  {
    key: '/traffic-agents',
    label: 'Agent 管理',
    roles: ['SYSTEM_ADMIN', 'SECURITY_ADMIN'],
    permissions: ['traffic.agents.view'],
    denyAuditOnly: true,
    group: '数据接入',
  },
  {
    key: '/security-overview',
    label: '安全总览',
    roles: ['SECURITY_ADMIN'],
    group: '安全态势',
  },
  {
    key: '/analytics',
    label: '统计分析',
    roles: ['SECURITY_ADMIN'],
    group: '安全态势',
  },
  // 系统告警：安全管理员（安全告警）与系统管理员（系统运维告警）双角色可见
  {
    key: '/system-alerts',
    label: '系统告警',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'],
    group: '安全态势',
  },
  // 漏洞情报提醒（PHP 场景闭环）：读 vuln_intel.read，写 vuln_intel.manage（仅 SYSTEM_ADMIN）页面内控
  {
    key: '/vuln-intel',
    label: '漏洞情报',
    permissions: ['vuln_intel.read'],
    group: '安全运营',
  },
  {
    key: '/reports',
    label: '报告任务',
    roles: ['SECURITY_ADMIN'],
    group: '报表中心',
  },
  {
    key: '/report-templates',
    label: '报告模板',
    roles: ['SECURITY_ADMIN'],
    group: '报表中心',
  },
  {
    key: '/report-archives',
    label: '报告归档',
    roles: ['SECURITY_ADMIN'],
    group: '报表中心',
  },
  {
    key: '/system-monitoring',
    label: '运行监控',
    roles: ['SYSTEM_ADMIN'],
    group: '系统运维',
  },
  {
    key: '/node-interfaces',
    label: '网口管理',
    roles: ['SYSTEM_ADMIN'],
    group: '系统运维',
  },
  {
    key: '/network-config',
    label: '网络配置',
    roles: ['SYSTEM_ADMIN'],
    group: '系统运维',
  },
  {
    key: '/network-tools',
    label: '网络工具',
    roles: ['SYSTEM_ADMIN'],
    group: '系统运维',
  },
  {
    key: '/system-containers',
    label: '容器运维',
    roles: ['SYSTEM_ADMIN'],
    permissions: ['containers.read'],
    group: '系统运维',
  },
  {
    key: '/ha-groups',
    label: 'HA 主备',
    roles: ['SYSTEM_ADMIN', 'SECURITY_ADMIN'],
    // 自定义角色持有 ha.read（路由按权限点放行），角色码之外按权限点补显
    permissions: ['ha.read'],
    group: '系统运维',
  },
  {
    key: '/storage',
    label: '存储容量',
    roles: ['SYSTEM_ADMIN'],
    group: '系统运维',
  },
  {
    key: '/backup-restore',
    label: '备份恢复',
    roles: ['SYSTEM_ADMIN'],
    group: '系统运维',
  },
  {
    key: '/system-upgrade',
    label: '系统升级',
    roles: ['SYSTEM_ADMIN'],
    group: '系统运维',
  },
  {
    key: '/system-control',
    label: '系统控制',
    roles: ['SYSTEM_ADMIN'],
    permissions: [
      'system.reboot',
      'system.shutdown',
      'system.factory_reset',
      'request_pcap.capture_control',
    ],
    group: '系统运维',
  },
  {
    key: '/delivery-check',
    label: '交付检查',
    roles: ['SYSTEM_ADMIN'],
    group: '系统运维',
  },
  {
    key: '/alert-notifications',
    label: '告警通知',
    roles: ['SYSTEM_ADMIN'],
    // SECURITY_ADMIN 持有 notification.read（路由按权限点放行），角色码之外按权限点补显
    permissions: ['notification.read'],
    group: '系统运维',
  },
  // 授权有效时按 license.read 控制；授权锁定态由 filterMenusByLicense 保留恢复入口。
  {
    key: '/license',
    label: '授权管理',
    roles: ['SYSTEM_ADMIN', 'SECURITY_ADMIN'],
    permissions: ['license.read'],
    denyAuditOnly: true,
    group: '系统运维',
  },
  // 阶段7：智能安全运营（仅安全管理员）
  {
    key: '/ai/assistant',
    label: '安全助手',
    roles: ['SECURITY_ADMIN'],
    group: '智能安全运营',
  },
  {
    key: '/ai/event-analysis',
    label: '事件智能分析',
    roles: ['SECURITY_ADMIN'],
    group: '智能安全运营',
  },
  {
    key: '/ai/attack-profile',
    label: '攻击画像分析',
    roles: ['SECURITY_ADMIN'],
    group: '智能安全运营',
  },
  {
    key: '/ai/attack-chain',
    label: '攻击链分析',
    roles: ['SECURITY_ADMIN'],
    group: '智能安全运营',
  },
  {
    key: '/ai/policy-recommendation',
    label: '策略智能建议',
    roles: ['SECURITY_ADMIN'],
    group: '智能安全运营',
  },
  {
    key: '/ai/report-summary',
    label: '报告智能总结',
    roles: ['SECURITY_ADMIN'],
    group: '智能安全运营',
  },
  {
    key: '/ai/tasks',
    label: '智能任务记录',
    roles: ['SECURITY_ADMIN'],
    group: '智能安全运营',
  },
  {
    key: '/ai/noise-reduction',
    label: '自动降噪',
    roles: ['SECURITY_ADMIN'],
    group: '智能安全运营',
  },
  // 阶段7：智能能力管理（仅系统管理员）
  {
    key: '/ai/admin/models',
    label: '模型管理',
    roles: ['SYSTEM_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/agents',
    label: '智能体管理',
    roles: ['SYSTEM_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/tools',
    label: '工具管理',
    roles: ['SYSTEM_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/prompts',
    label: '提示词管理',
    roles: ['SYSTEM_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/memories',
    label: '记忆管理',
    roles: ['SYSTEM_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/usage',
    label: '配额与成本',
    roles: ['SYSTEM_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/audits',
    label: '智能审计',
    roles: ['SYSTEM_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/evaluations',
    label: '质量评估',
    roles: ['SYSTEM_ADMIN'],
    group: '智能能力管理',
  },
  { key: '/users', label: '用户管理', roles: ['SYSTEM_ADMIN'] },
  { key: '/roles', label: '角色权限', roles: ['SYSTEM_ADMIN'] },
  { key: '/login-logs', label: '登录日志', roles: ['AUDIT_ADMIN'] },
  { key: '/audits', label: '操作审计', roles: ['AUDIT_ADMIN'] },
  { key: '/system-settings', label: '系统设置', roles: ['SYSTEM_ADMIN'] },
  { key: '/profile', label: '个人中心' },
]

export const CORE_MENU_KEYS = [
  '/dashboard',
  '/applications',
  '/api-endpoints',
  '/traffic-agents',
  '/protection-policies',
  '/api-policy',
  '/api-posture',
  '/api-data-flow',
  '/security-events',
  '/system-monitoring',
  '/users',
  '/system-settings',
  '/audits',
  '/login-logs',
  '/license',
  '/profile',
] as const

export function filterCoreMenus(
  menus: MenuDef[],
  currentKey?: string,
): MenuDef[] {
  const core = CORE_MENU_KEYS.flatMap((key) => {
    const menu = menus.find((item) => item.key === key)
    return menu ? [{ ...menu, group: undefined }] : []
  })
  const current = menus.find((menu) => menu.key === currentKey)
  if (current && !core.some((menu) => menu.key === current.key)) {
    core.push({ ...current, group: undefined })
  }
  return core
}

export const API_MENU_SECTIONS: Record<string, string> = {
  '/api-endpoints': '资产与接入',
  '/api-endpoint-groups': '资产与接入',
  '/api-specs': '资产与接入',
  '/api-mcp': '资产与接入',
  '/api-service-assets': '资产与接入',
  '/api-nodes': '资产与接入',
  '/api-models': '模型中心',
  '/api-model-maturity': '模型中心',
  '/api-learning': '模型中心',
  '/api-identity-profiles': '模型中心',
  '/api-access-profiles': '模型中心',
  '/api-parameters': '模型中心',
  '/api-admission': '策略与授权',
  '/api-machine-identities': '策略与授权',
  '/api-policy': '策略与授权',
  '/api-runtime-policies': '策略与授权',
  '/api-authz': '策略与授权',
  '/api-flow-baselines': '策略与授权',
  '/api-classifications': '数据安全',
  '/api-sensitive-fields': '数据安全',
  '/api-sensitive-types': '数据安全',
  '/api-masking-rules': '数据安全',
  '/api-cross-border': '数据安全',
  '/api-file-compliance': '数据安全',
  '/api-file-assets': '数据安全',
  '/api-graph': '关系与运行',
  '/api-topology': '关系与运行',
  '/api-data-flow': '关系与运行',
  '/api-group-control': '关系与运行',
  '/api-violations': '关系与运行',
  '/api-runtime-events': '关系与运行',
  '/api-llm': '关系与运行',
}

/** 按角色编码、用户权限点和产品能力过滤菜单；能力未初始化时按关闭处理。
 * 菜单可见性 = （角色码匹配 或 权限点命中）且产品能力开启，与路由 RequirePermission 口径一致 */
export function filterMenusByRoles(
  roleCodes: string[] | null | undefined,
  permissions: string[] | null | undefined,
  capabilities?: Partial<ProductCapabilities>,
): MenuDef[] {
  const codes = roleCodes ?? []
  const perms = permissions ?? []
  const auditOnly =
    codes.includes('AUDIT_ADMIN') &&
    !codes.some((code) => code === 'SYSTEM_ADMIN' || code === 'SECURITY_ADMIN')
  // webWaf 缺省 true（WAF/WDSP）；api 包显式 false
  const webWaf = capabilities?.webWafEnabled !== false
  return MENU_ITEMS.filter((item) => {
    if (item.denyAuditOnly && auditOnly) return false
    // 角色码与权限点为「或」关系：任一命中即显示；两者都未配置则全员可见
    if (item.roles || item.permissions) {
      const roleHit = item.roles?.some((r) => codes.includes(r)) ?? false
      const permHit = item.permissions?.some((p) => perms.includes(p)) ?? false
      if (!roleHit && !permHit) return false
    }
    if (item.capability === 'api_dynamic_protection') {
      return capabilities?.apiDynamicProtection === true
    }
    if (item.capability === 'apm') {
      // APM 能力未初始化或关闭时按不显示处理（fail-safe）
      return capabilities?.apmEnabled === true
    }
    if (item.capability === 'web_waf') {
      return webWaf
    }
    return true
  })
}

/** 授权管理菜单 key（授权锁定态下唯一保留的菜单项） */
export const LICENSE_MENU_KEY = '/license'

/** 授权锁定态菜单过滤：授权无效时仅保留「授权管理」恢复入口。 */
export function filterMenusByLicense(
  menus: MenuDef[],
  licenseValid: boolean,
): MenuDef[] {
  if (licenseValid) return menus
  const licenseMenu = MENU_ITEMS.find((m) => m.key === LICENSE_MENU_KEY)
  return licenseMenu ? [licenseMenu] : []
}
