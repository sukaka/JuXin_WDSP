export interface MenuDef {
  key: string
  label: string
  /** 允许看到该菜单的角色编码；缺省表示所有登录用户可见 */
  roles?: string[]
  /** 依赖的产品能力；缺省表示所有产品形态可见 */
  capability?: 'api_dynamic_protection'
  /** 侧边栏分组名；缺省为顶层菜单 */
  group?: string
}

export interface ProductCapabilities {
  apiDynamicProtection: boolean
}

export const MENU_ITEMS: MenuDef[] = [
  { key: '/dashboard', label: '工作台' },
  { key: '/applications', label: '网站应用', roles: ['SECURITY_ADMIN'], group: '应用防护' },
  { key: '/certificates', label: 'HTTPS 证书', roles: ['SECURITY_ADMIN'], group: '应用防护' },
  { key: '/config-publish', label: '配置发布', roles: ['SECURITY_ADMIN'], group: '应用防护' },
  {
    key: '/config-versions',
    label: '配置版本',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN'],
    group: '应用防护',
  },
  {
    key: '/gateway-status',
    label: '网关状态',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'],
    group: '应用防护',
  },
  {
    key: '/protection-policies',
    label: '防护策略',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '应用防护策略',
  },
  {
    key: '/waf-rules',
    label: '防护规则库',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '应用防护策略',
  },
  { key: '/custom-rules', label: '自定义规则', roles: ['SECURITY_ADMIN'], group: '应用防护策略' },
  {
    key: '/exceptions',
    label: '例外策略',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '应用防护策略',
  },
  {
    key: '/trusted-proxies',
    label: '可信代理',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN'],
    group: '访问控制',
  },
  {
    key: '/access-rules',
    label: 'IP 黑白名单',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '访问控制',
  },
  {
    key: '/rate-limit',
    label: '频率与 CC 防护',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '访问控制',
  },
  {
    key: '/temporary-blocks',
    label: '临时封禁',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '访问控制',
  },
  {
    key: '/access-control-events',
    label: '访问控制事件',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '访问控制',
  },
  {
    key: '/access-control-versions',
    label: '访问控制版本',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '访问控制',
  },
  // 阶段8 / WDSP：接口动态防护
  {
    key: '/api-endpoints',
    label: '接口端点资产',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN', 'SYSTEM_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-models',
    label: '接口模型版本',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-learning',
    label: '学习中心',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-parameters',
    label: '参数模型',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-classifications',
    label: '用途分类',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-sensitive-fields',
    label: '敏感数据',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN', 'SYSTEM_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-specs',
    label: '规范对比',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-graph',
    label: '安全图谱',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-topology',
    label: '调用拓扑',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-findings',
    label: '接口风险',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN', 'SYSTEM_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-shadow-zombie',
    label: '影子与僵尸接口',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN', 'SYSTEM_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/api-policy',
    label: '接口策略',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN', 'SYSTEM_ADMIN'],
    capability: 'api_dynamic_protection',
    group: '接口防护',
  },
  {
    key: '/security-events',
    label: '安全事件',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '事件中心',
  },
  {
    key: '/access-logs',
    label: '访问日志',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'],
    group: '事件中心',
  },
  {
    key: '/event-statistics',
    label: '事件统计',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '事件中心',
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
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '安全态势',
  },
  {
    key: '/system-alerts',
    label: '系统告警',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN'],
    group: '安全态势',
  },
  {
    key: '/reports',
    label: '报告任务',
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
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
    roles: ['SECURITY_ADMIN', 'AUDIT_ADMIN'],
    group: '报表中心',
  },
  {
    key: '/system-monitoring',
    label: '运行监控',
    roles: ['SYSTEM_ADMIN'],
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
    key: '/delivery-check',
    label: '交付检查',
    roles: ['SYSTEM_ADMIN', 'AUDIT_ADMIN'],
    group: '系统运维',
  },
  // 阶段7：智能安全运营
  { key: '/ai/assistant', label: '安全助手', roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'], group: '智能安全运营' },
  { key: '/ai/event-analysis', label: '事件智能分析', roles: ['SECURITY_ADMIN'], group: '智能安全运营' },
  { key: '/ai/attack-profile', label: '攻击画像分析', roles: ['SECURITY_ADMIN'], group: '智能安全运营' },
  { key: '/ai/attack-chain', label: '攻击链分析', roles: ['SECURITY_ADMIN'], group: '智能安全运营' },
  { key: '/ai/policy-recommendation', label: '策略智能建议', roles: ['SECURITY_ADMIN'], group: '智能安全运营' },
  {
    key: '/ai/report-summary',
    label: '报告智能总结',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'],
    group: '智能安全运营',
  },
  { key: '/ai/tasks', label: '智能任务记录', roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'], group: '智能安全运营' },
  {
    key: '/ai/noise-reduction',
    label: '自动降噪',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'],
    group: '智能安全运营',
  },
  // 阶段7：智能能力管理
  { key: '/ai/admin/models', label: '模型管理', roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'], group: '智能能力管理' },
  { key: '/ai/admin/agents', label: '智能体管理', roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'], group: '智能能力管理' },
  { key: '/ai/admin/tools', label: '工具管理', roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'], group: '智能能力管理' },
  { key: '/ai/admin/prompts', label: '提示词管理', roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'], group: '智能能力管理' },
  { key: '/ai/admin/memories', label: '记忆管理', roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN'], group: '智能能力管理' },
  {
    key: '/ai/admin/usage',
    label: '配额与成本',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/audits',
    label: '智能审计',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN'],
    group: '智能能力管理',
  },
  {
    key: '/ai/admin/evaluations',
    label: '质量评估',
    roles: ['SECURITY_ADMIN', 'SYSTEM_ADMIN', 'AUDIT_ADMIN'],
    group: '智能能力管理',
  },
  { key: '/users', label: '用户管理', roles: ['SYSTEM_ADMIN'] },
  { key: '/roles', label: '角色权限', roles: ['SYSTEM_ADMIN', 'AUDIT_ADMIN'] },
  { key: '/login-logs', label: '登录日志', roles: ['AUDIT_ADMIN'] },
  { key: '/audits', label: '操作审计', roles: ['AUDIT_ADMIN'] },
  { key: '/system-settings', label: '系统设置', roles: ['SYSTEM_ADMIN'] },
  { key: '/profile', label: '个人中心' },
]

/** 按角色编码和产品能力过滤菜单；能力未初始化时按关闭处理 */
export function filterMenusByRoles(
  roleCodes: string[] | null | undefined,
  capabilities?: Partial<ProductCapabilities>,
): MenuDef[] {
  const codes = roleCodes ?? []
  return MENU_ITEMS.filter((item) => {
    if (item.roles && !item.roles.some((r) => codes.includes(r))) return false
    if (item.capability === 'api_dynamic_protection') {
      return capabilities?.apiDynamicProtection === true
    }
    return true
  })
}
