export interface MenuDef {
  key: string
  label: string
  /** 允许看到该菜单的角色编码；缺省表示所有登录用户可见 */
  roles?: string[]
}

export const MENU_ITEMS: MenuDef[] = [
  { key: '/dashboard', label: '工作台' },
  { key: '/users', label: '用户管理', roles: ['SYSTEM_ADMIN'] },
  { key: '/roles', label: '角色权限', roles: ['SYSTEM_ADMIN', 'AUDIT_ADMIN'] },
  { key: '/login-logs', label: '登录日志', roles: ['AUDIT_ADMIN'] },
  { key: '/audits', label: '操作审计', roles: ['AUDIT_ADMIN'] },
  { key: '/system-settings', label: '系统设置', roles: ['SYSTEM_ADMIN'] },
  { key: '/profile', label: '个人中心' },
]

/** 按角色编码过滤菜单 */
export function filterMenusByRoles(roleCodes: string[] | null | undefined): MenuDef[] {
  const codes = roleCodes ?? []
  return MENU_ITEMS.filter((item) => !item.roles || item.roles.some((r) => codes.includes(r)))
}
