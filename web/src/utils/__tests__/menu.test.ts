import { describe, expect, it } from 'vitest'
import { filterMenusByRoles } from '../menu'

describe('filterMenusByRoles', () => {
  it('系统管理员：工作台/用户管理/角色权限/系统设置/个人中心，无日志与审计', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN']).map((m) => m.key)
    expect(keys).toEqual(['/dashboard', '/users', '/roles', '/system-settings', '/profile'])
  })

  it('审计管理员：工作台/角色权限/登录日志/操作审计/个人中心', () => {
    const keys = filterMenusByRoles(['AUDIT_ADMIN']).map((m) => m.key)
    expect(keys).toEqual(['/dashboard', '/roles', '/login-logs', '/audits', '/profile'])
  })

  it('安全管理员：仅工作台与个人中心', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN']).map((m) => m.key)
    expect(keys).toEqual(['/dashboard', '/profile'])
  })

  it('多角色取并集', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN', 'AUDIT_ADMIN']).map((m) => m.key)
    expect(keys).toContain('/login-logs')
    expect(keys).toContain('/dashboard')
  })

  it('无角色时只显示公共菜单', () => {
    const keys = filterMenusByRoles(null).map((m) => m.key)
    expect(keys).toEqual(['/dashboard', '/profile'])
  })
})
