import { describe, expect, it } from 'vitest'
import { filterMenusByRoles } from '../menu'

describe('filterMenusByRoles', () => {
  it('系统管理员：工作台/配置版本/网关状态/用户管理/角色权限/系统设置/个人中心', () => {
    const keys = filterMenusByRoles(['SYSTEM_ADMIN']).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/config-versions',
      '/gateway-status',
      '/users',
      '/roles',
      '/system-settings',
      '/profile',
    ])
  })

  it('审计管理员：工作台/配置版本/角色权限/登录日志/操作审计/个人中心', () => {
    const keys = filterMenusByRoles(['AUDIT_ADMIN']).map((m) => m.key)
    expect(keys).toEqual(['/dashboard', '/config-versions', '/roles', '/login-logs', '/audits', '/profile'])
  })

  it('安全管理员：工作台 + 应用防护全部菜单 + 个人中心', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN']).map((m) => m.key)
    expect(keys).toEqual([
      '/dashboard',
      '/applications',
      '/certificates',
      '/config-publish',
      '/config-versions',
      '/gateway-status',
      '/profile',
    ])
  })

  it('多角色取并集', () => {
    const keys = filterMenusByRoles(['SECURITY_ADMIN', 'AUDIT_ADMIN']).map((m) => m.key)
    expect(keys).toContain('/login-logs')
    expect(keys).toContain('/dashboard')
    expect(keys).toContain('/applications')
  })

  it('无角色时只显示公共菜单', () => {
    const keys = filterMenusByRoles(null).map((m) => m.key)
    expect(keys).toEqual(['/dashboard', '/profile'])
  })
})
