import { describe, expect, it } from 'vitest'
import { hasAnyPermission, hasPermission } from '../permission'

describe('hasPermission', () => {
  it('拥有权限返回 true', () => {
    expect(hasPermission(['users.read', 'users.create'], 'users.read')).toBe(true)
  })

  it('未拥有权限返回 false', () => {
    expect(hasPermission(['users.read'], 'users.create')).toBe(false)
  })

  it('空列表/undefined/null 返回 false', () => {
    expect(hasPermission([], 'users.read')).toBe(false)
    expect(hasPermission(undefined, 'users.read')).toBe(false)
    expect(hasPermission(null, 'users.read')).toBe(false)
  })

  it('空权限码返回 false', () => {
    expect(hasPermission(['users.read'], '')).toBe(false)
  })
})

describe('hasAnyPermission', () => {
  it('任一权限命中即返回 true', () => {
    expect(hasAnyPermission(['audits.read'], ['audits.read', 'audits.export'])).toBe(true)
    expect(hasAnyPermission(['users.read'], ['audits.read', 'audits.export'])).toBe(false)
  })
})
