import { beforeEach, describe, expect, it } from 'vitest'
import { useAuthStore } from '../auth'
import { getCsrfToken } from '../../api/client'
import type { CurrentUser } from '../../types'

const fakeUser: CurrentUser = {
  id: 'u1',
  username: 'admin',
  display_name: '系统管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  permissions: ['users.read'],
  must_change_password: false,
  last_login_at: null,
  last_login_ip: null,
}

describe('auth store', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
  })

  it('setSession 设置用户、CSRF 并标记已初始化', () => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-1')
    const state = useAuthStore.getState()
    expect(state.user).toEqual(fakeUser)
    expect(state.csrfToken).toBe('csrf-1')
    expect(state.initialized).toBe(true)
    // 同步写入 api client，供写操作使用
    expect(getCsrfToken()).toBe('csrf-1')
  })

  it('reset 清空用户与 CSRF，但保持已初始化', () => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-1')
    useAuthStore.getState().reset()
    const state = useAuthStore.getState()
    expect(state.user).toBeNull()
    expect(state.csrfToken).toBeNull()
    expect(state.initialized).toBe(true)
    expect(getCsrfToken()).toBeNull()
  })

  it('updateUser 更新用户信息', () => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-1')
    useAuthStore.getState().updateUser({ ...fakeUser, display_name: '新名字' })
    expect(useAuthStore.getState().user?.display_name).toBe('新名字')
  })
})
