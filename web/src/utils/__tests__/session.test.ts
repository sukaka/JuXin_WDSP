import { afterEach, describe, expect, it } from 'vitest'
import { QueryClient } from '@tanstack/react-query'
import { clearClientSession } from '../session'
import { useAuthStore } from '../../stores/auth'
import { useLicenseStore } from '../../stores/license'
import { useProductStore } from '../../stores/product'
import type { CurrentUser } from '../../types'

const fakeUser: CurrentUser = {
  id: 'u1',
  username: 'admin',
  display_name: '系统管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  permissions: ['users.read'],
  must_change_password: false,
}

describe('clearClientSession', () => {
  afterEach(() => {
    useAuthStore.getState().reset()
    useProductStore.getState().reset()
    useLicenseStore.getState().reset()
  })

  it('清空 QueryClient 缓存并重置 auth / product / license 全部 store，按序调用回调', () => {
    const qc = new QueryClient()
    qc.setQueryData(['security-events'], [{ id: 'e1' }])
    useAuthStore.getState().setSession(fakeUser, 'csrf-1')
    useProductStore.setState({ apiDynamicProtection: true, initialized: true })
    useLicenseStore.setState({ initialized: true })

    const order: string[] = []
    clearClientSession(qc, () => {
      order.push('beforeClear')
      // 回调触发时 store 已重置、缓存尚未清空（用于先卸载活跃观察器）
      expect(useAuthStore.getState().user).toBeNull()
      expect(qc.getQueryCache().getAll().length).toBe(1)
    })

    expect(order).toEqual(['beforeClear'])
    expect(qc.getQueryCache().getAll()).toHaveLength(0)
    expect(useAuthStore.getState().user).toBeNull()
    expect(useAuthStore.getState().csrfToken).toBeNull()
    expect(useProductStore.getState().initialized).toBe(false)
    expect(useLicenseStore.getState().initialized).toBe(false)
  })
})
