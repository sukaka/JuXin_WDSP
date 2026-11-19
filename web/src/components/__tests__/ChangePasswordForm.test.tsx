import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import ChangePasswordForm from '../ChangePasswordForm'
import { queryClient } from '../../api/queryClient'
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
  permissions: [],
  must_change_password: false,
}

describe('ChangePasswordForm', () => {
  beforeEach(() => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-pw')
    useProductStore.setState({ apiDynamicProtection: true, initialized: true })
    useLicenseStore.setState({ initialized: true })
    queryClient.setQueryData(['profile', 'secret'], { username: 'admin' })
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response(JSON.stringify({ code: 'SUCCESS', message: 'ok', data: null }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
        ),
      ),
    )
  })

  afterEach(() => {
    queryClient.clear()
    useAuthStore.getState().reset()
    useProductStore.getState().reset()
    useLicenseStore.getState().reset()
    vi.unstubAllGlobals()
  })

  it('改密成功后清空 QueryClient 缓存并重置 auth / product / license 全部 store', async () => {
    const onSuccess = vi.fn()
    render(
      <AntdApp>
        <ChangePasswordForm onSuccess={onSuccess} />
      </AntdApp>,
    )

    fireEvent.change(screen.getByPlaceholderText('请输入当前密码'), { target: { value: 'OldPass@123456' } })
    fireEvent.change(screen.getByPlaceholderText('请输入新密码'), { target: { value: 'NewPass@123456' } })
    fireEvent.change(screen.getByPlaceholderText('请再次输入新密码'), { target: { value: 'NewPass@123456' } })
    fireEvent.click(screen.getByRole('button', { name: /确认修改/ }))

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1))
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0)
    expect(useAuthStore.getState().user).toBeNull()
    expect(useProductStore.getState().initialized).toBe(false)
    expect(useLicenseStore.getState().initialized).toBe(false)
  })
})
