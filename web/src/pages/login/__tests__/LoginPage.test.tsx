import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import LoginPage from '../LoginPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const fakeUser: CurrentUser = {
  id: 'u1',
  username: 'admin',
  display_name: '系统管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  permissions: [],
  must_change_password: false,
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderLogin() {
  return render(
    <MemoryRouter>
      <AntdApp>
        <LoginPage />
      </AntdApp>
    </MemoryRouter>,
  )
}

describe('LoginPage', () => {
  beforeEach(() => {
    useAuthStore.setState({ user: null, csrfToken: null, initialized: false })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染登录表单（验证码关闭时）', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { enabled: false } }),
        ),
      ),
    )
    renderLogin()
    expect(await screen.findByPlaceholderText('用户名')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('密码')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /登 录/ })).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('图形验证码')).not.toBeInTheDocument()
  })

  it('提交登录：请求体正确并写入会话', async () => {
    const fetchMock = vi.fn<typeof fetch>((input) => {
      const url = String(input)
      if (url.includes('/auth/captcha')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { enabled: false } }),
        )
      }
      if (url.includes('/auth/login')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { user: fakeUser, csrf_token: 'csrf-login' },
          }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderLogin()
    fireEvent.change(await screen.findByPlaceholderText('用户名'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('密码'), { target: { value: 'Secret@123456' } })
    fireEvent.click(screen.getByRole('button', { name: /登 录/ }))

    await waitFor(() => {
      const loginCall = fetchMock.mock.calls.find(([input]) => String(input).includes('/auth/login'))
      expect(loginCall).toBeDefined()
      const init = loginCall?.[1] as RequestInit
      const body = JSON.parse(String(init.body)) as Record<string, unknown>
      expect(body.username).toBe('admin')
      expect(body.password).toBe('Secret@123456')
    })

    await waitFor(() => {
      expect(useAuthStore.getState().user?.username).toBe('admin')
      expect(useAuthStore.getState().csrfToken).toBe('csrf-login')
    })
  })

  it('登录失败：清空密码并刷新验证码，不写会话', async () => {
    let captchaCalls = 0
    const fetchMock = vi.fn<typeof fetch>((input) => {
      const url = String(input)
      if (url.includes('/auth/captcha')) {
        captchaCalls += 1
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { enabled: false } }),
        )
      }
      if (url.includes('/auth/login')) {
        return Promise.resolve(
          jsonResponse(401, { code: 'UNAUTHENTICATED', message: '用户名或密码错误' }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    renderLogin()
    fireEvent.change(await screen.findByPlaceholderText('用户名'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('密码'), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByRole('button', { name: /登 录/ }))

    await waitFor(() => {
      expect(captchaCalls).toBeGreaterThanOrEqual(2)
    })
    expect((screen.getByPlaceholderText('密码') as HTMLInputElement).value).toBe('')
    expect((screen.getByPlaceholderText('用户名') as HTMLInputElement).value).toBe('admin')
    expect(useAuthStore.getState().user).toBeNull()
  })
})
