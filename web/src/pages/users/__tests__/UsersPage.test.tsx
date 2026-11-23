import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import UsersPage from '../UsersPage'
import { usersApi } from '../../../api/users'
import { rolesApi } from '../../../api/roles'
import { setCsrfToken, setSessionExpiredHandler } from '../../../api/client'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, RoleItem, UserItem } from '../../../types'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const ADMIN_USER: CurrentUser = {
  id: 'admin-1',
  username: 'admin_main',
  display_name: '系统管理员',
  status: 'ACTIVE',
  roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
  permissions: [
    'users.read',
    'users.create',
    'users.update',
    'users.disable',
    'users.unlock',
    'users.reset_password',
    'users.force_logout',
  ],
  must_change_password: false,
}

const SAMPLE_ROLES: RoleItem[] = [
  {
    id: 'r-1',
    code: 'SYSTEM_ADMIN',
    name: '系统管理员',
    description: '系统管理',
    is_builtin: true,
  },
  {
    id: 'r-2',
    code: 'SECURITY_ADMIN',
    name: '安全管理员',
    description: '策略管理',
    is_builtin: true,
  },
]

const SAMPLE_USERS: UserItem[] = [
  {
    id: 'u-2',
    username: 'sec_ops',
    display_name: '安全运维',
    status: 'ACTIVE',
    must_change_password: false,
    totp_enabled: true,
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    created_at: '2026-11-20T08:00:00Z',
    updated_at: '2026-11-20T08:00:00Z',
    version: 1,
  },
]

function renderUsersPage() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  })
  return render(
    <ConfigProvider locale={zhCN}>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <UsersPage />
        </AntdApp>
      </QueryClientProvider>
    </ConfigProvider>,
  )
}

describe('UsersPage 与 users/roles API 契约测试', () => {
  beforeEach(() => {
    setCsrfToken('csrf-test')
    setSessionExpiredHandler(null)
    useAuthStore.setState({
      user: ADMIN_USER,
      csrfToken: 'csrf-test',
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('B12-05: 新建用户校验拒绝 3 位用户名与点号(.)，允许 4-64 位 [a-zA-Z0-9_-]', async () => {
    const createBodies: unknown[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
        if (url.includes('/api/v1/users') && init?.method === 'POST') {
          createBodies.push(JSON.parse(String(init.body)))
          return ok({
            user: {
              ...SAMPLE_USERS[0],
              id: 'u-new',
              username: 'user_1-A',
              display_name: '测试用户',
              totp_enabled: false,
            },
            temporary_password: 'TempPass!123456',
            notice: '请立即修改密码',
          })
        }
        if (url.includes('/api/v1/users')) {
          return ok({ items: SAMPLE_USERS, total: 1, page: 1, page_size: 20 })
        }
        if (url.includes('/api/v1/roles')) {
          return ok({ items: SAMPLE_ROLES })
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderUsersPage()
    expect(await screen.findByText('sec_ops')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /新建用户/ }))
    const dialog = await screen.findByRole('dialog')

    const usernameInput = within(dialog).getByPlaceholderText('登录用户名')
    const displayNameInput = within(dialog).getByPlaceholderText('用户显示名称')

    fireEvent.change(displayNameInput, { target: { value: '测试用户' } })

    const roleSelect = dialog.querySelector('.ant-select') as HTMLElement
    expect(roleSelect).toBeTruthy()
    fireEvent.mouseDown(roleSelect)
    const roleOption = await screen.findByText('安全管理员', {
      selector: '.ant-select-item-option-content',
    })
    fireEvent.click(roleOption)

    // 1. 3 位用户名被拒绝
    fireEvent.change(usernameInput, { target: { value: 'abc' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    expect(await within(dialog).findByText('4-64 位字母、数字、下划线或短横线')).toBeInTheDocument()
    expect(createBodies).toHaveLength(0)

    // 2. 包含点号(.) 的用户名被拒绝
    fireEvent.change(usernameInput, { target: { value: 'john.doe' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    expect(await within(dialog).findByText('4-64 位字母、数字、下划线或短横线')).toBeInTheDocument()
    expect(createBodies).toHaveLength(0)

    // 3. 合法 4+ 位 [a-zA-Z0-9_-] 用户名可正常提交
    fireEvent.change(usernameInput, { target: { value: 'user_1-A' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }))

    await waitFor(() => {
      expect(createBodies).toHaveLength(1)
    })
    expect(createBodies[0]).toEqual({
      username: 'user_1-A',
      display_name: '测试用户',
      role_code: 'SECURITY_ADMIN',
    })
    expect(await screen.findByText('TempPass!123456')).toBeInTheDocument()
  })

  it('B12-06: RESOURCE_CONFLICT 保留后端具体错误消息并触发列表刷新，空消息时走兜底提示', async () => {
    let usersListCalls = 0
    let conflictMessage = '用户名已存在'

    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
        if (url.includes('/api/v1/users') && init?.method === 'POST') {
          return Promise.resolve(
            jsonResponse(
              { code: 'RESOURCE_CONFLICT', message: conflictMessage },
              409,
            ),
          )
        }
        if (url.includes('/api/v1/users')) {
          usersListCalls += 1
          return ok({ items: SAMPLE_USERS, total: 1, page: 1, page_size: 20 })
        }
        if (url.includes('/api/v1/roles')) {
          return ok({ items: SAMPLE_ROLES })
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderUsersPage()
    expect(await screen.findByText('sec_ops')).toBeInTheDocument()
    const callsBeforeSubmit = usersListCalls

    fireEvent.click(screen.getByRole('button', { name: /新建用户/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('登录用户名'), {
      target: { value: 'sec_ops' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('用户显示名称'), {
      target: { value: '重复用户' },
    })
    const roleSelect = dialog.querySelector('.ant-select') as HTMLElement
    fireEvent.mouseDown(roleSelect)
    fireEvent.click(
      await screen.findByText('安全管理员', {
        selector: '.ant-select-item-option-content',
      }),
    )

    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }))

    expect(await screen.findByText('用户名已存在')).toBeInTheDocument()
    expect(screen.queryByText('数据已被他人修改，请刷新列表后重试')).not.toBeInTheDocument()
    await waitFor(() => {
      expect(usersListCalls).toBeGreaterThan(callsBeforeSubmit)
    })

    // 空 message 时回退到兜底冲突文案
    conflictMessage = ''
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定/ }))
    expect(await screen.findByText('操作冲突，请刷新列表后重试')).toBeInTheDocument()
  })

  it('B8-05: 角色接口返回 null/空数组时 UsersPage 筛选、新建与编辑弹窗均安全渲染', async () => {
    let returnRoles: RoleItem[] | null = null
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
        if (url.includes('/api/v1/users')) {
          return ok({ items: SAMPLE_USERS, total: 1, page: 1, page_size: 20 })
        }
        if (url.includes('/api/v1/roles')) {
          return ok({ items: returnRoles })
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderUsersPage()
    expect(await screen.findByText('sec_ops')).toBeInTheDocument()

    // 打开新建弹窗，roles 为 null 时不崩溃
    fireEvent.click(screen.getByRole('button', { name: /新建用户/ }))
    const createDialog = await screen.findByRole('dialog')
    expect(within(createDialog).getByText('新建用户')).toBeInTheDocument()
    fireEvent.click(within(createDialog).getByRole('button', { name: /取\s*消/ }))

    // 打开编辑弹窗，roles 为 null 时不崩溃
    fireEvent.click(screen.getByRole('button', { name: '编辑' }))
    const editDialog = await screen.findByRole('dialog')
    expect(within(editDialog).getByText('编辑用户：sec_ops')).toBeInTheDocument()

    // rolesApi.list / detail / permissions 对 null 规范化为 []
    returnRoles = null
    expect(await rolesApi.list()).toEqual({ items: [] })
  })

  it('B12-10 & B8-05: usersApi 操作方法返回 { message }，rolesApi 规范化 null 切片', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
      if (url.endsWith('/api/v1/users/u-1/enable')) return ok({ message: '用户已启用' })
      if (url.endsWith('/api/v1/users/u-1/disable')) return ok({ message: '用户已停用' })
      if (url.endsWith('/api/v1/users/u-1/unlock')) return ok({ message: '用户已解锁' })
      if (url.endsWith('/api/v1/users/u-1/totp/reset')) return ok({ message: '该用户的双因子认证已重置' })
      if (url.endsWith('/api/v1/users/u-1/sessions')) return ok({ message: '该用户已全部下线' })
      if (url.endsWith('/api/v1/users/u-1')) return ok({ message: '用户已删除' })
      if (url.includes('/api/v1/users?')) return ok({ items: null, total: 0, page: 1, page_size: 20 })
      if (url.endsWith('/api/v1/roles/r-1')) {
        return ok({ role: SAMPLE_ROLES[0], permissions: null, user_count: 0 })
      }
      if (url.endsWith('/api/v1/roles')) return ok({ items: null })
      if (url.endsWith('/api/v1/permissions')) return ok({ items: null })
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    expect(await usersApi.enable('u-1')).toEqual({ message: '用户已启用' })
    expect(await usersApi.disable('u-1')).toEqual({ message: '用户已停用' })
    expect(await usersApi.unlock('u-1')).toEqual({ message: '用户已解锁' })
    expect(await usersApi.resetTotp('u-1')).toEqual({ message: '该用户的双因子认证已重置' })
    expect(await usersApi.forceLogout('u-1')).toEqual({ message: '该用户已全部下线' })
    expect(await usersApi.remove('u-1')).toEqual({ message: '用户已删除' })
    expect(await usersApi.list({ page: 1, page_size: 20 })).toEqual({
      items: [],
      total: 0,
      page: 1,
      page_size: 20,
    })

    expect(await rolesApi.list()).toEqual({ items: [] })
    expect(await rolesApi.detail('r-1')).toEqual({
      role: SAMPLE_ROLES[0],
      permissions: [],
      user_count: 0,
    })
    expect(await rolesApi.permissions()).toEqual({ items: [] })
  })

  it('编辑角色为 null 的用户记录时弹窗正常打开而不崩溃', async () => {
    const userWithNullRoles: UserItem = {
      ...SAMPLE_USERS[0],
      id: 'u-null-roles',
      username: 'no_role_user',
      display_name: '无角色用户',
      roles: null as unknown as UserItem['roles'],
    }
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
        if (url.includes('/api/v1/users')) {
          return ok({ items: [userWithNullRoles], total: 1, page: 1, page_size: 20 })
        }
        if (url.includes('/api/v1/roles')) {
          return ok({ items: SAMPLE_ROLES })
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderUsersPage()
    expect(await screen.findByText('no_role_user')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '编辑' }))
    const editDialog = await screen.findByRole('dialog')
    expect(within(editDialog).getByText('编辑用户：no_role_user')).toBeInTheDocument()
    expect(within(editDialog).getByDisplayValue('无角色用户')).toBeInTheDocument()
  })
})
