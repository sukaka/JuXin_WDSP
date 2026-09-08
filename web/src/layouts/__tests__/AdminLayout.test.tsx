import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import AdminLayout from '../AdminLayout'
import { queryClient } from '../../api/queryClient'
import { SYSTEM_NAME } from '../../constants'
import { useAuthStore } from '../../stores/auth'
import { useBreadcrumbStore } from '../../stores/breadcrumb'
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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderLayout() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <AntdApp>
        <Routes>
          <Route element={<AdminLayout />}>
            <Route path="/dashboard" element={<div>dashboard-page</div>} />
          </Route>
          <Route path="/login" element={<div>login-page</div>} />
        </Routes>
      </AntdApp>
    </MemoryRouter>,
  )
}

describe('AdminLayout', () => {
  beforeEach(() => {
    useAuthStore.getState().setSession(fakeUser, 'csrf-token')
    useProductStore.setState({ initialized: false })
    useLicenseStore.setState({ status: null, initialized: false })
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null })),
      ),
    )
  })

  afterEach(() => {
    queryClient.clear()
    useAuthStore.getState().reset()
    useBreadcrumbStore.setState({ objectName: null })
    vi.unstubAllGlobals()
  })

  it('退出登录：清空 TanStack Query 缓存（防共享浏览器跨账号数据残留）并重置各 store 后跳登录页', async () => {
    // 模拟当前账号遗留的查询缓存
    queryClient.setQueryData(['security-events', 'list'], { items: [{ id: 'evt-a' }] })
    expect(queryClient.getQueryCache().getAll().length).toBeGreaterThan(0)

    renderLayout()

    // 打开用户下拉菜单（antd Dropdown 默认 hover 触发）
    fireEvent.mouseEnter(await screen.findByText('系统管理员'))
    fireEvent.click(await screen.findByText('退出登录'))

    await waitFor(() => {
      expect(queryClient.getQueryCache().getAll()).toHaveLength(0)
    })
    expect(useAuthStore.getState().user).toBeNull()
    expect(useProductStore.getState().initialized).toBe(false)
    expect(useLicenseStore.getState().initialized).toBe(false)
    expect(await screen.findByText('login-page')).toBeInTheDocument()
  })

  it('退出登录接口失败仍清空查询缓存并重置本地状态（不阻断本地清理）', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('network down'))))
    queryClient.setQueryData(['access-logs'], { items: [{ id: 'log-a' }] })

    renderLayout()
    fireEvent.mouseEnter(await screen.findByText('系统管理员'))
    fireEvent.click(await screen.findByText('退出登录'))

    await waitFor(() => {
      expect(queryClient.getQueryCache().getAll()).toHaveLength(0)
    })
    expect(useAuthStore.getState().user).toBeNull()
    expect(await screen.findByText('login-page')).toBeInTheDocument()
  })

  // jsdom 的 matchMedia mock 恒为 matches:false，useBreakpoint 判定为窄屏（<768px）
  it('窄屏下提供带可访问名称的菜单按钮，点击打开 Drawer 导航', async () => {
    renderLayout()
    const trigger = await screen.findByRole('button', { name: '打开导航菜单' })
    // Drawer 首次打开才挂载菜单内容（菜单项可访问名称带图标 aria-label 前缀，用正则匹配）
    expect(screen.queryByRole('menuitem', { name: /工作台/ })).not.toBeInTheDocument()
    fireEvent.click(trigger)
    expect(await screen.findByRole('menuitem', { name: /工作台/ })).toBeInTheDocument()
  })

  it('面包屑展示详情页注入的对象名：祖先节点可点击、当前节点纯文本', async () => {
    useBreadcrumbStore.setState({ objectName: '商城生产站点' })
    renderLayout()
    // 当前节点（对象名）为纯文本，不渲染为链接
    expect(await screen.findByText('商城生产站点')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '商城生产站点' })).not.toBeInTheDocument()
    // 祖先节点（系统名、一级菜单）为可点击链接
    expect(screen.getByRole('link', { name: SYSTEM_NAME })).toHaveAttribute('href', '/dashboard')
    expect(screen.getByRole('link', { name: '工作台' })).toHaveAttribute('href', '/dashboard')
  })

  it('面包屑无对象名注入时一级菜单为当前节点（纯文本）', async () => {
    renderLayout()
    expect(await screen.findByText('工作台')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '工作台' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: SYSTEM_NAME })).toHaveAttribute('href', '/dashboard')
  })
})
