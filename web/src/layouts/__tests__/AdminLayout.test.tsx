import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { isValidElement } from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { App as AntdApp } from 'antd'
import {
  AimOutlined,
  AlertOutlined,
  ApiOutlined,
  AppstoreOutlined,
  BugOutlined,
  CloudUploadOutlined,
  ExperimentOutlined,
  EyeInvisibleOutlined,
  FileTextOutlined,
  FundViewOutlined,
  RadarChartOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SafetyOutlined,
  SettingOutlined,
  ShareAltOutlined,
  StopOutlined,
  ToolOutlined,
} from '@ant-design/icons'
import AdminLayout, { menuGroupIconFor, menuIconFor } from '../AdminLayout'
import { queryClient } from '../../api/queryClient'
import { SYSTEM_NAME } from '../../constants'
import { useAuthStore } from '../../stores/auth'
import { useBreadcrumbStore } from '../../stores/breadcrumb'
import { useLicenseStore } from '../../stores/license'
import { useProductStore } from '../../stores/product'
import { API_MENU_SECTIONS, MENU_ITEMS } from '../../utils/menu'
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

function renderLayout(initialPath = '/dashboard') {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AntdApp>
          <Routes>
            <Route element={<AdminLayout />}>
              <Route path="/dashboard" element={<div>dashboard-page</div>} />
              <Route path="/api-models" element={<div>api-models-page</div>} />
              <Route path="/config-publish" element={<div>config-publish-page</div>} />
              <Route path="/system-alerts" element={<div>system-alerts-page</div>} />
            </Route>
            <Route path="/login" element={<div>login-page</div>} />
          </Routes>
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AdminLayout', () => {
  beforeEach(() => {
    window.localStorage.removeItem('wdsp.navigation.mode')
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
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('所有 MENU_ITEMS 均能取得有效菜单图标', () => {
    for (const item of MENU_ITEMS) {
      expect(isValidElement(menuIconFor(item.key)), `${item.key} 缺少菜单图标`).toBe(true)
    }
  })

  it('补齐指定菜单图标并为未知菜单提供默认图标', () => {
    expect(menuIconFor('/api-admission')).toEqual(<SafetyCertificateOutlined />)
    expect(menuIconFor('/network-tools')).toEqual(<ToolOutlined />)
    expect(menuIconFor('/system-settings')).toEqual(<SettingOutlined />)
    expect(menuIconFor('/unknown-menu')).toEqual(<AppstoreOutlined />)
  })

  it('所有菜单分组与 API 二级分类使用指定图标，未知分组使用默认图标', () => {
    const expectedIcons = {
      '应用防护': <AppstoreOutlined />,
      '应用防护策略': <SafetyOutlined />,
      '访问控制': <StopOutlined />,
      'API 防护': <ApiOutlined />,
      '事件中心': <AlertOutlined />,
      '安全风险': <AimOutlined />,
      '业务性能': <FundViewOutlined />,
      '数据接入': <RadarChartOutlined />,
      '安全态势': <RadarChartOutlined />,
      '安全运营': <BugOutlined />,
      '报表中心': <FileTextOutlined />,
      '系统运维': <SettingOutlined />,
      '智能安全运营': <RobotOutlined />,
      '智能能力管理': <ToolOutlined />,
      '资产与接入': <CloudUploadOutlined />,
      '模型中心': <ExperimentOutlined />,
      '策略与授权': <SafetyCertificateOutlined />,
      '数据安全': <EyeInvisibleOutlined />,
      '关系与运行': <ShareAltOutlined />,
    }
    const labels = new Set<string>([
      ...MENU_ITEMS.map((item) => item.group).filter((group): group is string => Boolean(group)),
      ...Object.values(API_MENU_SECTIONS),
    ])
    expect([...labels].sort()).toEqual(Object.keys(expectedIcons).sort())
    for (const label of labels) {
      expect(menuGroupIconFor(label), `${label} 分组图标不正确`).toEqual(expectedIcons[label as keyof typeof expectedIcons])
    }
    expect(menuGroupIconFor('未知分组')).toEqual(<AppstoreOutlined />)
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

  it('默认使用核心扁平导航，切换全部功能后展开组内分类并记住选择', async () => {
    useAuthStore.getState().setSession({
      ...fakeUser,
      display_name: '安全管理员',
      roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    }, 'csrf-token')
    useProductStore.setState({ initialized: true, apiDynamicProtection: true, webWafEnabled: true })
    renderLayout()

    fireEvent.click(await screen.findByRole('button', { name: '打开导航菜单' }))
    expect(await screen.findByRole('menuitem', { name: /API 接口资产/ })).toBeInTheDocument()
    expect(screen.queryByText('API 防护')).not.toBeInTheDocument()
    expect(screen.queryByText('模型中心')).not.toBeInTheDocument()

    fireEvent.click(await screen.findByRole('button', { name: '查看全部功能' }))
    expect(window.localStorage.getItem('wdsp.navigation.mode')).toBe('full')
    fireEvent.click(await screen.findByText('API 防护'))
    expect(await screen.findByRole('menuitem', { name: /API 态势/ })).toBeInTheDocument()
    fireEvent.click(await screen.findByText('模型中心'))
    expect(await screen.findByRole('menuitem', { name: /模型版本/ })).toBeInTheDocument()
    expect(await screen.findByRole('menuitem', { name: /参数模型/ })).toBeInTheDocument()
  })

  it('直达高级页面时核心模式只补入当前入口', async () => {
    useAuthStore.getState().setSession({
      ...fakeUser,
      display_name: '安全管理员',
      roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    }, 'csrf-token')
    useProductStore.setState({ initialized: true, apiDynamicProtection: true, webWafEnabled: true })
    renderLayout('/api-models')

    fireEvent.click(await screen.findByRole('button', { name: '打开导航菜单' }))
    expect(await screen.findByRole('menuitem', { name: /模型版本/ })).toBeInTheDocument()
    expect(screen.queryByText('API 防护')).not.toBeInTheDocument()
    expect(screen.queryByText('模型中心')).not.toBeInTheDocument()
    expect(screen.queryByRole('menuitem', { name: /参数模型/ })).not.toBeInTheDocument()
  })

  it('桌面端侧边栏加宽、独立纵向滚动并收紧三级菜单缩进且保留完整 title', async () => {
    const originalMatchMedia = window.matchMedia
    window.matchMedia = ((query: string) => ({
      matches: query.includes('min-width: 768px') || query.includes('min-width: 576px'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    })) as unknown as typeof window.matchMedia
    try {
      window.localStorage.setItem('wdsp.navigation.mode', 'full')
      useAuthStore.getState().setSession({
        ...fakeUser,
        display_name: '安全管理员',
        roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
      }, 'csrf-token')
      useProductStore.setState({ initialized: true, apiDynamicProtection: true, webWafEnabled: true })

      const { container, unmount } = renderLayout()
      const sider = container.querySelector('aside.admin-sider') as HTMLElement | null
      expect(sider).not.toBeNull()
      expect(sider?.style.width).toBe('248px')
      expect(sider?.style.position).toBe('sticky')
      expect(sider?.style.height).toBe('100vh')

      const scrollBox = container.querySelector('.admin-sider-menu-scroll') as HTMLElement | null
      expect(scrollBox).not.toBeNull()
      expect(scrollBox?.style.overflowY).toBe('auto')

      fireEvent.click(await screen.findByText('API 防护'))
      fireEvent.click(await screen.findByText('资产与接入'))
      fireEvent.click(await screen.findByText('策略与授权'))

      const endpointsItem = await screen.findByRole('menuitem', { name: /API 接口资产/ })
      const groupsItem = await screen.findByRole('menuitem', { name: /业务功能分组/ })
      const mcpItem = await screen.findByRole('menuitem', { name: /MCP 工具目录/ })
      const admissionItem = await screen.findByRole('menuitem', { name: /API 准入防护/ })

      expect(endpointsItem).toHaveAttribute('title', 'API 接口资产')
      expect(groupsItem).toHaveAttribute('title', '业务功能分组')
      expect(mcpItem).toHaveAttribute('title', 'MCP 工具目录')
      expect(admissionItem).toHaveAttribute('title', 'API 准入防护')
      expect(endpointsItem.style.paddingLeft).toBe('48px')
      unmount()
    } finally {
      window.matchMedia = originalMatchMedia
    }
  })

  it('AI 能力停用时对可见 AI 菜单的用户显示停用横幅', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
        if (url.includes('/ai/status')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { enabled: false, degraded: false, message: '未配置可用模型' },
            }),
          )
        }
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
      }),
    )
    renderLayout()
    expect(await screen.findByText(/AI 能力当前不可用：未配置可用模型/)).toBeInTheDocument()
  })

  it('AI 能力降级时显示降级横幅', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
        if (url.includes('/ai/status')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { enabled: true, degraded: true, message: '高档位模型不可用' },
            }),
          )
        }
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
      }),
    )
    renderLayout()
    expect(await screen.findByText(/AI 能力降级运行：高档位模型不可用/)).toBeInTheDocument()
  })

  it('AI 状态正常时不显示横幅', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.includes('/ai/status')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { enabled: true, degraded: false, message: '' },
          }),
        )
      }
      return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
    })
    vi.stubGlobal('fetch', fetchMock)
    renderLayout()
    await screen.findByText('dashboard-page')
    await waitFor(() =>
      expect(
        fetchMock.mock.calls.some((c) => String(c[0]).includes('/ai/status')),
      ).toBe(true),
    )
    await waitFor(() => {
      expect(screen.queryByText(/AI 能力当前不可用/)).not.toBeInTheDocument()
      expect(screen.queryByText(/AI 能力降级运行/)).not.toBeInTheDocument()
    })
  })

  it('用户无任何 AI 菜单时不请求 AI 状态接口', async () => {
    useAuthStore.getState().setSession(
      { ...fakeUser, roles: [{ code: 'AUDIT_ADMIN', name: '审计管理员' }] },
      'csrf-token',
    )
    const fetchMock = vi.fn<(input: RequestInfo | URL) => Promise<Response>>(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null })),
    )
    vi.stubGlobal('fetch', fetchMock)
    renderLayout()
    await screen.findByText('dashboard-page')
    // 给潜在请求一个触发窗口后断言未发起
    await new Promise((r) => setTimeout(r, 100))
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes('/ai/status'))).toBe(false)
  })

  it('顶部栏快捷方式：具备权限时按「配置发布 → 站内告警铃铛」顺序位于用户菜单左侧，点击可直达配置发布', async () => {
    useAuthStore.getState().setSession(
      {
        ...fakeUser,
        username: 'oper',
        display_name: 'oper',
        roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
        permissions: [
          'gateway_configs.preview',
          'gateway_configs.publish',
          'system_alerts.read_security',
        ],
      },
      'csrf-token',
    )
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/system-alerts')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], total: 3, page: 1, page_size: 8 },
            }),
          )
        }
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null }))
      }),
    )

    renderLayout()

    const publishBtn = await screen.findByRole('button', { name: '配置发布' })
    const alertBell = await screen.findByRole('button', { name: '站内告警（3 条活跃）' })
    const userLabel = screen.getByText('oper')

    // 顺序校验：配置发布在左、站内告警铃铛在中间、用户菜单在右
    expect(publishBtn.compareDocumentPosition(alertBell) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(alertBell.compareDocumentPosition(userLabel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    // 点击配置发布快捷入口直达配置发布页
    fireEvent.click(publishBtn)
    expect(await screen.findByText('config-publish-page')).toBeInTheDocument()
  })

  it('无权限或授权锁定时隐藏配置发布与站内告警快捷入口，且不请求系统告警接口', async () => {
    useAuthStore.getState().setSession(
      {
        ...fakeUser,
        permissions: ['gateway_configs.publish', 'system_alerts.read'],
      },
      'csrf-token',
    )
    useLicenseStore.setState({
      initialized: true,
      status: { valid: false, status: 'EXPIRED', reason: '授权已过期' } as never,
    })
    const fetchMock = vi.fn<(input: RequestInfo | URL) => Promise<Response>>(() =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: null })),
    )
    vi.stubGlobal('fetch', fetchMock)

    renderLayout()
    await screen.findByText('dashboard-page')
    expect(screen.queryByRole('button', { name: '配置发布' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /站内告警/ })).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes('/system-alerts'))).toBe(false)
  })
})
