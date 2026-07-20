import { useMemo, useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { App as AntdApp, Avatar, Breadcrumb, Dropdown, Layout, Menu, Space, Spin } from 'antd'
import type { MenuProps } from 'antd'
import {
  AppstoreOutlined,
  AuditOutlined,
  CloudServerOutlined,
  CloudUploadOutlined,
  DashboardOutlined,
  FileProtectOutlined,
  FileSearchOutlined,
  HistoryOutlined,
  KeyOutlined,
  LogoutOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  TeamOutlined,
  UserOutlined,
} from '@ant-design/icons'
import type { ReactNode } from 'react'
import { authApi } from '../api/auth'
import { useAuthStore } from '../stores/auth'
import { filterMenusByRoles } from '../utils/menu'
import { SYSTEM_NAME } from '../constants'

const { Header, Sider, Content } = Layout

const MENU_ICONS: Record<string, ReactNode> = {
  '/dashboard': <DashboardOutlined />,
  '/applications': <AppstoreOutlined />,
  '/certificates': <FileProtectOutlined />,
  '/config-publish': <CloudUploadOutlined />,
  '/config-versions': <HistoryOutlined />,
  '/gateway-status': <CloudServerOutlined />,
  '/users': <TeamOutlined />,
  '/roles': <SafetyCertificateOutlined />,
  '/login-logs': <FileSearchOutlined />,
  '/audits': <AuditOutlined />,
  '/system-settings': <SettingOutlined />,
  '/profile': <UserOutlined />,
}

export default function AdminLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { message } = AntdApp.useApp()
  const user = useAuthStore((s) => s.user)
  const reset = useAuthStore((s) => s.reset)
  const [collapsed, setCollapsed] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)

  const menus = useMemo(
    () => filterMenusByRoles(user?.roles.map((r) => r.code)),
    [user],
  )

  // 无分组的顶层菜单在前，分组菜单按 group 聚合为分组节点
  const menuItems = useMemo<NonNullable<MenuProps['items']>>(() => {
    const items: NonNullable<MenuProps['items']> = []
    const groups = new Map<string, typeof menus>()
    for (const m of menus) {
      if (!m.group) {
        items.push({ key: m.key, icon: MENU_ICONS[m.key], label: m.label })
      } else {
        const arr = groups.get(m.group) ?? []
        arr.push(m)
        groups.set(m.group, arr)
      }
    }
    for (const [label, children] of groups) {
      items.push({
        type: 'group',
        label,
        children: children.map((m) => ({ key: m.key, icon: MENU_ICONS[m.key], label: m.label })),
      })
    }
    return items
  }, [menus])

  const currentMenu = menus.find((m) => location.pathname.startsWith(m.key))

  const handleLogout = async () => {
    setLoggingOut(true)
    try {
      await authApi.logout()
    } catch {
      // 退出登录失败不阻断本地清理
    } finally {
      reset()
      setLoggingOut(false)
      message.success('已退出登录')
      navigate('/login', { replace: true })
    }
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} theme="dark">
        <div
          style={{
            height: 56,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            fontWeight: 600,
            fontSize: collapsed ? 14 : 16,
            letterSpacing: 1,
            whiteSpace: 'nowrap',
            overflow: 'hidden',
          }}
        >
          <SafetyCertificateOutlined style={{ marginRight: collapsed ? 0 : 8, fontSize: 20 }} />
          {collapsed ? '' : '九章智能防护'}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={currentMenu ? [currentMenu.key] : []}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            background: '#fff',
            padding: '0 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: '1px solid #f0f0f0',
          }}
        >
          <Breadcrumb
            items={[
              { title: SYSTEM_NAME },
              ...(currentMenu ? [{ title: currentMenu.label }] : []),
            ]}
          />
          <Dropdown
            menu={{
              items: [
                { key: 'profile', icon: <UserOutlined />, label: '个人资料' },
                { key: 'change-password', icon: <KeyOutlined />, label: '修改密码' },
                { type: 'divider' },
                { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', danger: true },
              ],
              onClick: ({ key }) => {
                if (key === 'profile') navigate('/profile')
                else if (key === 'change-password') navigate('/change-password')
                else if (key === 'logout') void handleLogout()
              },
            }}
          >
            <Space style={{ cursor: 'pointer' }}>
              <Avatar size="small" icon={<UserOutlined />} />
              <span>{user?.display_name || user?.username}</span>
              {loggingOut && <Spin size="small" />}
            </Space>
          </Dropdown>
        </Header>
        <Content style={{ margin: 16 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
