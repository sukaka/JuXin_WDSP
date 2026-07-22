import { useEffect, useMemo, useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { App as AntdApp, Avatar, Breadcrumb, Dropdown, Layout, Menu, Space, Spin } from 'antd'
import type { MenuProps } from 'antd'
import {
  AlertOutlined,
  AimOutlined,
  ApiOutlined,
  AppstoreOutlined,
  AuditOutlined,
  BarChartOutlined,
  BellOutlined,
  BookOutlined,
  BulbOutlined,
  CheckSquareOutlined,
  ClockCircleOutlined,
  CloudServerOutlined,
  CloudUploadOutlined,
  ControlOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  ExceptionOutlined,
  FileDoneOutlined,
  FileProtectOutlined,
  FileSearchOutlined,
  FileTextOutlined,
  FundViewOutlined,
  GlobalOutlined,
  HistoryOutlined,
  InboxOutlined,
  KeyOutlined,
  LineChartOutlined,
  LogoutOutlined,
  MessageOutlined,
  MonitorOutlined,
  PieChartOutlined,
  ProfileOutlined,
  RadarChartOutlined,
  RobotOutlined,
  RocketOutlined,
  SafetyCertificateOutlined,
  SafetyOutlined,
  SaveOutlined,
  ScheduleOutlined,
  SecurityScanOutlined,
  SettingOutlined,
  ShareAltOutlined,
  SnippetsOutlined,
  StopOutlined,
  TeamOutlined,
  ThunderboltOutlined,
  ToolOutlined,
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
  '/protection-policies': <SafetyOutlined />,
  '/waf-rules': <SecurityScanOutlined />,
  '/custom-rules': <ControlOutlined />,
  '/exceptions': <ExceptionOutlined />,
  '/trusted-proxies': <GlobalOutlined />,
  '/access-rules': <StopOutlined />,
  '/rate-limit': <ThunderboltOutlined />,
  '/temporary-blocks': <ClockCircleOutlined />,
  '/access-control-events': <ProfileOutlined />,
  '/security-events': <AlertOutlined />,
  '/event-statistics': <BarChartOutlined />,
  '/security-overview': <RadarChartOutlined />,
  '/analytics': <LineChartOutlined />,
  '/system-alerts': <BellOutlined />,
  '/reports': <FileTextOutlined />,
  '/report-templates': <FileDoneOutlined />,
  '/report-archives': <InboxOutlined />,
  '/system-monitoring': <MonitorOutlined />,
  '/storage': <DatabaseOutlined />,
  '/backup-restore': <SaveOutlined />,
  '/system-upgrade': <RocketOutlined />,
  '/delivery-check': <CheckSquareOutlined />,
  '/users': <TeamOutlined />,
  '/roles': <SafetyCertificateOutlined />,
  '/login-logs': <FileSearchOutlined />,
  '/audits': <AuditOutlined />,
  '/system-settings': <SettingOutlined />,
  '/profile': <UserOutlined />,
  '/ai/assistant': <RobotOutlined />,
  '/ai/event-analysis': <FundViewOutlined />,
  '/ai/attack-profile': <AimOutlined />,
  '/ai/attack-chain': <ShareAltOutlined />,
  '/ai/policy-recommendation': <BulbOutlined />,
  '/ai/report-summary': <SnippetsOutlined />,
  '/ai/tasks': <ScheduleOutlined />,
  '/ai/admin/models': <DeploymentUnitOutlined />,
  '/ai/admin/agents': <ApiOutlined />,
  '/ai/admin/tools': <ToolOutlined />,
  '/ai/admin/prompts': <MessageOutlined />,
  '/ai/admin/memories': <BookOutlined />,
  '/ai/admin/usage': <PieChartOutlined />,
  '/ai/admin/audits': <AuditOutlined />,
}

export default function AdminLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { message } = AntdApp.useApp()
  const user = useAuthStore((s) => s.user)
  const reset = useAuthStore((s) => s.reset)
  const [collapsed, setCollapsed] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)
  // 二级菜单默认收起，仅记录用户手动展开的分组
  const [openKeys, setOpenKeys] = useState<string[]>([])

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
        key: label,
        label,
        children: children.map((m) => ({ key: m.key, icon: MENU_ICONS[m.key], label: m.label })),
      })
    }
    return items
  }, [menus])

  const currentMenu = menus.find((m) => location.pathname.startsWith(m.key))

  // 直接进入某个分组下的页面时，自动展开该分组以保证选中项可见
  useEffect(() => {
    const group = currentMenu?.group
    if (group) {
      setOpenKeys((keys) => (keys.includes(group) ? keys : [...keys, group]))
    }
  }, [currentMenu])

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
          openKeys={collapsed ? undefined : openKeys}
          onOpenChange={(keys) => setOpenKeys(keys)}
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
