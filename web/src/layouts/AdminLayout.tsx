import { useEffect, useMemo, useState } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Avatar,
  Breadcrumb,
  Button,
  Drawer,
  Dropdown,
  Grid,
  Layout,
  Menu,
  Space,
  Spin,
} from 'antd'
import type { MenuProps } from 'antd'
import {
  AlertOutlined,
  AimOutlined,
  ApartmentOutlined,
  ApiOutlined,
  AppstoreOutlined,
  AuditOutlined,
  BarChartOutlined,
  BellOutlined,
  BookOutlined,
  BugOutlined,
  BulbOutlined,
  CheckCircleOutlined,
  CheckSquareOutlined,
  ClockCircleOutlined,
  CloudServerOutlined,
  CloudUploadOutlined,
  CompassOutlined,
  ContainerOutlined,
  ControlOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  ExceptionOutlined,
  ExperimentOutlined,
  EyeInvisibleOutlined,
  EyeOutlined,
  FileDoneOutlined,
  FileProtectOutlined,
  FileSearchOutlined,
  FileSyncOutlined,
  FileTextOutlined,
  FilterOutlined,
  FundProjectionScreenOutlined,
  FundViewOutlined,
  GatewayOutlined,
  GlobalOutlined,
  HistoryOutlined,
  IdcardOutlined,
  InboxOutlined,
  InsuranceOutlined,
  KeyOutlined,
  LineChartOutlined,
  LockOutlined,
  LogoutOutlined,
  MenuOutlined,
  MessageOutlined,
  MonitorOutlined,
  NodeIndexOutlined,
  NotificationOutlined,
  PartitionOutlined,
  PieChartOutlined,
  PoweroffOutlined,
  ProfileOutlined,
  RadarChartOutlined,
  ReadOutlined,
  RiseOutlined,
  RobotOutlined,
  RocketOutlined,
  SafetyCertificateOutlined,
  SafetyOutlined,
  SaveOutlined,
  ScanOutlined,
  ScheduleOutlined,
  SecurityScanOutlined,
  SettingOutlined,
  ShareAltOutlined,
  SlidersOutlined,
  SnippetsOutlined,
  StopOutlined,
  TagsOutlined,
  TeamOutlined,
  ThunderboltOutlined,
  ToolOutlined,
  UserOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import type { ReactNode } from 'react'
import { authApi } from '../api/auth'
import { queryClient } from '../api/queryClient'
import { useAuthStore } from '../stores/auth'
import { useBreadcrumbStore } from '../stores/breadcrumb'
import { useLicenseStore } from '../stores/license'
import { useProductStore } from '../stores/product'
import { filterMenusByLicense, filterMenusByRoles } from '../utils/menu'
import { SYSTEM_NAME } from '../constants'

const { Header, Sider, Content } = Layout

const MENU_ICONS: Record<string, ReactNode> = {
  '/dashboard': <DashboardOutlined />,
  '/big-screen': <FundProjectionScreenOutlined />,
  '/applications': <AppstoreOutlined />,
  '/site-discovery': <CompassOutlined />,
  '/certificates': <FileProtectOutlined />,
  '/config-publish': <CloudUploadOutlined />,
  '/config-versions': <HistoryOutlined />,
  '/security-regressions': <FileSearchOutlined />,
  '/gateway-status': <CloudServerOutlined />,
  '/protection-policies': <SafetyOutlined />,
  '/waf-rules': <SecurityScanOutlined />,
  '/custom-rules': <ControlOutlined />,
  '/exceptions': <ExceptionOutlined />,
  '/behavior-policy': <ControlOutlined />,
  '/risk-policy': <SlidersOutlined />,
  '/trusted-proxies': <GlobalOutlined />,
  '/access-rules': <StopOutlined />,
  '/l7-rules': <FilterOutlined />,
  '/rate-limit': <ThunderboltOutlined />,
  '/temporary-blocks': <ClockCircleOutlined />,
  '/access-control-events': <ProfileOutlined />,
  '/access-control-versions': <HistoryOutlined />,
  '/api-endpoints': <NodeIndexOutlined />,
  '/api-posture': <FundProjectionScreenOutlined />,
  '/api-models': <ExperimentOutlined />,
  '/api-model-maturity': <RiseOutlined />,
  '/api-identity-profiles': <IdcardOutlined />,
  '/api-access-profiles': <RadarChartOutlined />,
  '/api-learning': <ReadOutlined />,
  '/api-parameters': <SlidersOutlined />,
  '/api-classifications': <TagsOutlined />,
  '/api-sensitive-fields': <EyeInvisibleOutlined />,
  '/api-specs': <FileSyncOutlined />,
  '/api-graph': <ApartmentOutlined />,
  '/api-topology': <PartitionOutlined />,
  '/api-findings': <WarningOutlined />,
  '/api-shadow-zombie': <EyeOutlined />,
  '/api-policy': <InsuranceOutlined />,
  '/api-weaknesses': <BugOutlined />,
  '/api-sensitive-types': <KeyOutlined />,
  '/api-masking-rules': <EyeInvisibleOutlined />,
  '/api-violations': <FileSearchOutlined />,
  '/api-runtime-events': <MonitorOutlined />,
  '/api-runtime-policies': <DeploymentUnitOutlined />,
  '/api-authz': <SafetyCertificateOutlined />,
  '/api-flow-baselines': <NodeIndexOutlined />,
  '/api-scan': <ScanOutlined />,
  '/api-ai-ops': <RobotOutlined />,
  '/api-llm': <BulbOutlined />,
  '/api-cross-border': <GlobalOutlined />,
  '/api-service-assets': <CloudServerOutlined />,
  '/api-nodes': <ApartmentOutlined />,
  '/api-file-compliance': <FileProtectOutlined />,
  '/security-events': <AlertOutlined />,
  '/access-logs': <ContainerOutlined />,
  '/event-statistics': <BarChartOutlined />,
  '/site-access-trends': <LineChartOutlined />,
  '/risk-identities': <IdcardOutlined />,
  '/attack-sessions': <AimOutlined />,
  '/apm-overview': <FundViewOutlined />,
  '/apm-services': <CloudServerOutlined />,
  '/apm-endpoints': <NodeIndexOutlined />,
  '/apm-traces': <ApartmentOutlined />,
  '/apm-agents': <ApiOutlined />,
  '/apm-sql': <DatabaseOutlined />,
  '/apm-exceptions': <BugOutlined />,
  '/apm-runtime': <MonitorOutlined />,
  '/apm-dependencies': <ShareAltOutlined />,
  '/apm-slos': <AimOutlined />,
  '/apm-diagnostics': <ExperimentOutlined />,
  '/traffic-agents': <RadarChartOutlined />,
  '/security-overview': <RadarChartOutlined />,
  '/analytics': <LineChartOutlined />,
  '/system-alerts': <BellOutlined />,
  '/reports': <FileTextOutlined />,
  '/report-templates': <FileDoneOutlined />,
  '/report-archives': <InboxOutlined />,
  '/system-monitoring': <MonitorOutlined />,
  '/node-interfaces': <DeploymentUnitOutlined />,
  '/network-config': <GatewayOutlined />,
  '/ha-groups': <DeploymentUnitOutlined />,
  '/storage': <DatabaseOutlined />,
  '/backup-restore': <SaveOutlined />,
  '/system-upgrade': <RocketOutlined />,
  '/system-control': <PoweroffOutlined />,
  '/delivery-check': <CheckSquareOutlined />,
  '/alert-notifications': <NotificationOutlined />,
  '/license': <LockOutlined />,
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
  '/ai/noise-reduction': <FilterOutlined />,
  '/ai/admin/models': <DeploymentUnitOutlined />,
  '/ai/admin/agents': <ApiOutlined />,
  '/ai/admin/tools': <ToolOutlined />,
  '/ai/admin/prompts': <MessageOutlined />,
  '/ai/admin/memories': <BookOutlined />,
  '/ai/admin/usage': <PieChartOutlined />,
  '/ai/admin/audits': <AuditOutlined />,
  '/ai/admin/evaluations': <CheckCircleOutlined />,
}

export default function AdminLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { message } = AntdApp.useApp()
  const user = useAuthStore((s) => s.user)
  const reset = useAuthStore((s) => s.reset)
  const apiDynamicProtection = useProductStore((s) => s.apiDynamicProtection)
  const webWafEnabled = useProductStore((s) => s.webWafEnabled)
  const apmEnabled = useProductStore((s) => s.apmEnabled)
  const licenseStatus = useLicenseStore((s) => s.status)
  const licenseInitialized = useLicenseStore((s) => s.initialized)
  const [collapsed, setCollapsed] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)
  // 二级菜单默认收起，仅记录用户手动展开的分组
  const [openKeys, setOpenKeys] = useState<string[]>([])
  // 窄屏（<768px）切换到 Drawer 导航，桌面维持 Sider
  const screens = Grid.useBreakpoint()
  const isMobile = !screens.md
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  // 详情页注入的面包屑对象名（见 stores/breadcrumb.ts）
  const breadcrumbObjectName = useBreadcrumbStore((s) => s.objectName)

  // 授权锁定态：状态已加载且无效（含加载失败），仅保留授权管理入口并顶部红色告警
  const licenseLocked = licenseInitialized && !licenseStatus?.valid

  const menus = useMemo(
    () =>
      filterMenusByLicense(
        filterMenusByRoles(user?.roles.map((r) => r.code), user?.permissions, {
          apiDynamicProtection,
          webWafEnabled,
          apmEnabled,
        }),
        !licenseLocked,
      ),
    [apiDynamicProtection, webWafEnabled, apmEnabled, licenseLocked, user],
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

  // 窄屏下路由切换后自动收起 Drawer 导航
  useEffect(() => {
    setMobileMenuOpen(false)
  }, [location.pathname])

  // 层级面包屑：系统名 / 一级菜单 / 详情对象名；祖先节点可点击，当前节点纯文本
  const breadcrumbItems = useMemo(() => {
    const crumbs: { label: string; to?: string }[] = [{ label: SYSTEM_NAME, to: '/dashboard' }]
    if (currentMenu) crumbs.push({ label: currentMenu.label, to: currentMenu.key })
    if (breadcrumbObjectName) crumbs.push({ label: breadcrumbObjectName })
    return crumbs.map((crumb, index) => ({
      title:
        index < crumbs.length - 1 && crumb.to ? (
          <Link to={crumb.to}>{crumb.label}</Link>
        ) : (
          crumb.label
        ),
    }))
  }, [currentMenu, breadcrumbObjectName])

  const navMenu = (
    <Menu
      theme="dark"
      mode="inline"
      selectedKeys={currentMenu ? [currentMenu.key] : []}
      openKeys={collapsed && !isMobile ? undefined : openKeys}
      onOpenChange={(keys) => setOpenKeys(keys)}
      items={menuItems}
      onClick={({ key }) => navigate(key)}
    />
  )

  const handleLogout = async () => {
    setLoggingOut(true)
    try {
      await authApi.logout()
    } catch {
      // 退出登录失败不阻断本地清理
    } finally {
      reset()
      useProductStore.getState().reset()
      useLicenseStore.getState().reset()
      // SPA 跳转不刷新页面，必须清空查询缓存，防共享浏览器跨账号数据残留
      queryClient.clear()
      setLoggingOut(false)
      message.success('已退出登录')
      navigate('/login', { replace: true })
    }
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {isMobile ? (
        <Drawer
          placement="left"
          width={240}
          open={mobileMenuOpen}
          onClose={() => setMobileMenuOpen(false)}
          title={
            <Space>
              <SafetyCertificateOutlined />
              <span>九章动态安全</span>
            </Space>
          }
          styles={{ body: { padding: 0, background: '#001529' } }}
        >
          {navMenu}
        </Drawer>
      ) : (
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
            {collapsed ? '' : '九章动态安全'}
          </div>
          {navMenu}
        </Sider>
      )}
      <Layout>
        <Header
          style={{
            background: '#fff',
            padding: isMobile ? '0 12px' : '0 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
            borderBottom: '1px solid #f0f0f0',
          }}
        >
          <Space size={isMobile ? 4 : 8} style={{ minWidth: 0, overflow: 'hidden' }}>
            {isMobile && (
              <Button
                type="text"
                icon={<MenuOutlined />}
                aria-label="打开导航菜单"
                onClick={() => setMobileMenuOpen(true)}
              />
            )}
            <Breadcrumb items={breadcrumbItems} />
          </Space>
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
            <Space style={{ cursor: 'pointer', whiteSpace: 'nowrap' }}>
              <Avatar size="small" icon={<UserOutlined />} />
              <span>{user?.display_name || user?.username}</span>
              {loggingOut && <Spin size="small" />}
            </Space>
          </Dropdown>
        </Header>
        {licenseLocked && (
          <Alert
            type="error"
            showIcon
            banner
            message={
              licenseStatus?.reason
                ? `授权无效：${licenseStatus.reason}。系统已锁定，仅授权管理可用，请导入有效授权文件。`
                : '授权状态加载失败，系统已锁定。请前往授权管理页重试。'
            }
          />
        )}
        <Content style={{ margin: isMobile ? 8 : 16 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
