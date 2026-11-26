import { useEffect, useMemo, useState } from 'react'
import { flushSync } from 'react-dom'
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
  CodeOutlined,
  CodeSandboxOutlined,
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
import { useQuery } from '@tanstack/react-query'
import { authApi } from '../api/auth'
import { aiStatusApi } from '../api/ai'
import { queryClient } from '../api/queryClient'
import HeaderAlertsPopover from '../components/HeaderAlertsPopover'
import { useAuthStore } from '../stores/auth'
import { useBreadcrumbStore } from '../stores/breadcrumb'
import { useLicenseStore } from '../stores/license'
import { useProductStore } from '../stores/product'
import { API_MENU_SECTIONS, filterCoreMenus, filterMenusByLicense, filterMenusByRoles } from '../utils/menu'
import { hasAnyPermission } from '../utils/permission'
import { clearClientSession } from '../utils/session'
import { SYSTEM_NAME } from '../constants'

const { Header, Sider, Content } = Layout

const SIDER_WIDTH = 248
const MENU_INLINE_INDENT = 16

const MENU_ICONS: Record<string, ReactNode> = {
  '/dashboard': <DashboardOutlined />,
  '/big-screen': <FundProjectionScreenOutlined />,
  '/applications': <AppstoreOutlined />,
  '/site-discovery': <CompassOutlined />,
  '/certificates': <FileProtectOutlined />,
  '/config-publish': <CloudUploadOutlined />,
  '/config-versions': <HistoryOutlined />,
  '/gateway-status': <CloudServerOutlined />,
  '/protection-policies': <SafetyOutlined />,
  '/waf-rules': <SecurityScanOutlined />,
  '/custom-rules': <ControlOutlined />,
  '/waf/vuln-refs': <BugOutlined />,
  '/vuln-intel': <BugOutlined />,
  '/exceptions': <ExceptionOutlined />,
  '/behavior-policy': <ControlOutlined />,
  '/risk-policy': <SlidersOutlined />,
  '/trusted-proxies': <GlobalOutlined />,
  '/access-rules': <StopOutlined />,
  '/whitelists': <SafetyCertificateOutlined />,
  '/l7-rules': <FilterOutlined />,
  '/rate-limit': <ThunderboltOutlined />,
  '/temporary-blocks': <ClockCircleOutlined />,
  '/access-control-events': <ProfileOutlined />,
  '/access-control-versions': <HistoryOutlined />,
  '/ai-crawl': <RobotOutlined />,
  '/client-side-security': <CodeOutlined />,
  '/wasm-plugins': <CodeSandboxOutlined />,
  '/api-endpoints': <NodeIndexOutlined />,
  '/api-endpoint-groups': <DeploymentUnitOutlined />,
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
  '/api-mcp': <ApiOutlined />,
  '/api-a2a': <ShareAltOutlined />,
  '/api-machine-identities': <KeyOutlined />,
  '/api-graph': <ApartmentOutlined />,
  '/api-topology': <PartitionOutlined />,
  '/api-data-flow': <ShareAltOutlined />,
  '/api-group-control': <TeamOutlined />,
  '/api-admission': <SafetyCertificateOutlined />,
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
  '/tls-sessions': <LockOutlined />,
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
  '/network-tools': <ToolOutlined />,
  '/network-config': <GatewayOutlined />,
  '/xdp-acceleration': <ThunderboltOutlined />,
  '/system-containers': <CodeSandboxOutlined />,
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

const MENU_GROUP_ICONS: Record<string, ReactNode> = {
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

// eslint-disable-next-line react-refresh/only-export-components
export function menuIconFor(key: string): ReactNode {
  return MENU_ICONS[key] ?? <AppstoreOutlined />
}

// eslint-disable-next-line react-refresh/only-export-components
export function menuGroupIconFor(label: string): ReactNode {
  return MENU_GROUP_ICONS[label] ?? <AppstoreOutlined />
}

export default function AdminLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { message } = AntdApp.useApp()
  const user = useAuthStore((s) => s.user)
  const apiDynamicProtection = useProductStore((s) => s.apiDynamicProtection)
  const webWafEnabled = useProductStore((s) => s.webWafEnabled)
  const apmEnabled = useProductStore((s) => s.apmEnabled)
  const licenseStatus = useLicenseStore((s) => s.status)
  const licenseInitialized = useLicenseStore((s) => s.initialized)
  const [collapsed, setCollapsed] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)
  // 二级菜单默认收起，仅记录用户手动展开的分组
  const [openKeys, setOpenKeys] = useState<string[]>([])
  const [showAllNavigation, setShowAllNavigation] = useState(() => {
    try {
      return localStorage.getItem('wdsp.navigation.mode') === 'full'
    } catch {
      return false
    }
  })
  // 窄屏（<768px）切换到 Drawer 导航，桌面维持 Sider
  const screens = Grid.useBreakpoint()
  const isMobile = !screens.md
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  // 详情页注入的面包屑对象名（见 stores/breadcrumb.ts）
  const breadcrumbObjectName = useBreadcrumbStore((s) => s.objectName)

  // 授权锁定态：状态已加载且无效（含加载失败），仅保留授权管理入口并顶部红色告警
  const licenseLocked = licenseInitialized && !licenseStatus?.valid

  // 顶部快捷入口显隐：严格与路由权限和授权锁定状态保持一致
  const canAccessConfigPublish =
    !licenseLocked &&
    hasAnyPermission(user?.permissions, ['gateway_configs.preview', 'gateway_configs.publish'])
  const canReadAlerts =
    !licenseLocked &&
    hasAnyPermission(user?.permissions, [
      'system_alerts.read',
      'system_alerts.read_security',
      'system_alerts.read_audit',
    ])
  const onConfigPublish = location.pathname.startsWith('/config-publish')

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

  // AI 能力状态：仅当用户可见任一 AI 菜单时轮询（5 分钟间隔 + 5 分钟 staleTime，避免高频请求）；
  // 停用/降级时顶部横幅明示，正常时不渲染
  const hasAiMenu = useMemo(() => menus.some((m) => m.key.startsWith('/ai/')), [menus])
  const aiStatusQuery = useQuery({
    queryKey: ['ai-status'],
    queryFn: () => aiStatusApi.get(),
    // loggingOut：登出清空查询缓存期间禁用，避免 clear() 后活跃观察器立即重取
    enabled: hasAiMenu && !licenseLocked && !loggingOut,
    staleTime: 300_000,
    refetchInterval: 300_000,
  })
  const aiStatus = aiStatusQuery.data
  const aiStatusBanner = useMemo(() => {
    if (!aiStatus || (aiStatus.enabled && !aiStatus.degraded)) return null
    const detail = aiStatus.message ? `：${aiStatus.message}` : ''
    return !aiStatus.enabled
      ? `AI 能力当前不可用${detail || '，智能分析与草稿等 AI 功能暂停使用'}`
      : `AI 能力降级运行${detail || '，部分智能分析结果可能不完整'}`
  }, [aiStatus])

  const currentMenu = menus.find((m) => location.pathname.startsWith(m.key))
  const visibleMenus = useMemo(
    () => showAllNavigation || licenseLocked ? menus : filterCoreMenus(menus, currentMenu?.key),
    [showAllNavigation, licenseLocked, menus, currentMenu],
  )

  // 核心模式使用扁平导航；完整模式保留原有分组及 API 组内分类
  const menuItems = useMemo<NonNullable<MenuProps['items']>>(() => {
    const items: NonNullable<MenuProps['items']> = []
    const groups = new Map<string, typeof visibleMenus>()
    for (const m of visibleMenus) {
      if (!m.group) {
        items.push({ key: m.key, icon: menuIconFor(m.key), label: m.label, title: m.label })
      } else {
        const arr = groups.get(m.group) ?? []
        arr.push(m)
        groups.set(m.group, arr)
      }
    }
    for (const [label, groupChildren] of groups) {
      const children: NonNullable<MenuProps['items']> = []
      const sections = new Map<string, { key: string; icon: ReactNode; label: string; children: NonNullable<MenuProps['items']> }>()
      for (const m of groupChildren) {
        const section = label === 'API 防护' ? API_MENU_SECTIONS[m.key] : undefined
        if (!section) {
          children.push({ key: m.key, icon: menuIconFor(m.key), label: m.label, title: m.label })
          continue
        }
        let sectionItem = sections.get(section)
        if (!sectionItem) {
          sectionItem = { key: `${label}/section:${section}`, icon: menuGroupIconFor(section), label: section, children: [] }
          sections.set(section, sectionItem)
          children.push(sectionItem)
        }
        sectionItem.children.push({ key: m.key, icon: menuIconFor(m.key), label: m.label, title: m.label })
      }
      items.push({ key: label, icon: menuGroupIconFor(label), label, children })
    }
    return items
  }, [visibleMenus])

  // 直接进入组内分类页面时，同时展开一级分组和对应分类
  useEffect(() => {
    const group = currentMenu?.group
    const section = group === 'API 防护' && currentMenu ? API_MENU_SECTIONS[currentMenu.key] : undefined
    const required = [group, section ? `${group}/section:${section}` : undefined].filter((key): key is string => Boolean(key))
    if (required.length === 0) return
    setOpenKeys((keys) => {
      const missing = required.filter((key) => !keys.includes(key))
      return missing.length > 0 ? [...keys, ...missing] : keys
    })
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

  const isDesktopCollapsed = collapsed && !isMobile

  const navMenu = (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
      <div
        style={{
          flexShrink: 0,
          padding: isDesktopCollapsed ? '0 8px 12px' : isMobile ? '12px 16px' : '0 16px 12px',
          borderBottom: '1px solid rgba(255,255,255,0.12)',
        }}
      >
        <Button
          type="text"
          icon={<AppstoreOutlined />}
          aria-label={showAllNavigation ? '切换为核心功能导航' : '查看全部功能'}
          aria-pressed={showAllNavigation}
          onClick={() => setShowAllNavigation((previous) => {
            const next = !previous
            try {
              localStorage.setItem('wdsp.navigation.mode', next ? 'full' : 'core')
            } catch {
              // 浏览器禁用存储时仅保留当前会话内的模式
            }
            return next
          })}
          style={{
            width: '100%',
            justifyContent: isDesktopCollapsed ? 'center' : 'flex-start',
            color: 'rgba(255,255,255,0.85)',
          }}
        >
          {isDesktopCollapsed ? '' : showAllNavigation ? '核心功能' : '全部功能'}
        </Button>
      </div>
      <div
        className="admin-sider-menu-scroll"
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: 'auto',
          overflowX: 'hidden',
          paddingBottom: 12,
        }}
      >
        <Menu
          theme="dark"
          mode="inline"
          inlineIndent={MENU_INLINE_INDENT}
          selectedKeys={currentMenu ? [currentMenu.key] : []}
          openKeys={isDesktopCollapsed ? undefined : openKeys}
          onOpenChange={(keys) => setOpenKeys(keys)}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </div>
    </div>
  )

  const handleLogout = async () => {
    setLoggingOut(true)
    try {
      await authApi.logout()
    } catch {
      // 退出登录失败不阻断本地清理
    } finally {
      setLoggingOut(false)
      message.success('已退出登录')
      // SPA 跳转不刷新页面，必须清空查询缓存并重置全部 store，防共享浏览器跨账号数据残留；
      // 先 flushSync 完成路由卸载（摘掉活跃查询观察器），再清缓存，避免 AI 状态轮询等活跃查询在 clear 后立即重取回灌
      clearClientSession(queryClient, () => flushSync(() => navigate('/login', { replace: true })))
    }
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      {isMobile ? (
        <Drawer
          placement="left"
          size={SIDER_WIDTH}
          open={mobileMenuOpen}
          onClose={() => setMobileMenuOpen(false)}
          title={
            <Space>
              <SafetyCertificateOutlined />
              <span>九章动态安全</span>
            </Space>
          }
          styles={{
            body: {
              padding: 0,
              background: '#001529',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
            },
          }}
        >
          {navMenu}
        </Drawer>
      ) : (
        <Sider
          className="admin-sider"
          collapsible
          collapsed={collapsed}
          onCollapse={setCollapsed}
          theme="dark"
          width={SIDER_WIDTH}
          style={{
            position: 'sticky',
            top: 0,
            height: '100vh',
            alignSelf: 'flex-start',
          }}
          styles={{
            body: {
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
            },
          }}
        >
          <div
            style={{
              height: 56,
              flexShrink: 0,
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
          <Space size={isMobile ? 6 : 12} align="center" style={{ flexShrink: 0 }}>
            {canAccessConfigPublish && (
              <Button
                type="primary"
                ghost={!onConfigPublish}
                size={isMobile ? 'small' : 'middle'}
                icon={<CloudUploadOutlined />}
                aria-label="配置发布"
                onClick={() => navigate('/config-publish')}
              >
                {isMobile ? null : '配置发布'}
              </Button>
            )}
            {canReadAlerts && <HeaderAlertsPopover disabled={licenseLocked || loggingOut} />}
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
          </Space>
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
        {!licenseLocked && aiStatusBanner && (
          <Alert type="warning" showIcon banner message={aiStatusBanner} />
        )}
        <Content style={{ margin: isMobile ? 8 : 16 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}
