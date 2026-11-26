import { lazy, Suspense, type ReactNode } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { useAuthStore } from '../stores/auth'
import { useLicenseStore } from '../stores/license'
import { useProductStore } from '../stores/product'
import { hasAnyPermission } from '../utils/permission'
import { FullScreenLoading, RequireLicense } from './RequireLicense'
import { RequireWebWaf } from './RequireWebWaf'
import { RequireApm } from './RequireApm'
import { RequireBigScreen } from './RequireBigScreen'
const AdminLayout = lazy(() => import('../layouts/AdminLayout'))
const LoginPage = lazy(() => import('../pages/login/LoginPage'))
const ChangePasswordPage = lazy(
  () => import('../pages/change-password/ChangePasswordPage'),
)
const DashboardPage = lazy(() => import('../pages/dashboard/DashboardPage'))
const ScreenLobbyPage = lazy(
  () => import('../pages/big-screen/ScreenLobbyPage'),
)
const SecurityPostureScreen = lazy(
  () => import('../pages/big-screen/SecurityPostureScreen'),
)
const AttackMonitorScreen = lazy(
  () => import('../pages/big-screen/AttackMonitorScreen'),
)
const GlobeScreen = lazy(() => import('../pages/big-screen/GlobeScreen'))
const TrafficAccessScreen = lazy(
  () => import('../pages/big-screen/TrafficAccessScreen'),
)
const ApiSecurityScreen = lazy(
  () => import('../pages/big-screen/ApiSecurityScreen'),
)
const GatewayConnectionScreen = lazy(
  () => import('../pages/big-screen/GatewayConnectionScreen'),
)
const RuntimeOpsScreen = lazy(
  () => import('../pages/big-screen/RuntimeOpsScreen'),
)
const UsersPage = lazy(() => import('../pages/users/UsersPage'))
const RolesPage = lazy(() => import('../pages/roles/RolesPage'))
const LoginLogsPage = lazy(() => import('../pages/login-logs/LoginLogsPage'))
const AuditsPage = lazy(() => import('../pages/audits/AuditsPage'))
const SystemSettingsPage = lazy(
  () => import('../pages/system-settings/SystemSettingsPage'),
)
const ProfilePage = lazy(() => import('../pages/profile/ProfilePage'))
const ApplicationsPage = lazy(
  () => import('../pages/applications/ApplicationsPage'),
)
const ApplicationDetailPage = lazy(
  () => import('../pages/applications/ApplicationDetailPage'),
)
const SiteDiscoveryPage = lazy(
  () => import('../pages/site-discovery/SiteDiscoveryPage'),
)
const CertificatesPage = lazy(
  () => import('../pages/certificates/CertificatesPage'),
)
const ConfigPublishPage = lazy(
  () => import('../pages/config-publish/ConfigPublishPage'),
)
const ConfigVersionsPage = lazy(
  () => import('../pages/config-versions/ConfigVersionsPage'),
)
const GatewayStatusPage = lazy(
  () => import('../pages/gateway-status/GatewayStatusPage'),
)
const ProtectionPoliciesPage = lazy(
  () => import('../pages/protection-policies/ProtectionPoliciesPage'),
)
const WafRulesPage = lazy(() => import('../pages/waf-rules/WafRulesPage'))
const CustomRulesPage = lazy(
  () => import('../pages/custom-rules/CustomRulesPage'),
)
const VulnRefsPage = lazy(() => import('../pages/vuln-refs/VulnRefsPage'))
const VulnIntelPage = lazy(() => import('../pages/vuln-intel/VulnIntelPage'))
const ExceptionsPage = lazy(() => import('../pages/exceptions/ExceptionsPage'))
const TrustedProxiesPage = lazy(
  () => import('../pages/trusted-proxies/TrustedProxiesPage'),
)
const AccessRulesPage = lazy(
  () => import('../pages/access-rules/AccessRulesPage'),
)
const WhitelistsPage = lazy(
  () => import('../pages/whitelists/WhitelistsPage'),
)
const L7RulesPage = lazy(() => import('../pages/l7-rules/L7RulesPage'))
const RateLimitPage = lazy(() => import('../pages/rate-limit/RateLimitPage'))
const TemporaryBlocksPage = lazy(
  () => import('../pages/temporary-blocks/TemporaryBlocksPage'),
)
const AccessControlEventsPage = lazy(
  () => import('../pages/access-control-events/AccessControlEventsPage'),
)
const AccessControlVersionsPage = lazy(
  () => import('../pages/access-control-versions/AccessControlVersionsPage'),
)
const AiCrawlPage = lazy(() => import('../pages/ai-crawl/AiCrawlPage'))
const ClientSideSecurityPage = lazy(
  () => import('../pages/client-side-security/ClientSideSecurityPage'),
)
const ApiEndpointsPage = lazy(
  () => import('../pages/api-endpoints/ApiEndpointsPage'),
)
const ApiEndpointGroupsPage = lazy(
  () => import('../pages/api-endpoint-groups/ApiEndpointGroupsPage'),
)
const ApiAdmissionPage = lazy(
  () => import('../pages/api-admission/ApiAdmissionPage'),
)
const ApiModelsPage = lazy(() => import('../pages/api-models/ApiModelsPage'))
const ModelMaturityPage = lazy(
  () => import('../pages/api-model-maturity/ModelMaturityPage'),
)
const ApiIdentityProfilesPage = lazy(
  () => import('../pages/api-identity-profiles/ApiIdentityProfilesPage'),
)
const ApiAccessProfilesPage = lazy(
  () => import('../pages/api-access-profiles/ApiAccessProfilesPage'),
)
const ApiLearningPage = lazy(
  () => import('../pages/api-learning/ApiLearningPage'),
)
const ApiParametersPage = lazy(
  () => import('../pages/api-parameters/ApiParametersPage'),
)
const ApiClassificationsPage = lazy(
  () => import('../pages/api-classifications/ApiClassificationsPage'),
)
const ApiSensitiveFieldsPage = lazy(
  () => import('../pages/api-sensitive-fields/ApiSensitiveFieldsPage'),
)
const ApiSpecsPage = lazy(() => import('../pages/api-specs/ApiSpecsPage'))
const ApiMcpPage = lazy(() => import('../pages/api-mcp/ApiMcpPage'))
const ApiMachineIdentitiesPage = lazy(
  () => import('../pages/api-machine-identities/ApiMachineIdentitiesPage'),
)
const ApiGraphPage = lazy(() => import('../pages/api-graph/ApiGraphPage'))
const ApiTopologyPage = lazy(
  () => import('../pages/api-topology/ApiTopologyPage'),
)
const ApiDataFlowPage = lazy(
  () => import('../pages/api-data-flow/ApiDataFlowPage'),
)
const ApiGroupControlPage = lazy(
  () => import('../pages/api-group-control/ApiGroupControlPage'),
)
const ApiFindingsPage = lazy(
  () => import('../pages/api-findings/ApiFindingsPage'),
)
const ApiShadowZombiePage = lazy(
  () => import('../pages/api-shadow-zombie/ApiShadowZombiePage'),
)
const ApiPolicyPage = lazy(() => import('../pages/api-policy/ApiPolicyPage'))
const ApiWeaknessesPage = lazy(
  () => import('../pages/api-weaknesses/ApiWeaknessesPage'),
)
const ApiSensitiveTypesPage = lazy(
  () => import('../pages/api-sensitive-types/ApiSensitiveTypesPage'),
)
const ApiMaskingRulesPage = lazy(
  () => import('../pages/api-masking-rules/ApiMaskingRulesPage'),
)
const ApiViolationsPage = lazy(
  () => import('../pages/api-violations/ApiViolationsPage'),
)
const ApiRuntimeEventsPage = lazy(
  () => import('../pages/api-runtime-events/ApiRuntimeEventsPage'),
)
const ApiRuntimePoliciesPage = lazy(
  () => import('../pages/api-runtime-policies/ApiRuntimePoliciesPage'),
)
const ApiAuthzPage = lazy(() => import('../pages/api-authz/ApiAuthzPage'))
const ApiFlowBaselinesPage = lazy(
  () => import('../pages/api-flow-baselines/ApiFlowBaselinesPage'),
)
const ApiScanPage = lazy(() => import('../pages/api-scan/ApiScanPage'))
const ApiPosturePage = lazy(() => import('../pages/api-posture/ApiPosturePage'))
const ApiAIOpsPage = lazy(() => import('../pages/api-ai-ops/ApiAIOpsPage'))
const ApiLLMPage = lazy(() => import('../pages/api-llm/ApiLLMPage'))
const ApiCrossBorderPage = lazy(
  () => import('../pages/api-cross-border/ApiCrossBorderPage'),
)
const ApiServiceAssetsPage = lazy(
  () => import('../pages/api-service-assets/ApiServiceAssetsPage'),
)
const ApiNodesPage = lazy(() => import('../pages/api-nodes/ApiNodesPage'))
const ApiFileCompliancePage = lazy(
  () => import('../pages/api-file-compliance/ApiFileCompliancePage'),
)
const ApiFileAssetsPage = lazy(
  () => import('../pages/api-file-assets/ApiFileAssetsPage'),
)
const SecurityEventsPage = lazy(
  () => import('../pages/security-events/SecurityEventsPage'),
)
const RiskIdentitiesPage = lazy(
  () => import('../pages/risk-identities/RiskIdentitiesPage'),
)
const IdentityDetailPage = lazy(
  () => import('../pages/risk-identities/IdentityDetailPage'),
)
const AttackSessionsPage = lazy(
  () => import('../pages/attack-sessions/AttackSessionsPage'),
)
const AttackSessionDetailPage = lazy(
  () => import('../pages/attack-sessions/AttackSessionDetailPage'),
)
const BehaviorPolicyPage = lazy(
  () => import('../pages/behavior-policy/BehaviorPolicyPage'),
)
const BehaviorPolicyGuidePage = lazy(
  () => import('../pages/behavior-policy/BehaviorPolicyGuidePage'),
)
const RiskPolicyPage = lazy(() => import('../pages/risk-policy/RiskPolicyPage'))
const RiskPolicyGuidePage = lazy(
  () => import('../pages/risk-policy/RiskPolicyGuidePage'),
)
const SecurityRegressionsPage = lazy(
  () => import('../pages/security-regressions/SecurityRegressionsPage'),
)
const SecurityRegressionDetailPage = lazy(
  () => import('../pages/security-regressions/SecurityRegressionDetailPage'),
)
const SecurityRegressionCasesPage = lazy(
  () => import('../pages/security-regressions/SecurityRegressionCasesPage'),
)
const AccessLogsPage = lazy(() => import('../pages/access-logs/AccessLogsPage'))
const EventStatisticsPage = lazy(
  () => import('../pages/event-statistics/EventStatisticsPage'),
)
const SiteAccessTrendsPage = lazy(
  () => import('../pages/site-access-trends/SiteAccessTrendsPage'),
)
const TLSSessionsPage = lazy(
  () => import('../pages/tls-sessions/TLSSessionsPage'),
)
const ApmOverviewPage = lazy(
  () => import('../pages/apm-overview/ApmOverviewPage'),
)
const ApmServicesPage = lazy(
  () => import('../pages/apm-services/ApmServicesPage'),
)
const ApmEndpointsPage = lazy(
  () => import('../pages/apm-endpoints/ApmEndpointsPage'),
)
const ApmTracesPage = lazy(() => import('../pages/apm-traces/ApmTracesPage'))
const ApmAgentsPage = lazy(() => import('../pages/apm-agents/ApmAgentsPage'))
const ApmSqlPage = lazy(() => import('../pages/apm-sql/ApmSqlPage'))
const ApmExceptionsPage = lazy(
  () => import('../pages/apm-exceptions/ApmExceptionsPage'),
)
const ApmRuntimePage = lazy(() => import('../pages/apm-runtime/ApmRuntimePage'))
const ApmDependenciesPage = lazy(
  () => import('../pages/apm-dependencies/ApmDependenciesPage'),
)
const ApmSlosPage = lazy(() => import('../pages/apm-slos/ApmSlosPage'))
const ApmDiagnosticsPage = lazy(
  () => import('../pages/apm-diagnostics/ApmDiagnosticsPage'),
)
const TrafficAgentsPage = lazy(
  () => import('../pages/traffic-agents/TrafficAgentsPage'),
)
const SecurityOverviewPage = lazy(
  () => import('../pages/security-overview/SecurityOverviewPage'),
)
const AnalyticsPage = lazy(() => import('../pages/analytics/AnalyticsPage'))
const SystemAlertsPage = lazy(
  () => import('../pages/system-alerts/SystemAlertsPage'),
)
const AlertNotificationsPage = lazy(
  () => import('../pages/alert-notifications/AlertNotificationsPage'),
)
const ReportsPage = lazy(() => import('../pages/reports/ReportsPage'))
const ReportTemplatesPage = lazy(
  () => import('../pages/report-templates/ReportTemplatesPage'),
)
const ReportArchivesPage = lazy(
  () => import('../pages/report-archives/ReportArchivesPage'),
)
const SystemMonitoringPage = lazy(
  () => import('../pages/system-monitoring/SystemMonitoringPage'),
)
const NodeInterfacesPage = lazy(
  () => import('../pages/node-interfaces/NodeInterfacesPage'),
)
const NetworkConfigPage = lazy(
  () => import('../pages/network-config/NetworkConfigPage'),
)
const NetworkToolsPage = lazy(
  () => import('../pages/network-tools/NetworkToolsPage'),
)
const SystemContainersPage = lazy(
  () => import('../pages/system-containers/SystemContainersPage'),
)
const HaGroupsPage = lazy(() => import('../pages/ha-groups/HaGroupsPage'))
const StoragePage = lazy(() => import('../pages/storage/StoragePage'))
const BackupRestorePage = lazy(
  () => import('../pages/backup-restore/BackupRestorePage'),
)
const SystemUpgradePage = lazy(
  () => import('../pages/system-upgrade/SystemUpgradePage'),
)
const SystemControlPage = lazy(
  () => import('../pages/system-control/SystemControlPage'),
)
const DeliveryCheckPage = lazy(
  () => import('../pages/delivery-check/DeliveryCheckPage'),
)
const AssistantPage = lazy(() => import('../pages/ai/assistant/AssistantPage'))
const EventAnalysisPage = lazy(
  () => import('../pages/ai/event-analysis/EventAnalysisPage'),
)
const AttackProfilePage = lazy(
  () => import('../pages/ai/attack-profile/AttackProfilePage'),
)
const AttackChainPage = lazy(
  () => import('../pages/ai/attack-chain/AttackChainPage'),
)
const PolicyRecommendationPage = lazy(
  () => import('../pages/ai/policy-recommendation/PolicyRecommendationPage'),
)
const ReportSummaryPage = lazy(
  () => import('../pages/ai/report-summary/ReportSummaryPage'),
)
const AiTasksPage = lazy(() => import('../pages/ai/tasks/AiTasksPage'))
const NoiseReductionPage = lazy(
  () => import('../pages/ai/noise-reduction/NoiseReductionPage'),
)
const AiModelsPage = lazy(() => import('../pages/ai/admin/models/AiModelsPage'))
const AiAgentsPage = lazy(() => import('../pages/ai/admin/agents/AiAgentsPage'))
const AiToolsPage = lazy(() => import('../pages/ai/admin/tools/AiToolsPage'))
const AiPromptsPage = lazy(
  () => import('../pages/ai/admin/prompts/AiPromptsPage'),
)
const AiMemoriesPage = lazy(
  () => import('../pages/ai/admin/memories/AiMemoriesPage'),
)
const AiUsagePage = lazy(() => import('../pages/ai/admin/usage/AiUsagePage'))
const AiAuditsPage = lazy(() => import('../pages/ai/admin/audits/AiAuditsPage'))
const AiEvaluationsPage = lazy(
  () => import('../pages/ai/admin/evaluations/AiEvaluationsPage'),
)
const ForbiddenPage = lazy(() =>
  import('../pages/errors').then((module) => ({
    default: module.ForbiddenPage,
  })),
)
const NotFoundPage = lazy(() =>
  import('../pages/errors').then((module) => ({
    default: module.NotFoundPage,
  })),
)
const ServerErrorPage = lazy(() =>
  import('../pages/errors').then((module) => ({
    default: module.ServerErrorPage,
  })),
)
const LicensePage = lazy(() => import('../pages/license/LicensePage'))

/** 登录守卫：未初始化完成先 Loading；未登录跳登录页；强制改密跳改密页 */
function RequireAuth({ children }: { children: ReactNode }) {
  const { user, initialized } = useAuthStore()
  const location = useLocation()
  if (!initialized) return <FullScreenLoading />
  if (!user)
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  if (user.must_change_password && location.pathname !== '/change-password') {
    return <Navigate to="/change-password" replace />
  }
  return <>{children}</>
}

/** 权限守卫：无权限跳 403；传入数组时表示拥有任一权限即可 */
function RequirePermission({
  permission,
  denyAuditOnly = false,
  children,
}: {
  permission: string | string[]
  denyAuditOnly?: boolean
  children: ReactNode
}) {
  const user = useAuthStore((s) => s.user)
  const codes = Array.isArray(permission) ? permission : [permission]
  const roleCodes = user?.roles.map((role) => role.code) ?? []
  const auditOnly =
    roleCodes.includes('AUDIT_ADMIN') &&
    !roleCodes.some(
      (code) => code === 'SYSTEM_ADMIN' || code === 'SECURITY_ADMIN',
    )
  if (denyAuditOnly && auditOnly) {
    return <Navigate to="/403" replace />
  }
  if (!hasAnyPermission(user?.permissions, codes)) {
    return <Navigate to="/403" replace />
  }
  return <>{children}</>
}

/** 授权有效时要求查看权限；授权失效时保留恢复入口，避免重定向循环。 */
function RequireLicenseAccess({ children }: { children: ReactNode }) {
  const user = useAuthStore((s) => s.user)
  const status = useLicenseStore((s) => s.status)
  const roleCodes = user?.roles.map((role) => role.code) ?? []
  const builtInOperator = roleCodes.some(
    (code) => code === 'SYSTEM_ADMIN' || code === 'SECURITY_ADMIN',
  )
  const auditOnly = roleCodes.includes('AUDIT_ADMIN') && !builtInOperator
  if (
    status?.valid &&
    (auditOnly ||
      (!builtInOperator &&
        !hasAnyPermission(user?.permissions, ['license.read'])))
  ) {
    return <Navigate to="/403" replace />
  }
  return <>{children}</>
}

/** WDSP 产品能力守卫：探测失败或纯 WAF 均按不存在处理 */
function RequireAPIDynamicProtection({ children }: { children: ReactNode }) {
  const { initialized, apiDynamicProtection } = useProductStore()
  if (!initialized) return <FullScreenLoading />
  if (!apiDynamicProtection) return <Navigate to="/404" replace />
  return <>{children}</>
}

export default function AppRoutes() {
  return (
    <Suspense fallback={<FullScreenLoading />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/change-password"
          element={
            <RequireAuth>
              <ChangePasswordPage />
            </RequireAuth>
          }
        />
        <Route
          path="/behavior-policy/guide"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequirePermission permission="behavior_policy.read">
                  <BehaviorPolicyGuidePage />
                </RequirePermission>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/risk-policy/guide"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequirePermission permission="risk_policy.read" denyAuditOnly>
                  <RiskPolicyGuidePage />
                </RequirePermission>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/big-screen/security-posture"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequirePermission permission="dashboard.security.read" denyAuditOnly>
                  <SecurityPostureScreen />
                </RequirePermission>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/big-screen/attack-monitor"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequirePermission
                  permission={[
                    'analytics.security.read',
                    'security_events.read',
                  ]}
                  denyAuditOnly
                >
                  <AttackMonitorScreen />
                </RequirePermission>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/big-screen/globe-attack"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequirePermission
                  permission={[
                    'analytics.security.read',
                    'security_events.read',
                  ]}
                  denyAuditOnly
                >
                  <GlobeScreen />
                </RequirePermission>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/big-screen/traffic-access"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequirePermission permission="analytics.security.read" denyAuditOnly>
                  <TrafficAccessScreen />
                </RequirePermission>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/big-screen/api-security"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequireAPIDynamicProtection>
                  <RequirePermission permission="api_runtime.read" denyAuditOnly>
                    <ApiSecurityScreen />
                  </RequirePermission>
                </RequireAPIDynamicProtection>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/big-screen/gateway-connections"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequirePermission permission="big_screen.runtime.read" denyAuditOnly>
                  <GatewayConnectionScreen />
                </RequirePermission>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/big-screen/runtime-ops"
          element={
            <RequireAuth>
              <RequireLicense>
                <RequirePermission permission="big_screen.runtime.read" denyAuditOnly>
                  <RuntimeOpsScreen />
                </RequirePermission>
              </RequireLicense>
            </RequireAuth>
          }
        />
        <Route
          path="/"
          element={
            <RequireAuth>
              <RequireLicense>
                <AdminLayout />
              </RequireLicense>
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<DashboardPage />} />
          <Route
            path="big-screen"
            element={
              <RequireBigScreen>
                <ScreenLobbyPage />
              </RequireBigScreen>
            }
          />
          <Route
            path="license"
            element={
              <RequireLicenseAccess>
                <LicensePage />
              </RequireLicenseAccess>
            }
          />
          <Route
            path="applications"
            element={
              <RequirePermission permission="applications.read">
                <ApplicationsPage />
              </RequirePermission>
            }
          />
          <Route
            path="applications/:id"
            element={
              <RequirePermission permission="applications.read">
                <ApplicationDetailPage />
              </RequirePermission>
            }
          />
          <Route
            path="site-discovery"
            element={
              <RequirePermission permission="site_discovery.read">
                <SiteDiscoveryPage />
              </RequirePermission>
            }
          />
          <Route
            path="certificates"
            element={
              <RequirePermission permission="certificates.read">
                <CertificatesPage />
              </RequirePermission>
            }
          />
          <Route
            path="config-publish"
            element={
              <RequirePermission permission="gateway_configs.preview">
                <ConfigPublishPage />
              </RequirePermission>
            }
          />
          <Route
            path="config-versions"
            element={
              <RequirePermission permission="config_versions.read">
                <ConfigVersionsPage />
              </RequirePermission>
            }
          />
          <Route
            path="gateway-status"
            element={
              <RequirePermission permission="gateway_status.read">
                <GatewayStatusPage />
              </RequirePermission>
            }
          />
          <Route
            path="protection-policies"
            element={
              <RequireWebWaf>
                <RequirePermission permission="protection_policies.read">
                  <ProtectionPoliciesPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="waf-rules"
            element={
              <RequireWebWaf>
                <RequirePermission permission="waf_rules.read">
                  <WafRulesPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="custom-rules"
            element={
              <RequireWebWaf>
                <RequirePermission permission="custom_rules.manage">
                  <CustomRulesPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          {/* CNNVD 兼容性 P1：漏洞档案（读沿用 waf_rules.read，写 waf_rule.vuln_ref.edit 页面内控） */}
          <Route
            path="waf/vuln-refs"
            element={
              <RequireWebWaf>
                <RequirePermission permission="waf_rules.read">
                  <VulnRefsPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="exceptions"
            element={
              <RequireWebWaf>
                <RequirePermission permission="exceptions.read">
                  <ExceptionsPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          {/* AI 自动化渗透防护 阶段1：行为检测策略（全局单例） */}
          <Route
            path="behavior-policy"
            element={
              <RequirePermission permission="behavior_policy.read">
                <BehaviorPolicyPage />
              </RequirePermission>
            }
          />
          {/* AI 自动化渗透防护 阶段3：风险策略（全局单例） */}
          <Route
            path="risk-policy"
            element={
              <RequirePermission permission="risk_policy.read" denyAuditOnly>
                <RiskPolicyPage />
              </RequirePermission>
            }
          />
          {/* P1-04 R4a：安全回归证据与发布门禁（列表 + 详情 + 用例差异；AUDIT_ADMIN 持 read 可看） */}
          <Route
            path="security-regressions"
            element={
              <RequirePermission permission="security_regression.read">
                <SecurityRegressionsPage />
              </RequirePermission>
            }
          />
          <Route
            path="security-regressions/:id"
            element={
              <RequirePermission permission="security_regression.read">
                <SecurityRegressionDetailPage />
              </RequirePermission>
            }
          />
          <Route
            path="security-regressions/:id/cases"
            element={
              <RequirePermission permission="security_regression.read">
                <SecurityRegressionCasesPage />
              </RequirePermission>
            }
          />
          <Route
            path="trusted-proxies"
            element={
              <RequirePermission permission="trusted_proxies.read">
                <TrustedProxiesPage />
              </RequirePermission>
            }
          />
          <Route
            path="access-rules"
            element={
              <RequireWebWaf>
                <RequirePermission permission="access_rules.read">
                  <AccessRulesPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="whitelists"
            element={
              <RequireWebWaf>
                <RequirePermission permission="access_rules.read">
                  <WhitelistsPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="l7-rules"
            element={
              <RequireWebWaf>
                <RequirePermission permission="l7rules.read">
                  <L7RulesPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="rate-limit"
            element={
              <RequireWebWaf>
                <RequirePermission permission="rate_limits.read">
                  <RateLimitPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="temporary-blocks"
            element={
              <RequireWebWaf>
                <RequirePermission permission="temporary_blocks.read">
                  <TemporaryBlocksPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="access-control-events"
            element={
              <RequireWebWaf>
                <RequirePermission permission="access_control_events.read">
                  <AccessControlEventsPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          <Route
            path="access-control-versions"
            element={
              <RequireWebWaf>
                <RequirePermission
                  permission={[
                    'access_control_versions.read',
                    'access_control_versions.rollback',
                  ]}
                >
                  <AccessControlVersionsPage />
                </RequirePermission>
              </RequireWebWaf>
            }
          />
          {/* WDSP Phase 9A-2：AI 爬虫公钥目录（Web Bot Auth） */}
          <Route
            path="ai-crawl"
            element={
              <RequirePermission permission="ai_crawl.read">
                <AiCrawlPage />
              </RequirePermission>
            }
          />
          {/* WDSP Phase 9B：客户端供应链安全（PCI DSS 4.0 6.4.3 & 11.6.1） */}
          <Route
            path="client-side-security"
            element={
              <RequirePermission permission="client_side.read">
                <ClientSideSecurityPage />
              </RequirePermission>
            }
          />
          <Route
            path="api-endpoints"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission
                  permission={[
                    'api_asset.read',
                    'api_asset.confirm',
                    'api_asset.edit',
                  ]}
                >
                  <ApiEndpointsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-endpoint-groups"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_endpoint_group.read">
                  <ApiEndpointGroupsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-admission"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_asset.read">
                  <ApiAdmissionPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-posture"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiPosturePage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-models"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission
                  permission={['api_model.read', 'api_model.edit']}
                >
                  <ApiModelsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-model-maturity"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ModelMaturityPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-identity-profiles"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiIdentityProfilesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-access-profiles"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiAccessProfilesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-learning"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_learning.read">
                  <ApiLearningPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-parameters"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_parameter.read">
                  <ApiParametersPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-classifications"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_classification.read">
                  <ApiClassificationsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-sensitive-fields"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiSensitiveFieldsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-specs"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_spec.read">
                  <ApiSpecsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-mcp"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_spec.read">
                  <ApiMcpPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-machine-identities"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="jwt_trust.read">
                  <ApiMachineIdentitiesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-graph"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_graph.read">
                  <ApiGraphPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-topology"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_graph.read">
                  <ApiTopologyPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-data-flow"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_data_flow.read">
                  <ApiDataFlowPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-group-control"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiGroupControlPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-findings"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiFindingsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-shadow-zombie"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiShadowZombiePage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-policy"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_policy.read">
                  <ApiPolicyPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-weaknesses"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_weakness.read">
                  <ApiWeaknessesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-sensitive-types"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_data.read">
                  <ApiSensitiveTypesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-masking-rules"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_data.read">
                  <ApiMaskingRulesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-violations"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiViolationsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-runtime-events"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiRuntimeEventsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-runtime-policies"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_model.read">
                  <ApiRuntimePoliciesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-authz"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_authorization.read">
                  <ApiAuthzPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-flow-baselines"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_flow.read">
                  <ApiFlowBaselinesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-scan"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_scan.read">
                  <ApiScanPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-ai-ops"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_ai.read">
                  <ApiAIOpsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-llm"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiLLMPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-cross-border"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_data.read">
                  <ApiCrossBorderPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-service-assets"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_asset.read">
                  <ApiServiceAssetsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-nodes"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_runtime.read">
                  <ApiNodesPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-file-compliance"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_data.read">
                  <ApiFileCompliancePage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          <Route
            path="api-file-assets"
            element={
              <RequireAPIDynamicProtection>
                <RequirePermission permission="api_data.read">
                  <ApiFileAssetsPage />
                </RequirePermission>
              </RequireAPIDynamicProtection>
            }
          />
          {/* 漏洞情报提醒（PHP 场景闭环）：读 vuln_intel.read，写 vuln_intel.manage 页面内控 */}
          <Route
            path="vuln-intel"
            element={
              <RequirePermission permission="vuln_intel.read">
                <VulnIntelPage />
              </RequirePermission>
            }
          />
          <Route
            path="security-events"
            element={
              <RequirePermission permission="security_events.read">
                <SecurityEventsPage />
              </RequirePermission>
            }
          />
          <Route
            path="access-logs"
            element={
              <RequirePermission permission="access_logs.read">
                <AccessLogsPage />
              </RequirePermission>
            }
          />
          <Route
            path="event-statistics"
            element={
              <RequirePermission permission="security_events.read">
                <EventStatisticsPage />
              </RequirePermission>
            }
          />
          <Route
            path="site-access-trends"
            element={
              <RequirePermission permission="analytics.security.read">
                <SiteAccessTrendsPage />
              </RequirePermission>
            }
          />
          <Route
            path="tls-sessions"
            element={
              <RequirePermission permission="events.read" denyAuditOnly>
                <TLSSessionsPage />
              </RequirePermission>
            }
          />
          {/* AI 自动化渗透防护 阶段1：风险身份列表 + 详情 */}
          <Route
            path="risk-identities"
            element={
              <RequirePermission permission="security_identities.read">
                <RiskIdentitiesPage />
              </RequirePermission>
            }
          />
          <Route
            path="risk-identities/:id"
            element={
              <RequirePermission permission="security_identities.read">
                <IdentityDetailPage />
              </RequirePermission>
            }
          />
          {/* AI 自动化渗透防护 阶段4：攻击活动列表 + 详情 */}
          <Route
            path="attack-sessions"
            element={
              <RequirePermission
                permission="attack_sessions.read"
                denyAuditOnly
              >
                <AttackSessionsPage />
              </RequirePermission>
            }
          />
          <Route
            path="attack-sessions/:id"
            element={
              <RequirePermission
                permission="attack_sessions.read"
                denyAuditOnly
              >
                <AttackSessionDetailPage />
              </RequirePermission>
            }
          />
          {/* APM 阶段1（无 Agent 模式）：能力关闭按 404 处理 */}
          <Route
            path="apm-overview"
            element={
              <RequireApm>
                <RequirePermission permission="apm.overview.read">
                  <ApmOverviewPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="apm-services"
            element={
              <RequireApm>
                <RequirePermission permission="apm.services.read">
                  <ApmServicesPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="apm-endpoints"
            element={
              <RequireApm>
                <RequirePermission permission="apm.services.read">
                  <ApmEndpointsPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="apm-traces"
            element={
              <RequireApm>
                <RequirePermission permission="apm.traces.read">
                  <ApmTracesPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="apm-agents"
            element={
              <RequireApm>
                <RequirePermission permission="apm.agents.manage">
                  <ApmAgentsPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          {/* WDSP 流量采集 Agent 管理（契约 §4：读 traffic.agents.view，写 traffic.agents.manage） */}
          <Route
            path="traffic-agents"
            element={
              <RequirePermission permission="traffic.agents.view" denyAuditOnly>
                <TrafficAgentsPage />
              </RequirePermission>
            }
          />
          {/* APM 阶段3：SQL / 异常 / 运行时 / 依赖 / SLO（同样受 apm_enabled 门控） */}
          <Route
            path="apm-sql"
            element={
              <RequireApm>
                <RequirePermission permission="apm.sql.read">
                  <ApmSqlPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="apm-exceptions"
            element={
              <RequireApm>
                <RequirePermission permission="apm.traces.read">
                  <ApmExceptionsPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="apm-runtime"
            element={
              <RequireApm>
                <RequirePermission permission="apm.runtime.read">
                  <ApmRuntimePage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="apm-dependencies"
            element={
              <RequireApm>
                <RequirePermission permission="apm.services.read">
                  <ApmDependenciesPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="apm-slos"
            element={
              <RequireApm>
                <RequirePermission permission="apm.overview.read">
                  <ApmSlosPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          {/* APM 阶段4：诊断中心（深度诊断会话 + 全局 kill switch，受 apm_enabled 门控） */}
          <Route
            path="apm-diagnostics"
            element={
              <RequireApm>
                <RequirePermission permission="apm.diagnostics.manage">
                  <ApmDiagnosticsPage />
                </RequirePermission>
              </RequireApm>
            }
          />
          <Route
            path="security-overview"
            element={
              <RequirePermission permission="dashboard.security.read">
                <SecurityOverviewPage />
              </RequirePermission>
            }
          />
          <Route
            path="analytics"
            element={
              <RequirePermission
                permission={[
                  'analytics.security.read',
                  'analytics.disposition.read',
                ]}
              >
                <AnalyticsPage />
              </RequirePermission>
            }
          />
          <Route
            path="system-alerts"
            element={
              <RequirePermission
                permission={[
                  'system_alerts.read',
                  'system_alerts.read_security',
                  'system_alerts.read_audit',
                ]}
              >
                <SystemAlertsPage />
              </RequirePermission>
            }
          />
          <Route
            path="reports"
            element={
              <RequirePermission
                permission={['reports.read', 'reports.read_audit']}
              >
                <ReportsPage />
              </RequirePermission>
            }
          />
          <Route
            path="report-templates"
            element={
              <RequirePermission permission="reports.read">
                <ReportTemplatesPage />
              </RequirePermission>
            }
          />
          <Route
            path="report-archives"
            element={
              <RequirePermission
                permission={['reports.read', 'reports.read_audit']}
              >
                <ReportArchivesPage />
              </RequirePermission>
            }
          />
          <Route
            path="system-monitoring"
            element={
              <RequirePermission permission="system_health.read">
                <SystemMonitoringPage />
              </RequirePermission>
            }
          />
          <Route
            path="node-interfaces"
            element={
              <RequirePermission permission="system_health.read">
                <NodeInterfacesPage />
              </RequirePermission>
            }
          />
          <Route
            path="network-config"
            element={
              <RequirePermission permission="system_health.read">
                <NetworkConfigPage />
              </RequirePermission>
            }
          />
          <Route
            path="network-tools"
            element={
              <RequirePermission permission="network_tools.execute">
                <NetworkToolsPage />
              </RequirePermission>
            }
          />
          <Route
            path="system-containers"
            element={
              <RequirePermission permission="containers.read">
                <SystemContainersPage />
              </RequirePermission>
            }
          />
          <Route
            path="ha-groups"
            element={
              <RequirePermission permission="ha.read">
                <HaGroupsPage />
              </RequirePermission>
            }
          />
          <Route
            path="storage"
            element={
              <RequirePermission permission="system_health.read">
                <StoragePage />
              </RequirePermission>
            }
          />
          <Route
            path="backup-restore"
            element={
              <RequirePermission permission="backups.read">
                <BackupRestorePage />
              </RequirePermission>
            }
          />
          <Route
            path="system-upgrade"
            element={
              <RequirePermission permission="upgrades.read">
                <SystemUpgradePage />
              </RequirePermission>
            }
          />
          <Route
            path="system-control"
            element={
              <RequirePermission
                permission={[
                  'system.reboot',
                  'system.shutdown',
                  'system.factory_reset',
                  'request_pcap.capture_control',
                ]}
              >
                <SystemControlPage />
              </RequirePermission>
            }
          />
          <Route
            path="delivery-check"
            element={
              <RequirePermission permission="delivery_checks.read">
                <DeliveryCheckPage />
              </RequirePermission>
            }
          />
          <Route
            path="alert-notifications"
            element={
              <RequirePermission permission="notification.read">
                <AlertNotificationsPage />
              </RequirePermission>
            }
          />
          <Route
            path="users"
            element={
              <RequirePermission permission="users.read">
                <UsersPage />
              </RequirePermission>
            }
          />
          <Route
            path="roles"
            element={
              <RequirePermission permission="roles.read">
                <RolesPage />
              </RequirePermission>
            }
          />
          <Route
            path="login-logs"
            element={
              <RequirePermission permission="login_logs.read">
                <LoginLogsPage />
              </RequirePermission>
            }
          />
          <Route
            path="audits"
            element={
              <RequirePermission permission="audits.read">
                <AuditsPage />
              </RequirePermission>
            }
          />
          <Route
            path="system-settings"
            element={
              <RequirePermission permission="system_settings.read">
                <SystemSettingsPage />
              </RequirePermission>
            }
          />
          <Route path="profile" element={<ProfilePage />} />
          {/* 阶段7：AI安全运营 */}
          <Route
            path="ai/assistant"
            element={
              <RequirePermission permission="ai.chat.use">
                <AssistantPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/event-analysis"
            element={
              <RequirePermission permission="ai.event_analysis.use">
                <EventAnalysisPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/attack-profile"
            element={
              <RequirePermission permission="ai.attack_profile.use">
                <AttackProfilePage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/attack-chain"
            element={
              <RequirePermission permission="ai.attack_chain.use">
                <AttackChainPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/policy-recommendation"
            element={
              <RequirePermission permission="ai.policy_recommendation.use">
                <PolicyRecommendationPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/report-summary"
            element={
              <RequirePermission
                permission={['ai.report_summary.use', 'ai.root_cause.use']}
              >
                <ReportSummaryPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/tasks"
            element={
              <RequirePermission permission="ai.sessions.read_own">
                <AiTasksPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/noise-reduction"
            element={
              <RequirePermission
                permission={[
                  'ai.noise_reduction.use',
                  'ai.noise_reduction.manage',
                ]}
              >
                <NoiseReductionPage />
              </RequirePermission>
            }
          />
          {/* 阶段7：AI管理 */}
          <Route
            path="ai/admin/models"
            element={
              <RequirePermission permission="ai.models.read">
                <AiModelsPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/admin/agents"
            element={
              <RequirePermission permission="ai.agents.read">
                <AiAgentsPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/admin/tools"
            element={
              <RequirePermission permission="ai.tools.read">
                <AiToolsPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/admin/prompts"
            element={
              <RequirePermission permission="ai.prompts.read">
                <AiPromptsPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/admin/memories"
            element={
              <RequirePermission permission="ai.memories.read_own">
                <AiMemoriesPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/admin/usage"
            element={
              <RequirePermission permission="ai.usage.read">
                <AiUsagePage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/admin/audits"
            element={
              <RequirePermission permission="ai.audits.read">
                <AiAuditsPage />
              </RequirePermission>
            }
          />
          <Route
            path="ai/admin/evaluations"
            element={
              <RequirePermission
                permission={[
                  'ai.evaluations.run',
                  'ai.usage.read',
                  'ai.audits.read',
                ]}
              >
                <AiEvaluationsPage />
              </RequirePermission>
            }
          />
        </Route>
        <Route path="/403" element={<ForbiddenPage />} />
        <Route path="/500" element={<ServerErrorPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Suspense>
  )
}
