import type { ReactNode } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { Spin } from 'antd'
import { useAuthStore } from '../stores/auth'
import { useProductStore } from '../stores/product'
import { hasAnyPermission } from '../utils/permission'
import AdminLayout from '../layouts/AdminLayout'
import LoginPage from '../pages/login/LoginPage'
import ChangePasswordPage from '../pages/change-password/ChangePasswordPage'
import DashboardPage from '../pages/dashboard/DashboardPage'
import UsersPage from '../pages/users/UsersPage'
import RolesPage from '../pages/roles/RolesPage'
import LoginLogsPage from '../pages/login-logs/LoginLogsPage'
import AuditsPage from '../pages/audits/AuditsPage'
import SystemSettingsPage from '../pages/system-settings/SystemSettingsPage'
import ProfilePage from '../pages/profile/ProfilePage'
import ApplicationsPage from '../pages/applications/ApplicationsPage'
import ApplicationDetailPage from '../pages/applications/ApplicationDetailPage'
import CertificatesPage from '../pages/certificates/CertificatesPage'
import ConfigPublishPage from '../pages/config-publish/ConfigPublishPage'
import ConfigVersionsPage from '../pages/config-versions/ConfigVersionsPage'
import GatewayStatusPage from '../pages/gateway-status/GatewayStatusPage'
import ProtectionPoliciesPage from '../pages/protection-policies/ProtectionPoliciesPage'
import WafRulesPage from '../pages/waf-rules/WafRulesPage'
import CustomRulesPage from '../pages/custom-rules/CustomRulesPage'
import ExceptionsPage from '../pages/exceptions/ExceptionsPage'
import TrustedProxiesPage from '../pages/trusted-proxies/TrustedProxiesPage'
import AccessRulesPage from '../pages/access-rules/AccessRulesPage'
import RateLimitPage from '../pages/rate-limit/RateLimitPage'
import TemporaryBlocksPage from '../pages/temporary-blocks/TemporaryBlocksPage'
import AccessControlEventsPage from '../pages/access-control-events/AccessControlEventsPage'
import AccessControlVersionsPage from '../pages/access-control-versions/AccessControlVersionsPage'
import ApiEndpointsPage from '../pages/api-endpoints/ApiEndpointsPage'
import ApiModelsPage from '../pages/api-models/ApiModelsPage'
import ApiLearningPage from '../pages/api-learning/ApiLearningPage'
import ApiParametersPage from '../pages/api-parameters/ApiParametersPage'
import ApiClassificationsPage from '../pages/api-classifications/ApiClassificationsPage'
import ApiSensitiveFieldsPage from '../pages/api-sensitive-fields/ApiSensitiveFieldsPage'
import ApiSpecsPage from '../pages/api-specs/ApiSpecsPage'
import ApiGraphPage from '../pages/api-graph/ApiGraphPage'
import ApiTopologyPage from '../pages/api-topology/ApiTopologyPage'
import ApiFindingsPage from '../pages/api-findings/ApiFindingsPage'
import ApiShadowZombiePage from '../pages/api-shadow-zombie/ApiShadowZombiePage'
import ApiPolicyPage from '../pages/api-policy/ApiPolicyPage'
import SecurityEventsPage from '../pages/security-events/SecurityEventsPage'
import AccessLogsPage from '../pages/access-logs/AccessLogsPage'
import EventStatisticsPage from '../pages/event-statistics/EventStatisticsPage'
import SecurityOverviewPage from '../pages/security-overview/SecurityOverviewPage'
import AnalyticsPage from '../pages/analytics/AnalyticsPage'
import SystemAlertsPage from '../pages/system-alerts/SystemAlertsPage'
import ReportsPage from '../pages/reports/ReportsPage'
import ReportTemplatesPage from '../pages/report-templates/ReportTemplatesPage'
import ReportArchivesPage from '../pages/report-archives/ReportArchivesPage'
import SystemMonitoringPage from '../pages/system-monitoring/SystemMonitoringPage'
import StoragePage from '../pages/storage/StoragePage'
import BackupRestorePage from '../pages/backup-restore/BackupRestorePage'
import SystemUpgradePage from '../pages/system-upgrade/SystemUpgradePage'
import DeliveryCheckPage from '../pages/delivery-check/DeliveryCheckPage'
import AssistantPage from '../pages/ai/assistant/AssistantPage'
import EventAnalysisPage from '../pages/ai/event-analysis/EventAnalysisPage'
import AttackProfilePage from '../pages/ai/attack-profile/AttackProfilePage'
import AttackChainPage from '../pages/ai/attack-chain/AttackChainPage'
import PolicyRecommendationPage from '../pages/ai/policy-recommendation/PolicyRecommendationPage'
import ReportSummaryPage from '../pages/ai/report-summary/ReportSummaryPage'
import AiTasksPage from '../pages/ai/tasks/AiTasksPage'
import NoiseReductionPage from '../pages/ai/noise-reduction/NoiseReductionPage'
import AiModelsPage from '../pages/ai/admin/models/AiModelsPage'
import AiAgentsPage from '../pages/ai/admin/agents/AiAgentsPage'
import AiToolsPage from '../pages/ai/admin/tools/AiToolsPage'
import AiPromptsPage from '../pages/ai/admin/prompts/AiPromptsPage'
import AiMemoriesPage from '../pages/ai/admin/memories/AiMemoriesPage'
import AiUsagePage from '../pages/ai/admin/usage/AiUsagePage'
import AiAuditsPage from '../pages/ai/admin/audits/AiAuditsPage'
import AiEvaluationsPage from '../pages/ai/admin/evaluations/AiEvaluationsPage'
import { ForbiddenPage, NotFoundPage, ServerErrorPage } from '../pages/errors'

function FullScreenLoading() {
  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <Spin size="large" tip="加载中..." />
    </div>
  )
}

/** 登录守卫：未初始化完成先 Loading；未登录跳登录页；强制改密跳改密页 */
function RequireAuth({ children }: { children: ReactNode }) {
  const { user, initialized } = useAuthStore()
  const location = useLocation()
  if (!initialized) return <FullScreenLoading />
  if (!user) return <Navigate to="/login" state={{ from: location.pathname }} replace />
  if (user.must_change_password && location.pathname !== '/change-password') {
    return <Navigate to="/change-password" replace />
  }
  return <>{children}</>
}

/** 权限守卫：无权限跳 403；传入数组时表示拥有任一权限即可 */
function RequirePermission({ permission, children }: { permission: string | string[]; children: ReactNode }) {
  const user = useAuthStore((s) => s.user)
  const codes = Array.isArray(permission) ? permission : [permission]
  if (!hasAnyPermission(user?.permissions, codes)) {
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
        path="/"
        element={
          <RequireAuth>
            <AdminLayout />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
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
            <RequirePermission permission="protection_policies.read">
              <ProtectionPoliciesPage />
            </RequirePermission>
          }
        />
        <Route
          path="waf-rules"
          element={
            <RequirePermission permission="waf_rules.read">
              <WafRulesPage />
            </RequirePermission>
          }
        />
        <Route
          path="custom-rules"
          element={
            <RequirePermission permission="custom_rules.manage">
              <CustomRulesPage />
            </RequirePermission>
          }
        />
        <Route
          path="exceptions"
          element={
            <RequirePermission permission="exceptions.read">
              <ExceptionsPage />
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
            <RequirePermission permission="access_rules.read">
              <AccessRulesPage />
            </RequirePermission>
          }
        />
        <Route
          path="rate-limit"
          element={
            <RequirePermission permission="rate_limits.read">
              <RateLimitPage />
            </RequirePermission>
          }
        />
        <Route
          path="temporary-blocks"
          element={
            <RequirePermission permission="temporary_blocks.read">
              <TemporaryBlocksPage />
            </RequirePermission>
          }
        />
        <Route
          path="access-control-events"
          element={
            <RequirePermission permission="access_control_events.read">
              <AccessControlEventsPage />
            </RequirePermission>
          }
        />
        <Route
          path="access-control-versions"
          element={
            <RequirePermission
              permission={['access_control_versions.read', 'access_control_versions.rollback']}
            >
              <AccessControlVersionsPage />
            </RequirePermission>
          }
        />
        <Route
          path="api-endpoints"
          element={
            <RequireAPIDynamicProtection>
              <RequirePermission permission={['api_asset.read', 'api_asset.confirm', 'api_asset.edit']}>
                <ApiEndpointsPage />
              </RequirePermission>
            </RequireAPIDynamicProtection>
          }
        />
        <Route
          path="api-models"
          element={
            <RequireAPIDynamicProtection>
              <RequirePermission permission={['api_model.read', 'api_model.edit']}>
                <ApiModelsPage />
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
            <RequirePermission permission={['analytics.security.read', 'analytics.disposition.read']}>
              <AnalyticsPage />
            </RequirePermission>
          }
        />
        <Route
          path="system-alerts"
          element={
            <RequirePermission
              permission={['system_alerts.read', 'system_alerts.read_security', 'system_alerts.read_audit']}
            >
              <SystemAlertsPage />
            </RequirePermission>
          }
        />
        <Route
          path="reports"
          element={
            <RequirePermission permission={['reports.read', 'reports.read_audit']}>
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
            <RequirePermission permission={['reports.read', 'reports.read_audit']}>
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
          path="delivery-check"
          element={
            <RequirePermission permission="delivery_checks.read">
              <DeliveryCheckPage />
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
            <RequirePermission permission={['ai.report_summary.use', 'ai.root_cause.use']}>
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
            <RequirePermission permission={['ai.noise_reduction.use', 'ai.noise_reduction.manage']}>
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
            <RequirePermission permission={['ai.evaluations.run', 'ai.usage.read', 'ai.audits.read']}>
              <AiEvaluationsPage />
            </RequirePermission>
          }
        />
      </Route>
      <Route path="/403" element={<ForbiddenPage />} />
      <Route path="/500" element={<ServerErrorPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}
