import type { ReactNode } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { Spin } from 'antd'
import { useAuthStore } from '../stores/auth'
import { hasPermission } from '../utils/permission'
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

/** 权限守卫：无权限跳 403 */
function RequirePermission({ permission, children }: { permission: string; children: ReactNode }) {
  const user = useAuthStore((s) => s.user)
  if (!hasPermission(user?.permissions, permission)) {
    return <Navigate to="/403" replace />
  }
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
      </Route>
      <Route path="/403" element={<ForbiddenPage />} />
      <Route path="/500" element={<ServerErrorPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  )
}
