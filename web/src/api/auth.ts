import { request } from './client'
import type {
  CaptchaData,
  HealthStatus,
  LoginResult,
  MeResult,
  SessionItem,
} from '../types'

export interface LoginBody {
  username: string
  password: string
  captcha_id?: string
  captcha_code?: string
}

export interface ChangePasswordBody {
  old_password: string
  new_password: string
}

export const authApi = {
  captcha: () => request<CaptchaData>('/auth/captcha'),
  login: (body: LoginBody) => request<LoginResult>('/auth/login', { method: 'POST', body }),
  logout: () => request<null>('/auth/logout', { method: 'POST' }),
  me: () => request<MeResult>('/auth/me'),
  changePassword: (body: ChangePasswordBody) =>
    request<{ message: string; relogin_required: boolean }>('/auth/change-password', {
      method: 'POST',
      body,
    }),
  sessions: () => request<{ items: SessionItem[] }>('/auth/sessions'),
  revokeSession: (id: string) => request<null>(`/auth/sessions/${id}`, { method: 'DELETE' }),
  /** /health 不是统一信封格式，使用 raw 模式 */
  health: () => request<HealthStatus>('/health', { raw: true }),
}
