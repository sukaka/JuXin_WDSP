import { request } from './client'
import type {
  CaptchaData,
  HealthStatus,
  LoginResponse,
  LoginResult,
  MeResult,
  SessionItem,
  TotpSetupData,
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

export interface TotpVerifyBody {
  challenge_token: string
  /** 6 位动态令牌码，或一次性恢复码（xxxx-xxxx） */
  code: string
}

export interface TotpCodeBody {
  /** 6 位动态令牌码；关闭双因子时也可使用恢复码 */
  code: string
}

export const authApi = {
  captcha: () => request<CaptchaData>('/auth/captcha'),
  login: (body: LoginBody) =>
    // TOTP_REQUIRED（已开启双因子、待第二步验证）为 HTTP 200 的业务分支，按成功解包
    request<LoginResponse>('/auth/login', { method: 'POST', body, branchCodes: ['TOTP_REQUIRED'] }),
  logout: () => request<null>('/auth/logout', { method: 'POST' }),
  me: () => request<MeResult>('/auth/me'),
  changePassword: (body: ChangePasswordBody) =>
    request<{ message: string; relogin_required: boolean }>('/auth/change-password', {
      method: 'POST',
      body,
    }),
  /** 登录第二步：challenge_token（5 分钟有效、一次性）+ 动态令牌/恢复码 */
  totpVerify: (body: TotpVerifyBody) =>
    request<LoginResult>('/auth/totp-verify', { method: 'POST', body }),
  /** 生成待启用 TOTP 密钥与恢复码；重复调用覆盖旧的待启用密钥 */
  totpSetup: () => request<TotpSetupData>('/auth/totp/setup', { method: 'POST' }),
  /** 用待启用密钥验证动态码，通过才正式启用双因子 */
  totpEnable: (body: TotpCodeBody) => request<null>('/auth/totp/enable', { method: 'POST', body }),
  /** 验证动态码/恢复码后关闭双因子并清除密钥与恢复码 */
  totpDisable: (body: TotpCodeBody) =>
    request<null>('/auth/totp/disable', { method: 'POST', body }),
  sessions: () => request<{ items: SessionItem[] }>('/auth/sessions'),
  revokeSession: (id: string) => request<null>(`/auth/sessions/${id}`, { method: 'DELETE' }),
  /** /health 不是统一信封格式，使用 raw 模式 */
  health: () => request<HealthStatus>('/health', { raw: true }),
}
