import { create } from 'zustand'
import { setCsrfToken as syncClientCsrfToken } from '../api/client'
import type { CurrentUser } from '../types'

interface AuthState {
  /** 当前登录用户；null 表示未登录 */
  user: CurrentUser | null
  /** CSRF Token（仅内存） */
  csrfToken: string | null
  /** 是否已完成 /auth/me 启动探测 */
  initialized: boolean
  setSession: (user: CurrentUser, csrfToken: string) => void
  updateUser: (user: CurrentUser) => void
  setCsrfToken: (token: string) => void
  reset: () => void
}

export const useAuthStore = create<AuthState>()((set) => ({
  user: null,
  csrfToken: null,
  initialized: false,
  setSession: (user, csrfToken) => {
    syncClientCsrfToken(csrfToken)
    set({ user, csrfToken, initialized: true })
  },
  updateUser: (user) => set({ user }),
  setCsrfToken: (token) => {
    syncClientCsrfToken(token)
    set({ csrfToken: token })
  },
  reset: () => {
    syncClientCsrfToken(null)
    set({ user: null, csrfToken: null, initialized: true })
  },
}))
