import { create } from 'zustand'
import { licenseApi } from '../api/license'
import type { LicenseState } from '../types'

interface LicenseStoreState {
  /** 当前授权状态；null = 尚未获取或获取失败 */
  status: LicenseState | null
  /** 是否已完成首次状态加载（授权守卫据此先 Loading 再判定） */
  initialized: boolean
  load: () => Promise<void>
  /** 导入成功后写入最新状态（导入响应即最新 State） */
  setStatus: (status: LicenseState) => void
  reset: () => void
}

export const useLicenseStore = create<LicenseStoreState>()((set) => ({
  status: null,
  initialized: false,
  load: async () => {
    try {
      const status = await licenseApi.status()
      set({ status, initialized: true })
    } catch {
      // 加载失败按未知处理（status=null）：守卫将锁定到授权管理页，
      // 后端 423 门控仍是强制点；授权页提供重试入口
      set({ status: null, initialized: true })
    }
  },
  setStatus: (status) => set({ status, initialized: true }),
  reset: () => set({ status: null, initialized: false }),
}))
