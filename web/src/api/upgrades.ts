import { request } from './client'
import type {
  PageResult,
  UpgradeJobItem,
  UpgradePackageItem,
  UpgradePrecheckResult,
} from '../types'

export interface UpgradeListParams {
  status?: string
  page: number
  page_size: number
}

export interface RegisterUpgradePackageBody {
  file_name: string
  version_from: string
  version_to: string
  file_hash: string
  file_size: number
}

/**
 * 系统升级（upgrades.read / upgrades.precheck / upgrades.execute / upgrades.rollback）。
 * 执行升级与回滚为高危操作，页面层必须二次确认。
 */
export const upgradesApi = {
  list: async (params: UpgradeListParams) => {
    const data = await request<PageResult<UpgradeJobItem>>('/upgrades', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  /** 登记升级包元数据（文件经离线介质拷贝到服务端指定目录） */
  registerPackage: (body: RegisterUpgradePackageBody) =>
    request<UpgradePackageItem>('/upgrades/packages', { method: 'POST', body }),
  precheck: (packageId: string) =>
    request<UpgradePrecheckResult>('/upgrades/precheck', { method: 'POST', body: { package_id: packageId } }),
  /** 执行升级 */
  execute: (packageId: string) =>
    request<UpgradeJobItem>('/upgrades', { method: 'POST', body: { package_id: packageId } }),
  get: (id: string) => request<UpgradeJobItem>(`/upgrades/${id}`),
  rollback: (id: string) => request<UpgradeJobItem>(`/upgrades/${id}/rollback`, { method: 'POST' }),
}
