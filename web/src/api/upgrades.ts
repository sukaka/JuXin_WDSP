import { request, upload } from './client'
import { summarizeCheckResult } from '../utils/stage6'
import type {
  PageResult,
  UpgradeJobItem,
  UpgradePackageItem,
  UpgradePrecheckItem,
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

/** 升级包登记/上传响应（data 为 {package} 包装；校验未通过时带 message 说明） */
export interface UpgradePackageResp {
  package: UpgradePackageItem
  message?: string
}

/** 后端预检原始响应（data 为 {precheck, passed}） */
interface PrecheckRawResp {
  precheck?: UpgradePrecheckItem[] | null
  passed?: boolean
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
  /** 升级包分页列表 */
  listPackages: async (params: UpgradeListParams) => {
    const data = await request<PageResult<UpgradePackageItem>>('/upgrade-packages', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  /** 上传升级包：服务端流式落盘并自算 SHA-256/大小后登记（upgrades.execute） */
  uploadPackage: (file: File, versionFrom: string, versionTo: string) => {
    const form = new FormData()
    form.append('file', file)
    form.append('version_from', versionFrom)
    form.append('version_to', versionTo)
    return upload<UpgradePackageResp>('/upgrades/packages/upload', form)
  },
  /** 登记升级包元数据（文件经离线介质拷贝到服务端升级包目录） */
  registerPackage: (body: RegisterUpgradePackageBody) =>
    request<UpgradePackageResp>('/upgrades/packages', { method: 'POST', body }),
  precheck: async (packageId: string): Promise<UpgradePrecheckResult> => {
    const data = await request<PrecheckRawResp>('/upgrades/precheck', {
      method: 'POST',
      body: { package_id: packageId },
    })
    const items = data.precheck ?? []
    return { package_id: packageId, overall_result: summarizeCheckResult(items), items }
  },
  /** 执行升级 */
  execute: async (packageId: string) => {
    const data = await request<{ job: UpgradeJobItem }>('/upgrades', { method: 'POST', body: { package_id: packageId } })
    return data.job
  },
  get: async (id: string) => {
    const data = await request<{ job: UpgradeJobItem }>(`/upgrades/${id}`)
    return data.job
  },
  rollback: async (id: string) => {
    const data = await request<{ job: UpgradeJobItem }>(`/upgrades/${id}/rollback`, { method: 'POST' })
    return data.job
  },
}
