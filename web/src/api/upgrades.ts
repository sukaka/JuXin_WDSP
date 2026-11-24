import { request, upload, type UploadProgress } from './client'
import { summarizeCheckResult } from '../utils/stage6'
import type {
  PageResult,
  UpgradeClusterMode,
  UpgradeClusterNodesResult,
  UpgradeJobItem,
  UpgradeNodeExecution,
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

/** 升级包登记/上传响应（data 为 {package} 包装；登记校验未通过时带 message 说明） */
export interface UpgradePackageResp {
  package: UpgradePackageItem
  message?: string
  /** 上传专用：校验通过且已创建升级任务时为升级任务（立即升级为执行态；定时升级为 SCHEDULED 并携带 scheduled_at）；null 表示未自动执行（原因见 warning） */
  execution?: UpgradeJobItem | null
  /** 上传专用：execution 为 null 时说明未自动开始升级的原因（如已有执行中任务） */
  warning?: string
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
  /** 集群节点升级版本与就绪度总览（GET /upgrades/nodes） */
  listClusterNodes: async (): Promise<UpgradeClusterNodesResult> => {
    const data = await request<UpgradeClusterNodesResult>('/upgrades/nodes')
    return { ...data, items: data.items ?? [] }
  },
  list: async (params: UpgradeListParams) => {
    const data = await request<PageResult<UpgradeJobItem>>('/upgrades', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  /** 升级包分页列表 */
  listPackages: async (params: UpgradeListParams) => {
    const data = await request<PageResult<UpgradePackageItem>>('/upgrade-packages', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  /**
   * 上传升级包：multipart 携带 file；scheduledAt（RFC3339 带时区）存在时创建定时升级任务
   * （execution.status 为 SCHEDULED），缺省立即开始升级（upgrades.execute）；
   * clusterMode 为 HA_ROLLING 时启用先备后主滚动升级。
   */
  uploadPackage: (
    file: File,
    scheduledAt?: string,
    onProgress?: (progress: UploadProgress) => void,
    clusterMode?: UpgradeClusterMode,
  ) => {
    const form = new FormData()
    form.append('file', file)
    if (scheduledAt) form.append('scheduled_at', scheduledAt)
    if (clusterMode === 'HA_ROLLING') form.append('cluster_mode', clusterMode)
    return upload<UpgradePackageResp>('/upgrades/packages/upload', form, { onProgress })
  },
  /** 登记升级包元数据（文件经离线介质拷贝到服务端升级包目录） */
  registerPackage: (body: RegisterUpgradePackageBody) =>
    request<UpgradePackageResp>('/upgrades/packages', { method: 'POST', body }),
  precheck: async (
    packageId: string,
    clusterMode?: UpgradeClusterMode,
  ): Promise<UpgradePrecheckResult> => {
    const body: Record<string, unknown> = { package_id: packageId }
    if (clusterMode) body.cluster_mode = clusterMode
    const data = await request<PrecheckRawResp>('/upgrades/precheck', {
      method: 'POST',
      body,
    })
    const items = data.precheck ?? []
    return { package_id: packageId, overall_result: summarizeCheckResult(items), items }
  },
  /** 执行升级（可选 cluster_mode: LOCAL | HA_ROLLING） */
  execute: async (packageId: string, clusterMode?: UpgradeClusterMode) => {
    const body: Record<string, unknown> = { package_id: packageId }
    if (clusterMode) body.cluster_mode = clusterMode
    const data = await request<{ job: UpgradeJobItem }>('/upgrades', { method: 'POST', body })
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
  /** 取消定时升级任务（仅 SCHEDULED 状态可取消；已开始的任务服务端返回 409） */
  cancelUpgrade: async (id: string) => {
    const data = await request<{ job: UpgradeJobItem }>(`/upgrades/${id}/cancel`, { method: 'POST' })
    return data.job
  },
  /** 重试单个失败/跳过的备节点升级（POST /upgrades/{id}/retry-node） */
  retryNode: async (jobId: string, nodeId: string): Promise<UpgradeNodeExecution> => {
    const data = await request<{ node_execution: UpgradeNodeExecution }>(
      `/upgrades/${jobId}/retry-node`,
      {
        method: 'POST',
        body: { node_id: nodeId },
      },
    )
    return data.node_execution
  },
}
