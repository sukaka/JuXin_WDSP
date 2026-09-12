import { request } from './client'
import type {
  BusinessSnapshot,
  ConfigVersionItem,
  GatewayStatusData,
  PageResult,
  PublishTaskItem,
} from '../types'

export interface PreviewResult {
  configuration_hash: string
  server_count: number
  route_count: number
  /** preview 响应中为对象（与 version/diff 中的 JSON 字符串不同） */
  business_snapshot: BusinessSnapshot
  config_preview: string
}

export interface ValidateResult {
  valid: boolean
  error?: string
  configuration_hash?: string
  server_count?: number
  route_count?: number
  business_snapshot?: BusinessSnapshot
}

export interface PublishBody {
  idempotency_key?: string
  app_ids?: string[]
}

export interface CurrentVersionResult {
  has_current: boolean
  version?: ConfigVersionItem
}

export interface DiffResult {
  target_version: ConfigVersionItem
  current_version_number: string
  current_hash: string
  target_hash: string
  same: boolean
  /** JSON 字符串，内容为 BusinessSnapshot */
  business_snapshot: string
}

export const gatewayConfigApi = {
  preview: () => request<PreviewResult>('/gateway-config/preview', { method: 'POST' }),
  validate: () => request<ValidateResult>('/gateway-config/validate', { method: 'POST' }),
  publish: (body: PublishBody) =>
    request<PublishTaskItem>('/gateway-config/publish', { method: 'POST', body }),
  current: () => request<CurrentVersionResult>('/gateway-config/current'),
}

export const publishTasksApi = {
  list: (params: { status?: string; page: number; page_size: number }) =>
    request<PageResult<PublishTaskItem>>('/publish-tasks', { query: { ...params } }),
  get: (id: string) => request<PublishTaskItem>(`/publish-tasks/${id}`),
}

export const configVersionsApi = {
  list: (params: { page: number; page_size: number }) =>
    request<PageResult<ConfigVersionItem>>('/config-versions', { query: { ...params } }),
  get: (id: string) => request<ConfigVersionItem>(`/config-versions/${id}`),
  diff: (id: string) => request<DiffResult>(`/config-versions/${id}/diff`),
  rollback: (id: string) =>
    request<PublishTaskItem>(`/config-versions/${id}/rollback`, { method: 'POST' }),
}

export const gatewayApi = {
  status: () => request<GatewayStatusData>('/gateway/status'),
}
