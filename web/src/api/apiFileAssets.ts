import { request } from './client'
import type { ApiFileLineageItem } from './apiFileSignature'
import type { PageResult } from '../types'

export interface ApiFileAsset extends ApiFileLineageItem {
  endpoint_id?: string | null
  extension: string
  mime: string
  size_bytes: number
  sha256?: string | null
  identity_fingerprint: string
  client_ip_masked: string
  sensitive_types: string[]
  first_seen: string
  created_at: string
  updated_at: string
}

export interface ApiFileAssetStats {
  days: number
  summary: {
    upload_assets: number
    download_assets: number
    upload_transfers: number
    download_transfers: number
    sensitive_file_count: number
  }
}

export interface ApiFileAssetListParams {
  days: number
  direction?: 'UPLOAD' | 'DOWNLOAD'
  mime?: string
  extension?: string
  endpoint_key?: string
  sha256?: string
  identity_fingerprint?: string
  sensitive_only?: boolean
  page: number
  page_size: number
}

export const apiFileAssetsApi = {
  list: (params: ApiFileAssetListParams) =>
    request<PageResult<ApiFileAsset>>('/api-security/file-assets', {
      query: { ...params },
    }),
  stats: (days: number) =>
    request<ApiFileAssetStats>('/api-security/file-assets/stats', {
      query: { days },
    }),
}
