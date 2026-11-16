import { request } from './client'

export interface ApiFileSignatureVerifyBody {
  filename: string
  content_format: 'ooxml_zip'
  content_base64: string
  identity_fp?: string
}

export interface ApiFileSignatureVerifyResult {
  valid: boolean
  kid?: string
  signed_at?: string
  identity_fp_prefix?: string
  reason?: string
}

export interface ApiFileLineageItem {
  id: string
  direction: 'UPLOAD' | 'DOWNLOAD'
  filename: string
  identity_fingerprint: string
  client_ip_masked: string
  endpoint_key: string
  last_seen: string
  transfer_count: number
}

export interface ApiFileLineage {
  sha256: string
  days: number
  total: number
  upload_assets: number
  download_assets: number
  truncated: boolean
  items: ApiFileLineageItem[]
}

export const apiFileSignatureApi = {
  verify: (body: ApiFileSignatureVerifyBody) =>
    request<ApiFileSignatureVerifyResult>(
      '/api-security/file-signature/verify',
      {
        method: 'POST',
        body,
      },
    ),
  lineage: (sha256: string) =>
    request<ApiFileLineage>('/api-security/file-assets/lineage', {
      query: { sha256 },
    }),
}
