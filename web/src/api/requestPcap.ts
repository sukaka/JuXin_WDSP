import { buildUrl, request } from './client'

export type RequestPcapIntegrity = 'UNVERIFIED' | 'PASS' | 'FAILED' | 'KEY_UNAVAILABLE'

export interface RequestPcapItem {
  artifact_id: string
  gateway_node_id: string
  capture_point: string
  state: string
  storage_tier: 'HOT' | 'WARM'
  capture_started_at: string
  capture_ended_at: string
  packet_count: number
  dropped_count: number
  truncated: boolean
  plaintext_size_bytes: number
  ciphertext_size_bytes: number
  plaintext_sha256: string
  ciphertext_sha256: string
  expires_at: string
  integrity_status: RequestPcapIntegrity
  last_verified_at?: string | null
  verification_error_code?: string
  match_status: 'PENDING' | 'UNMATCHED' | 'FAILED' | 'AMBIGUOUS' | 'MATCHED'
  match_basis: string
  coverage: 'REQUEST' | 'CONNECTION' | 'UNKNOWN'
  candidate_count: number
  first_packet_no?: number | null
  last_packet_no?: number | null
  download_eligible: boolean
  download_blocked_reason?: string
}

export interface RequestPcapLookup {
  request_id: string
  items: RequestPcapItem[]
  truncated?: boolean
}

export interface RequestPcapGrant {
  grant_id: string
  expires_at: string
  artifact_id: string
  request_id: string
}

export const requestPcapApi = {
  lookup: async (requestId: string) => {
    const result = await request<RequestPcapLookup>('/request-pcap/lookup', { query: { request_id: requestId } })
    return { ...result, items: result.items ?? [] }
  },
  verify: (artifactId: string, requestId: string, reason: string) =>
    request<RequestPcapItem>(`/request-pcap/artifacts/${encodeURIComponent(artifactId)}/verify`, {
      method: 'POST', body: { request_id: requestId, reason },
    }),
  createGrant: (artifactId: string, requestId: string, reason: string, password: string) =>
    request<RequestPcapGrant>(`/request-pcap/artifacts/${encodeURIComponent(artifactId)}/download-grants`, {
      method: 'POST', body: { request_id: requestId, reason, password },
    }),
  downloadUrl: (grant: RequestPcapGrant) =>
    buildUrl(`/request-pcap/artifacts/${encodeURIComponent(grant.artifact_id)}/download`, {
      request_id: grant.request_id, grant_id: grant.grant_id,
    }),
}
