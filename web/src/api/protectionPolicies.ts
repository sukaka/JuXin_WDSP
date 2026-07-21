import { request } from './client'
import type { PageResult, ProtectionMode, ProtectionPolicyDetail, ProtectionPolicyItem } from '../types'

export interface ProtectionPolicyListParams {
  keyword?: string
  protection_mode?: string
  page: number
  page_size: number
}

export interface CreateProtectionPolicyBody {
  code: string
  name: string
  description: string
  protection_mode: ProtectionMode
  paranoia_level: number
  inbound_anomaly_threshold: number
  outbound_anomaly_threshold: number
  request_body_access: boolean
  response_body_access: boolean
}

export interface UpdateProtectionPolicyBody extends Omit<CreateProtectionPolicyBody, 'code'> {
  version: number
}

export const protectionPoliciesApi = {
  list: async (params: ProtectionPolicyListParams) => {
    const data = await request<PageResult<ProtectionPolicyItem>>('/protection-policies', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  get: (id: string) => request<ProtectionPolicyDetail>(`/protection-policies/${id}`),
  create: (body: CreateProtectionPolicyBody) =>
    request<ProtectionPolicyItem>('/protection-policies', { method: 'POST', body }),
  update: (id: string, body: UpdateProtectionPolicyBody) =>
    request<ProtectionPolicyItem>(`/protection-policies/${id}`, { method: 'PUT', body }),
  remove: (id: string) =>
    request<{ message: string }>(`/protection-policies/${id}`, { method: 'DELETE' }),
  copy: (id: string) =>
    request<ProtectionPolicyItem>(`/protection-policies/${id}/copy`, { method: 'POST' }),
  applications: (id: string) =>
    request<{ application_ids: string[]; count: number }>(`/protection-policies/${id}/applications`),
}
