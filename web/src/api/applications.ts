import { request } from './client'
import type {
  ApplicationDetail,
  ApplicationItem,
  DomainItem,
  PageResult,
  ProtectionMode,
  UpstreamItem,
  UpstreamTestResult,
} from '../types'

export interface ApplicationListParams {
  keyword?: string
  status?: string
  protection_mode?: string
  page: number
  page_size: number
}

export interface CreateApplicationBody {
  code: string
  name: string
  description: string
  business_owner: string
  technical_owner: string
  protection_mode: ProtectionMode
}

export interface UpdateApplicationBody {
  name: string
  description: string
  business_owner: string
  technical_owner: string
  protection_mode: ProtectionMode
  version: number
}

export interface DomainBody {
  hostname: string
  is_primary: boolean
  http_enabled: boolean
  https_enabled: boolean
  http_port?: number | null
  https_port?: number | null
  redirect_http_to_https: boolean
}

export interface UpstreamBody {
  name: string
  scheme: string
  host: string
  port: number
  weight: number
  priority: number
  health_check_enabled: boolean
  health_check_path: string
  health_check_method: string
  health_check_interval_seconds: number
  health_check_timeout_seconds: number
  expected_status_codes: string
  connect_timeout_ms: number
  response_header_timeout_ms: number
  tls_server_name: string
  tls_verify: boolean
  max_retries: number
}

export interface UpdateUpstreamBody extends UpstreamBody {
  version: number
}

export interface UpstreamTestBody {
  scheme: string
  host: string
  port: number
  health_check_path: string
  tls_server_name: string
  tls_verify: boolean
  allow_private: boolean
}

export const applicationsApi = {
  list: (params: ApplicationListParams) =>
    request<PageResult<ApplicationItem>>('/applications', { query: { ...params } }),
  get: (id: string) => request<ApplicationDetail>(`/applications/${id}`),
  create: (body: CreateApplicationBody) =>
    request<ApplicationItem>('/applications', { method: 'POST', body }),
  update: (id: string, body: UpdateApplicationBody) =>
    request<ApplicationItem>(`/applications/${id}`, { method: 'PUT', body }),
  remove: (id: string) => request<{ message: string }>(`/applications/${id}`, { method: 'DELETE' }),
  enable: (id: string) =>
    request<{ message: string }>(`/applications/${id}/enable`, { method: 'POST' }),
  disable: (id: string) =>
    request<{ message: string }>(`/applications/${id}/disable`, { method: 'POST' }),
  copy: (id: string) =>
    request<ApplicationItem>(`/applications/${id}/copy`, { method: 'POST' }),
}

export const domainsApi = {
  list: (appId: string) =>
    request<{ items: DomainItem[] }>(`/applications/${appId}/domains`),
  create: (appId: string, body: DomainBody) =>
    request<DomainItem>(`/applications/${appId}/domains`, { method: 'POST', body }),
  update: (appId: string, domainId: string, body: DomainBody) =>
    request<DomainItem>(`/applications/${appId}/domains/${domainId}`, { method: 'PUT', body }),
  remove: (appId: string, domainId: string) =>
    request<{ message: string }>(`/applications/${appId}/domains/${domainId}`, { method: 'DELETE' }),
}

export const upstreamsApi = {
  list: (appId: string) =>
    request<{ items: UpstreamItem[] }>(`/applications/${appId}/upstreams`),
  create: (appId: string, body: UpstreamBody) =>
    request<UpstreamItem>(`/applications/${appId}/upstreams`, { method: 'POST', body }),
  // 更新/删除/启停为平铺路径 /upstreams/{id}
  update: (id: string, body: UpdateUpstreamBody) =>
    request<UpstreamItem>(`/upstreams/${id}`, { method: 'PUT', body }),
  remove: (id: string) => request<{ message: string }>(`/upstreams/${id}`, { method: 'DELETE' }),
  enable: (id: string) => request<{ message: string }>(`/upstreams/${id}/enable`, { method: 'POST' }),
  disable: (id: string) =>
    request<{ message: string }>(`/upstreams/${id}/disable`, { method: 'POST' }),
  test: (body: UpstreamTestBody) =>
    request<UpstreamTestResult>('/upstreams/test', { method: 'POST', body }),
}
