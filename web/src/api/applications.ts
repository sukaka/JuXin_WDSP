import { request } from './client'
import type {
  ApiAdmissionMode,
  AppHeaderConfig,
  AppHeaderConfigResult,
  AppPathRoute,
  AppTLSConfig,
  AppTLSConfigResult,
  ApplicationDetail,
  ApplicationItem,
  DeploymentMode,
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
  deployment_mode?: string
  page: number
  page_size: number
}

export interface CreateApplicationBody {
  /** 应用标识（可选；留空由服务端自动生成唯一标识） */
  code?: string
  name: string
  description: string
  business_owner: string
  technical_owner: string
  protection_mode: ProtectionMode
  deployment_mode?: DeploymentMode
}

export interface UpdateApplicationBody {
  name: string
  description: string
  business_owner: string
  technical_owner: string
  protection_mode: ProtectionMode
  deployment_mode?: DeploymentMode
  /** API 准入模式（不携带则不改变现状；准入面板切换模式时随整包更新提交） */
  api_admission_mode?: ApiAdmissionMode
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
  /** 域名级防护策略 ID：UUID=绑定该策略，null=清除并继承应用策略，省略=保持原值不变 */
  policy_id?: string | null
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
}

export const applicationsApi = {
  list: (params: ApplicationListParams) =>
    request<PageResult<ApplicationItem>>('/applications', { query: { ...params } }),
  // 后端对无域名/源站的应用返回 null（Go nil slice），统一归一化为空数组
  get: async (id: string) => {
    const data = await request<ApplicationDetail>(`/applications/${id}`)
    return { ...data, domains: data.domains ?? [], upstreams: data.upstreams ?? [] }
  },
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
  list: async (appId: string) => {
    const data = await request<{ items: DomainItem[] | null }>(`/applications/${appId}/domains`)
    return { ...data, items: data.items ?? [] }
  },
  create: (appId: string, body: DomainBody) =>
    request<DomainItem>(`/applications/${appId}/domains`, { method: 'POST', body }),
  update: (appId: string, domainId: string, body: DomainBody) =>
    request<DomainItem>(`/applications/${appId}/domains/${domainId}`, { method: 'PUT', body }),
  remove: (appId: string, domainId: string) =>
    request<{ message: string }>(`/applications/${appId}/domains/${domainId}`, { method: 'DELETE' }),
}

export const upstreamsApi = {
  list: async (appId: string) => {
    const data = await request<{ items: UpstreamItem[] | null }>(`/applications/${appId}/upstreams`)
    return { ...data, items: data.items ?? [] }
  },
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

export interface UpdateHeaderConfigBody extends AppHeaderConfig {
  version: number
}

export interface PathRouteBody {
  path_prefix: string
  upstream_scheme: string
  upstream_host: string
  upstream_port: number
  strip_prefix: boolean
  priority: number
  status: string
  description: string
}

export interface UpdatePathRouteBody extends PathRouteBody {
  version: number
}

export interface PathRouteMutationResult {
  route: AppPathRoute
  message: string
}

export interface PathRouteListParams {
  page: number
  page_size: number
}

export const headerConfigApi = {
  get: (appId: string) =>
    request<AppHeaderConfigResult>(`/applications/${appId}/header-config`),
  update: (appId: string, body: UpdateHeaderConfigBody) =>
    request<AppHeaderConfigResult>(`/applications/${appId}/header-config`, { method: 'PUT', body }),
}

export interface UpdateTLSConfigBody extends AppTLSConfig {
  version: number
}

export const tlsConfigApi = {
  get: (appId: string) =>
    request<AppTLSConfigResult>(`/applications/${appId}/tls-config`),
  update: (appId: string, body: UpdateTLSConfigBody) =>
    request<AppTLSConfigResult>(`/applications/${appId}/tls-config`, { method: 'PUT', body }),
}

export const pathRoutesApi = {
  list: (appId: string, params: PathRouteListParams) =>
    request<PageResult<AppPathRoute>>(`/applications/${appId}/path-routes`, { query: { ...params } }),
  create: (appId: string, body: PathRouteBody) =>
    request<PathRouteMutationResult>(`/applications/${appId}/path-routes`, { method: 'POST', body }),
  update: (appId: string, routeId: string, body: UpdatePathRouteBody) =>
    request<PathRouteMutationResult>(`/applications/${appId}/path-routes/${routeId}`, { method: 'PATCH', body }),
  remove: (appId: string, routeId: string) =>
    request<{ message: string }>(`/applications/${appId}/path-routes/${routeId}`, { method: 'DELETE' }),
}
