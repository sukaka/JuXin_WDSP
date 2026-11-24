import { request } from './client'
import type {
  AcmeConfig,
  AcmeKeyType,
  AcmeOrderItem,
  AcmeProvider,
  AcmeTestResult,
  AppAutoSslStatus,
  PageResult,
} from '../types'

export interface UpdateAcmeConfigBody {
  enabled: boolean
  provider: AcmeProvider
  directory_url: string
  custom_directory_allowlist: string
  email: string
  tos_agreed: boolean
  eab_kid: string
  eab_hmac_key?: string
  clear_eab_hmac_key?: boolean
  key_type: AcmeKeyType
  renew_before_days: number
  auto_publish: boolean
  version: number
}

export interface TestAcmeConfigBody {
  provider: AcmeProvider
  directory_url: string
  custom_directory_allowlist: string
}

export interface AcmeOrderListParams {
  application_id?: string
  status?: string
  page: number
  page_size: number
}

export interface UpdateAppAutoSslBody {
  enabled: boolean
  challenge_type?: string
  renew_before_days?: number | null
}

export const acmeApi = {
  getConfig: () => request<AcmeConfig>('/certificates/acme/config'),
  updateConfig: (body: UpdateAcmeConfigBody) =>
    request<AcmeConfig>('/certificates/acme/config', { method: 'PUT', body }),
  testConfig: (body: TestAcmeConfigBody) =>
    request<AcmeTestResult>('/certificates/acme/config/test', { method: 'POST', body }),
  listOrders: (params: AcmeOrderListParams) =>
    request<PageResult<AcmeOrderItem>>('/certificates/acme/orders', { query: { ...params } }),
  renewCertificate: (certificateId: string) =>
    request<AcmeOrderItem>(`/certificates/${certificateId}/renew`, { method: 'POST' }),
  getAppAutoSsl: (applicationId: string) =>
    request<AppAutoSslStatus>(`/applications/${applicationId}/auto-ssl`),
  updateAppAutoSsl: (applicationId: string, body: UpdateAppAutoSslBody) =>
    request<AppAutoSslStatus>(`/applications/${applicationId}/auto-ssl`, { method: 'PUT', body }),
  issueAppCert: (applicationId: string) =>
    request<AcmeOrderItem>(`/applications/${applicationId}/auto-ssl/issue`, { method: 'POST' }),
}
