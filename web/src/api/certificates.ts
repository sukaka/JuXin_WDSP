import { request } from './client'
import type { CertificateDetail, CertificateItem, PageResult } from '../types'

export interface CertificateListParams {
  name?: string
  status?: string
  include_replaced?: boolean
  page: number
  page_size: number
}

export interface UploadCertificateBody {
  name: string
  cert_pem: string
  key_pem: string
  chain_pem: string
}

export interface CertificateApplications {
  application_ids: string[]
  count: number
}

export const certificatesApi = {
  list: (params: CertificateListParams) =>
    request<PageResult<CertificateItem>>('/certificates', { query: { ...params } }),
  get: (id: string) => request<CertificateDetail>(`/certificates/${id}`),
  upload: (body: UploadCertificateBody) =>
    request<CertificateItem>('/certificates', { method: 'POST', body }),
  remove: (id: string) => request<{ message: string }>(`/certificates/${id}`, { method: 'DELETE' }),
  applications: (id: string) =>
    request<CertificateApplications>(`/certificates/${id}/applications`),
  applicationCertificate: (applicationId: string) =>
    request<{ certificate: CertificateItem | null }>(`/applications/${applicationId}/certificate`),
  bind: (certificateId: string, applicationId: string) =>
    request<{ message: string }>(`/certificates/${certificateId}/bind`, {
      method: 'POST',
      body: { application_id: applicationId },
    }),
  unbind: (certificateId: string, applicationId: string) =>
    request<{ message: string }>(`/certificates/${certificateId}/unbind`, {
      method: 'POST',
      body: { application_id: applicationId },
    }),
}
