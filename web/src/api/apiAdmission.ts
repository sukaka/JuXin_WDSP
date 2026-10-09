import { request } from './client'
import type { ApiAdmissionCoverage, ApiAdmissionDeniedItem, PageResult } from '../types'

/**
 * API 准入防护（docs/API_ADMISSION_CONTROL_DESIGN.md §5.2/§5.3）。
 * 覆盖率与拦截列表均按应用维度；确认/忽略复用 apiEndpointsApi（api_asset.confirm/ignore）。
 */
export const apiAdmissionApi = {
  /** 覆盖率与影响面报告：hits_window 为命中统计窗口（小时，1–2160，缺省 168） */
  coverage: async (params: { application_id: string; hits_window: number }) => {
    const data = await request<ApiAdmissionCoverage>('/api-security/admission/coverage', {
      query: { ...params },
    })
    return { ...data, unconfirmed_hot: data.unconfirmed_hot ?? [] }
  },
  /** 准入拦截列表：窗口内 PROTECT 拦截的端点聚合（分页） */
  denied: async (params: {
    application_id: string
    hits_window: number
    page: number
    page_size: number
  }) => {
    const data = await request<PageResult<ApiAdmissionDeniedItem>>('/api-security/admission/denied', {
      query: { ...params },
    })
    return {
      ...data,
      items: (data.items ?? []).map((item) => ({
        ...item,
        sample_client_ips: item.sample_client_ips ?? [],
      })),
    }
  },
}
