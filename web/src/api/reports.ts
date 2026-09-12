import { buildUrl, request } from './client'
import type { PageResult, ReportArchiveItem, ReportContentScope, ReportJobItem, ReportType } from '../types'

export interface ReportListParams {
  report_type?: string
  status?: string
  page: number
  page_size: number
}

export interface CreateReportBody {
  report_type: ReportType
  content_scope?: ReportContentScope
  include_api_assets?: boolean
  page_orientation?: 'P' | 'L'
  start_time?: string
  end_time?: string
  application_ids?: string[]
  template_id?: string
  format: 'html' | 'pdf' | 'docx'
}

/** 报告任务（reports.read / reports.create / reports.download / reports.delete_own） */
export const reportsApi = {
  list: async (params: ReportListParams) => {
    const data = await request<PageResult<ReportJobItem>>('/reports', { query: { ...params } })
    return { ...data, items: data.items ?? [] }
  },
  create: async (body: CreateReportBody) =>
    (await request<{ report: ReportJobItem }>('/reports', { method: 'POST', body })).report,
  get: async (id: string) => (await request<{ report: ReportJobItem }>(`/reports/${id}`)).report,
  retry: (id: string) => request<{ message: string }>(`/reports/${id}/retry`, { method: 'POST' }),
  /**
   * 预览：HTML 报告返回原始 HTML 文本（非 JSON 信封），渲染时用 srcDoc 注入 sandbox iframe；
   * PDF 报告后端返回提示 JSON，请使用下载接口。
   */
  preview: (id: string) => request<string>(`/reports/${id}/preview`, { rawText: true }),
  /** 下载地址（浏览器直接打开，携带会话 Cookie，后端记录下载审计） */
  downloadUrl: (id: string) => buildUrl(`/reports/${id}/download`),
  remove: (id: string) => request<{ message: string }>(`/reports/${id}`, { method: 'DELETE' }),
}

export interface ReportArchiveListParams {
  page: number
  page_size: number
}

/** 报告归档（只读，引用报告编号） */
export const reportArchivesApi = {
  list: async (params: ReportArchiveListParams) => {
    const data = await request<PageResult<ReportArchiveItem>>('/report-archives', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
}
