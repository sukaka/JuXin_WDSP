import { request } from './client'
import type { PageResult, ReportTemplateItem } from '../types'

export interface ReportTemplateBody {
  name: string
  company_name: string
  product_name: string
  logo_text: string
  header_text: string
  footer_text: string
  report_no_format: string
  prepared_by: string
  reviewed_by: string
  description: string
  /** 章节开关：key 为章节标识，true 为纳入报告 */
  sections: Record<string, boolean>
}

/** 报告模板（读：reports.read 等；写：report_templates.manage；内置模板禁止修改/删除） */
export const reportTemplatesApi = {
  list: async (params: { page: number; page_size: number }) => {
    const data = await request<PageResult<ReportTemplateItem>>('/report-templates', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  create: async (body: ReportTemplateBody) =>
    (await request<{ template: ReportTemplateItem }>('/report-templates', { method: 'POST', body })).template,
  get: async (id: string) =>
    (await request<{ template: ReportTemplateItem }>(`/report-templates/${id}`)).template,
  update: (id: string, body: ReportTemplateBody) =>
    request<{ message: string }>(`/report-templates/${id}`, { method: 'PUT', body }),
  remove: (id: string) => request<{ message: string }>(`/report-templates/${id}`, { method: 'DELETE' }),
}
