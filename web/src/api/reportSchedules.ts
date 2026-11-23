import { request } from './client'
import type { PageResult, ReportScheduleItem, ReportScheduleType } from '../types'

export interface ReportScheduleListParams {
  page: number
  page_size: number
}

export interface SaveReportScheduleBody {
  name: string
  report_type: ReportScheduleType
  api_report_type?: string
  content_scope: string
  application_ids?: string[]
  template_id?: string
  file_format: string
  include_api_assets?: boolean
  page_orientation?: 'P' | 'L'
  time_of_day: string
  day_of_week: number
  day_of_month: number
  send_email: boolean
  emails?: string[]
  enabled: boolean
}

/** 定时报告计划（reports.read / reports.create） */
export const reportSchedulesApi = {
  list: async (params: ReportScheduleListParams) => {
    const data = await request<PageResult<ReportScheduleItem>>(
      '/report-schedules',
      { query: { ...params } },
    )
    return { ...data, items: data.items ?? [] }
  },
  create: async (body: SaveReportScheduleBody) =>
    (
      await request<{ schedule: ReportScheduleItem }>('/report-schedules', {
        method: 'POST',
        body,
      })
    ).schedule,
  update: (id: string, body: SaveReportScheduleBody) =>
    request<{ message: string }>(`/report-schedules/${id}`, {
      method: 'PUT',
      body,
    }),
  remove: (id: string) =>
    request<{ message: string }>(`/report-schedules/${id}`, {
      method: 'DELETE',
    }),
  runNow: (id: string) =>
    request<{ message: string }>(`/report-schedules/${id}/run-now`, {
      method: 'POST',
    }),
}
