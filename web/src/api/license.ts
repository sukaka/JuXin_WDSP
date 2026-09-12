import { request, upload } from './client'
import type { LicenseHistoryItem, LicenseState, PageResult } from '../types'

export const licenseApi = {
  /** 授权状态（登录即可；锁定状态下也可访问） */
  status: () => request<LicenseState>('/license/status'),
  /** 导入 .lic（license.manage；multipart 字段名 file；成功返回最新授权状态） */
  import: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return upload<LicenseState>('/license/import', form)
  },
  /** 导入历史分页（license.read） */
  history: (page: number, pageSize: number) =>
    request<PageResult<LicenseHistoryItem>>('/license/history', {
      query: { page, page_size: pageSize },
    }),
}
