import { request } from './client'

/**
 * 自定义拦截页面与多版本管理客户端（迁移 000251）。
 * 权限：block_pages.read（查看/预览/历史）/ block_pages.manage（新建/编辑/回滚/删除/绑定）。
 */

export type BlockPageEditorMode = 'VISUAL' | 'HTML'
export type BlockPageScene = 'DEFAULT' | 'WAF' | 'ACCESS_CONTROL' | 'RATE_LIMIT'
export type BlockPageTheme =
  | 'classic_dark'
  | 'clean_light'
  | 'enterprise_blue'
  | 'alert_red'
  | 'amber_limit'

export const BLOCK_PAGE_LIMITS = {
  maxNameLen: 128,
  maxDescriptionLen: 512,
  maxChangeNoteLen: 512,
  maxHtmlBytes: 65536,
  maxJsonCodeBytes: 128,
  maxJsonMessageBytes: 512,
} as const

export interface VisualConfig {
  badge: string
  title: string
  subtitle?: string
  description: string
  contact_info?: string
  brand_name?: string
  logo_url?: string
  primary_color?: string
  bg_color?: string
  card_color?: string
  text_color?: string
  show_request_id: boolean
  show_timestamp: boolean
  show_client_ip: boolean
  show_domain: boolean
  show_status_code: boolean
  show_retry_after?: boolean
  footer_text?: string
}

export interface BlockPageItem {
  id: string
  name: string
  description: string
  editor_mode: BlockPageEditorMode
  theme: BlockPageTheme | string
  visual_config: VisualConfig
  html_content: string
  rendered_html: string
  status_code: number
  json_code: string
  json_message: string
  version: number
  is_builtin: boolean
  binding_count: number
  created_by: string
  updated_by: string
  created_at: string
  updated_at: string
}

export interface BlockPageVersionItem {
  id: string
  block_page_id: string
  version: number
  editor_mode: BlockPageEditorMode
  theme: BlockPageTheme | string
  visual_config: VisualConfig
  html_content: string
  rendered_html: string
  status_code: number
  json_code: string
  json_message: string
  change_note: string
  created_by: string
  created_at: string
}

export interface BlockPageBindingItem {
  id: string
  application_id: string | null
  application_code?: string
  application_name?: string
  scene: BlockPageScene
  block_page_id: string
  block_page_name: string
  block_page_latest_version: number
  pinned_version: number | null
  effective_version: number
  enabled: boolean
  updated_by: string
  created_at: string
  updated_at: string
}

export interface ThemePreset {
  key: BlockPageTheme | string
  label: string
  description: string
  bg_color: string
  card_color: string
  primary_color: string
  text_color: string
}

export interface PlaceholderInfo {
  token: string
  label: string
  description: string
  example: string
}

export interface SceneInfo {
  key: BlockPageScene
  label: string
  description: string
}

export interface BlockPageListResult {
  items: BlockPageItem[]
  total: number
  page: number
  page_size: number
  themes: ThemePreset[]
  placeholders: PlaceholderInfo[]
  scenes: SceneInfo[]
}

export interface BlockPageDetailResult {
  block_page: BlockPageItem
  versions: BlockPageVersionItem[]
  bindings: BlockPageBindingItem[]
}

export interface CreateBlockPageBody {
  name: string
  description?: string
  editor_mode?: BlockPageEditorMode
  theme?: string
  visual_config?: VisualConfig
  html_content?: string
  status_code?: number
  json_code?: string
  json_message?: string
  change_note?: string
  clone_from_id?: string
  clone_from_version?: number
}

export interface UpdateBlockPageBody {
  expected_version: number
  name: string
  description?: string
  editor_mode: BlockPageEditorMode
  theme?: string
  visual_config?: VisualConfig
  html_content?: string
  status_code?: number
  json_code?: string
  json_message?: string
  change_note?: string
}

export interface RollbackBlockPageBody {
  expected_version: number
  target_version: number
  change_note?: string
}

export interface PreviewBlockPageBody {
  block_page_id?: string
  version?: number
  editor_mode?: BlockPageEditorMode
  theme?: string
  visual_config?: VisualConfig
  html_content?: string
  status_code?: number
  scene?: BlockPageScene
  sample_domain?: string
  sample_path?: string
  sample_ip?: string
  sample_app_code?: string
}

export interface PreviewBlockPageResult {
  rendered_html: string
  sanitized_template_html: string
  warnings?: string[]
  byte_size: number
  max_bytes: number
  effective_status_code: number
}

export interface UpsertBlockPageBindingBody {
  application_id?: string | null
  scene: BlockPageScene
  block_page_id: string
  pinned_version?: number | null
  enabled?: boolean
}

export const DEFAULT_VISUAL_CONFIG: VisualConfig = {
  badge: '安全拦截',
  title: '请求已被安全策略阻断',
  subtitle: 'Security Policy Enforcement',
  description:
    '您发起的请求触发了本站的安全防护策略，已被拦截。如果您认为这是误判，请记录下方信息并联系系统管理员处理。',
  contact_info: '请联系您的系统管理员，并提供请求编号与发生时间，以便快速定位和处理。',
  brand_name: '九章WEB应用智能防护系统',
  logo_url: '',
  primary_color: '',
  bg_color: '',
  card_color: '',
  text_color: '',
  show_request_id: true,
  show_timestamp: true,
  show_client_ip: true,
  show_domain: true,
  show_status_code: true,
  show_retry_after: false,
  footer_text: '',
}

export const blockPagesApi = {
  list: async (params?: {
    keyword?: string
    editor_mode?: string
    page?: number
    page_size?: number
  }) => {
    const data = await request<BlockPageListResult>('/block-pages', {
      query: { ...params },
    })
    return {
      ...data,
      items: data.items ?? [],
      themes: data.themes ?? [],
      placeholders: data.placeholders ?? [],
      scenes: data.scenes ?? [],
    }
  },
  get: async (id: string) => {
    const data = await request<BlockPageDetailResult>(`/block-pages/${id}`)
    return {
      ...data,
      versions: data.versions ?? [],
      bindings: data.bindings ?? [],
    }
  },
  create: (body: CreateBlockPageBody) =>
    request<{
      block_page: BlockPageItem
      version: BlockPageVersionItem
      warnings?: string[]
    }>('/block-pages', { method: 'POST', body }),
  update: (id: string, body: UpdateBlockPageBody) =>
    request<{
      block_page: BlockPageItem
      version: BlockPageVersionItem
      warnings?: string[]
    }>(`/block-pages/${id}`, { method: 'PUT', body }),
  rollback: (id: string, body: RollbackBlockPageBody) =>
    request<{
      block_page: BlockPageItem
      version: BlockPageVersionItem
    }>(`/block-pages/${id}/rollback`, { method: 'POST', body }),
  remove: (id: string) =>
    request<{ deleted: boolean; id: string }>(`/block-pages/${id}`, {
      method: 'DELETE',
    }),
  preview: (body: PreviewBlockPageBody) =>
    request<PreviewBlockPageResult>('/block-pages/preview', {
      method: 'POST',
      body,
    }),
  listBindings: async (params?: { application_id?: string; scene?: string }) => {
    const data = await request<{ items: BlockPageBindingItem[] | null }>(
      '/block-pages/bindings',
      { query: { ...params } },
    )
    return { items: data.items ?? [] }
  },
  upsertBinding: (body: UpsertBlockPageBindingBody) =>
    request<{ binding: BlockPageBindingItem }>('/block-pages/bindings', {
      method: 'PUT',
      body,
    }),
  deleteBinding: (id: string) =>
    request<{ deleted: boolean; id: string }>(`/block-pages/bindings/${id}`, {
      method: 'DELETE',
    }),
}
