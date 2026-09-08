import { request } from './client'
import type { PageResult } from '../types'

/* ==================== 站点资产发现（docs/SITE_DISCOVERY_DESIGN.md §4.4）：流量学习站点清单 ==================== */

/** 处置状态机：NEW→CONFIRMED；NEW/CONFIRMED→IGNORED；任意→NEW（restore） */
export type SiteDiscoveryStatus = 'NEW' | 'CONFIRMED' | 'IGNORED'
export type SiteDiscoveryProtocol = 'HTTP' | 'HTTPS'
/** 发现来源部署模式：镜像旁路/路由牵引/透明串接 */
export type SiteDiscoverySourceMode = 'MIRROR' | 'ROUTED' | 'TRANSPARENT'

/** 站点发现条目（与 server/internal/sitediscovery 响应字段一致） */
export interface SiteDiscoveryItem {
  id: string
  /** 识别到的域名；空串表示未识别（如无 SNI 的 TLS 握手） */
  domain: string
  /** 源站 IP */
  ip: string
  /** 源站端口 */
  port: number
  protocol: SiteDiscoveryProtocol
  /** 发现来源部署模式 */
  source_mode: SiteDiscoverySourceMode
  /** 发现该站点的网关节点 */
  gateway_node: string
  /** 累计命中次数（近似值） */
  seen_count: number
  /** 最近窗口去重客户端数 */
  client_count: number
  first_seen: string
  last_seen: string
  status: SiteDiscoveryStatus
  confirmed_by: string
  confirmed_at: string | null
  created_at: string
  updated_at: string
}

export interface SiteDiscoveryListParams {
  page: number
  page_size: number
  status?: SiteDiscoveryStatus
  protocol?: SiteDiscoveryProtocol
  source_mode?: SiteDiscoverySourceMode
  /** 域名或 IP 模糊匹配 */
  keyword?: string
}

export const siteDiscoveryApi = {
  /** 站点发现分页列表（按 last_seen 倒序） */
  list: async (params: SiteDiscoveryListParams) => {
    const data = await request<PageResult<SiteDiscoveryItem>>('/site-discoveries', {
      query: { ...params },
    })
    return { ...data, items: data.items ?? [] }
  },
  /** 确认（NEW→CONFIRMED），返回更新后的条目 */
  confirm: (id: string) =>
    request<SiteDiscoveryItem>(`/site-discoveries/${id}/confirm`, { method: 'POST' }),
  /** 忽略（NEW/CONFIRMED→IGNORED），返回更新后的条目 */
  ignore: (id: string) =>
    request<SiteDiscoveryItem>(`/site-discoveries/${id}/ignore`, { method: 'POST' }),
  /** 恢复为新发现（任意→NEW，清空确认审计），返回更新后的条目 */
  restore: (id: string) =>
    request<SiteDiscoveryItem>(`/site-discoveries/${id}/restore`, { method: 'POST' }),
}
