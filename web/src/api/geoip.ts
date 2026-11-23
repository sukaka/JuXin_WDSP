import { request } from './client'
import type { IPGeoInfo } from '../types'

export interface GeoLookupOneResponse {
  geo: IPGeoInfo
  geo_enabled: boolean
  sources: string[]
}

export interface GeoLookupBatchResponse {
  items: Record<string, IPGeoInfo>
  geo_enabled: boolean
  sources: string[]
}

const MAX_BATCH_SIZE = 200

/** 后端统一 GeoIP 归属地查询 API（ip2region + DB-IP/MMDB） */
export const geoipApi = {
  lookup(ip: string): Promise<GeoLookupOneResponse> {
    return request<GeoLookupOneResponse>(`/geoip/lookup?ip=${encodeURIComponent(ip)}`)
  },

  async lookupBatch(ips: string[]): Promise<GeoLookupBatchResponse> {
    const unique = [...new Set(ips.map((s) => s.trim()).filter(Boolean))]
    if (unique.length === 0) {
      return { items: {}, geo_enabled: true, sources: [] }
    }
    if (unique.length <= MAX_BATCH_SIZE) {
      return request<GeoLookupBatchResponse>('/geoip/lookup', {
        method: 'POST',
        body: { ips: unique },
      })
    }
    const merged: Record<string, IPGeoInfo> = {}
    let geoEnabled = false
    let sources: string[] = []
    for (let i = 0; i < unique.length; i += MAX_BATCH_SIZE) {
      const chunk = unique.slice(i, i + MAX_BATCH_SIZE)
      const res = await request<GeoLookupBatchResponse>('/geoip/lookup', {
        method: 'POST',
        body: { ips: chunk },
      })
      Object.assign(merged, res.items)
      geoEnabled = geoEnabled || res.geo_enabled
      if (res.sources?.length) sources = res.sources
    }
    return { items: merged, geo_enabled: geoEnabled, sources }
  },
}
