// 必须在 mmdb-lib 之前求值：mmdb-lib 模块顶层引用全局 Buffer
import './bufferPolyfill'
import { Buffer } from 'buffer'
import * as isoCountries from 'i18n-iso-countries'
import zhLocale from 'i18n-iso-countries/langs/zh.json'
import { Reader } from 'mmdb-lib'
import type { CountryResponse } from 'mmdb-lib/lib/reader/response'
import type { IPGeoInfo } from '../types'

isoCountries.registerLocale(zhLocale)

/**
 * 离线 IP 归属地查询（浏览器端 MMDB 降级回退链与辅助格式化）。
 *
 * 主查询链路：由后端统一 GeoIP 引擎（ip2region XDB + DB-IP Lite / MMDB，见 server/internal/apigeo）
 * 通过 /api/v1/geoip/lookup 与事件/访问日志响应直接提供。
 *
 * 本模块保留浏览器端离线 MMDB 解析作为大屏接口不可用时的降级兜底，并兼容两套 MMDB 记录格式：
 * - sapics/ip-location-db 扁平结构（country_code / state1 / city / latitude / longitude）
 * - DB-IP 官方 / MaxMind GeoIP2 嵌套结构（country.iso_code / subdivisions / city / location）
 *
 * 数据源（均已在 THIRD_PARTY_NOTICES.md 登记并归档 licenses/）：
 * - city-ipv6.mmdb：DB-IP City Lite（CC BY 4.0，需署名——大屏地球面板已带链接）
 * - country.mmdb：@ip-location-db/geo-whois-asn-country（CC0；NRO 统计数据 CC-BY-4.0）
 *
 * 仅用于大屏可视化的攻击来源定位，不参与任何防护判定。
 */

const COUNTRY_MMDB_URL = '/assets/geo/country.mmdb'
const CITY_IPV6_MMDB_URL = '/assets/geo/city-ipv6.mmdb'

interface GeoNamesMap {
  'zh-CN'?: string
  zh_CN?: string
  zh?: string
  en?: string
  [lang: string]: string | undefined
}

/** 兼容 sapics 扁平记录与官方 DB-IP / MaxMind GeoIP2 嵌套记录 */
export interface MmdbGeoRecord {
  // sapics 扁平字段
  country_code?: string
  state1?: string
  state2?: string
  city?: string | { names?: GeoNamesMap }
  latitude?: number
  longitude?: number
  // DB-IP 官方 / MaxMind GeoIP2 嵌套字段
  country?: { iso_code?: string; names?: GeoNamesMap }
  registered_country?: { iso_code?: string; names?: GeoNamesMap }
  subdivisions?: Array<{ iso_code?: string; names?: GeoNamesMap }>
  location?: { latitude?: number; longitude?: number }
}

/** 一次归属地查询的结果；location 为 [经度, 纬度]，缺失（回退/无坐标）时为 null */
export interface GeoPoint {
  countryCode: string
  /** 城市名（可能为空串：库中无更细粒度数据） */
  city: string
  /** 省份/州（可能为空串） */
  state: string
  location: [number, number] | null
}

type AnyReader = Reader<CountryResponse>

let countryReaderPromise: Promise<AnyReader | null> | null = null
let cityV6ReaderPromise: Promise<AnyReader | null> | null = null

function loadReader(url: string): Promise<AnyReader | null> {
  return (async () => {
    try {
      const resp = await fetch(url)
      if (!resp.ok) return null
      const buf = await resp.arrayBuffer()
      return new Reader<CountryResponse>(Buffer.from(buf))
    } catch {
      // 数据文件缺失或损坏时降级为无定位（不影响大屏其余功能）
      return null
    }
  })()
}

function countryReader(): Promise<AnyReader | null> {
  if (!countryReaderPromise) countryReaderPromise = loadReader(COUNTRY_MMDB_URL)
  return countryReaderPromise
}

function cityV6Reader(): Promise<AnyReader | null> {
  if (!cityV6ReaderPromise) cityV6ReaderPromise = loadReader(CITY_IPV6_MMDB_URL)
  return cityV6ReaderPromise
}

function pickLocalizedName(names?: GeoNamesMap): string {
  if (!names) return ''
  for (const k of ['zh-CN', 'zh_CN', 'zh', 'en'] as const) {
    const val = names[k]?.trim()
    if (val) return val
  }
  return ''
}

/** alpha-2 → 中文国家名（i18n-iso-countries 中文 locale，未知名返回原代码） */
export function countryNameZh(alpha2: string): string {
  const code = alpha2.trim().toUpperCase()
  if (!code) return ''
  return isoCountries.getName(code, 'zh') ?? code
}

/** 格式化归属地与运营商展示文本（安全事件与访问日志共用） */
export function formatGeoDisplay(geo?: IPGeoInfo | null): { location: string; isp: string } {
  if (!geo) return { location: '', isp: '' }
  const location = geo.label?.trim() || (geo.country_code ? countryNameZh(geo.country_code) : '')
  const isp = geo.isp?.trim() || ''
  return { location, isp }
}

/** 判断是否为公网地址（内网/保留地址不做归属地定位） */
export function isPublicIp(ip: string): boolean {
  if (ip.includes(':')) {
    // IPv6：排除环回、链路本地、ULA、未指定
    const head = ip.split(':')[0].toLowerCase()
    return !(head === '' || head === '::1' || head === '1' || /^f[cdef]/.test(head) || head === 'fe80')
  }
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false
  const [a, b] = parts
  if (a === 10 || a === 127 || a === 0) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  if (a === 169 && b === 254) return false
  if (a >= 224) return false // 组播/保留
  if (a === 100 && b >= 64 && b <= 127) return false // CGNAT
  return true
}

/** 查询 IP 的 ISO 3166-1 alpha-2 国家代码；内网/查询失败/库未加载返回 null */
export async function lookupCountry(ip: string): Promise<string | null> {
  const geo = await lookupGeo(ip)
  return geo?.countryCode ?? null
}

/** 从 MMDB 记录构造 GeoPoint（兼容 sapics 扁平结构与官方 DB-IP/MaxMind 嵌套结构） */
export function mmdbRecordToGeo(rec: MmdbGeoRecord | null | undefined): GeoPoint | null {
  if (!rec) return null
  const rawCode =
    rec.country_code || rec.country?.iso_code || rec.registered_country?.iso_code || ''
  const countryCode = rawCode.trim().toUpperCase()
  if (!countryCode) return null

  const state =
    pickLocalizedName(rec.subdivisions?.[0]?.names) || (rec.state1?.trim() ?? '')

  let city = ''
  if (typeof rec.city === 'string') {
    city = rec.city.trim()
  } else if (rec.city && typeof rec.city === 'object') {
    city = pickLocalizedName(rec.city.names)
  }

  const lat = typeof rec.location?.latitude === 'number' ? rec.location.latitude : rec.latitude
  const lon = typeof rec.location?.longitude === 'number' ? rec.location.longitude : rec.longitude
  const hasCoord =
    typeof lat === 'number' &&
    typeof lon === 'number' &&
    !Number.isNaN(lat) &&
    !Number.isNaN(lon) &&
    !(lat === 0 && lon === 0)

  return {
    countryCode,
    city,
    state,
    location: hasCoord ? [lon, lat] : null,
  }
}

/**
 * 查询 IP 的归属地（浏览器端 MMDB 降级回退链）。
 * IPv6 走城市库（城市级）；未命中或 IPv4 回退国家库（location 为 null）。
 */
export async function lookupGeo(ip: string): Promise<GeoPoint | null> {
  if (!isPublicIp(ip)) return null
  if (ip.includes(':')) {
    const reader = await cityV6Reader()
    if (reader) {
      try {
        const geo = mmdbRecordToGeo(reader.get(ip) as unknown as MmdbGeoRecord | null)
        if (geo) return geo
      } catch {
        // 单个 IP 查询失败回退国家库
      }
    }
  }
  const fallback = await countryReader()
  if (!fallback) return null
  try {
    return mmdbRecordToGeo(fallback.get(ip) as unknown as MmdbGeoRecord | null)
  } catch {
    return null
  }
}
