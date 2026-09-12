// 必须在 mmdb-lib 之前求值：mmdb-lib 模块顶层引用全局 Buffer
import './bufferPolyfill'
import { Buffer } from 'buffer'
import { Reader } from 'mmdb-lib'
import type { CountryResponse } from 'mmdb-lib/lib/reader/response'

/**
 * 离线 IP 归属地查询（mmdb 部分）。
 *
 * 数据源（均已在 THIRD_PARTY_NOTICES.md 登记并归档 licenses/）：
 * - city-ipv6.mmdb：DB-IP City Lite（CC BY 4.0，需署名——大屏地球面板已带链接），
 *   仅用于 IPv6 的城市级定位（纯真库无 IPv6 数据）；
 * - country.mmdb：@ip-location-db/geo-whois-asn-country（CC0；NRO 统计数据 CC-BY-4.0），
 *   IPv4+IPv6，仅国家代码，用作城市库未命中时的回退。
 *
 * IPv4 的城市级定位由纯真库承担（见 pages/big-screen/components/qqwryGeo.ts），
 * 本模块不再加载 IPv4 城市库。
 *
 * 仅用于大屏可视化的攻击来源定位，不参与任何防护判定。
 */

const COUNTRY_MMDB_URL = '/assets/geo/country.mmdb'
const CITY_IPV6_MMDB_URL = '/assets/geo/city-ipv6.mmdb'

/** geo-whois-asn-country 记录结构（非 MaxMind 标准 CountryResponse，仅顶层 country_code） */
interface IpLocationDbCountryRecord {
  country_code?: string
}

/** DB-IP City Lite 记录结构 */
interface DbIpCityRecord {
  country_code?: string
  state1?: string
  state2?: string
  city?: string
  latitude?: number
  longitude?: number
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

/** 从 DB-IP 城市库记录构造 GeoPoint；无国家代码返回 null */
function cityRecordToGeo(rec: DbIpCityRecord | null): GeoPoint | null {
  if (!rec?.country_code) return null
  const hasCoord =
    typeof rec.latitude === 'number' &&
    typeof rec.longitude === 'number' &&
    !(rec.latitude === 0 && rec.longitude === 0)
  return {
    countryCode: rec.country_code,
    city: rec.city ?? '',
    state: rec.state1 ?? '',
    location: hasCoord ? [rec.longitude!, rec.latitude!] : null,
  }
}

/**
 * 查询 IP 的归属地（mmdb 链）。
 * IPv6 走城市库（城市级）；IPv4 仅作纯真库未命中时的国家代码回退。
 * 城市库未命中或加载失败时回退国家库（location 为 null）。
 */
export async function lookupGeo(ip: string): Promise<GeoPoint | null> {
  if (!isPublicIp(ip)) return null
  if (ip.includes(':')) {
    const reader = await cityV6Reader()
    if (reader) {
      try {
        const geo = cityRecordToGeo(reader.get(ip) as unknown as DbIpCityRecord | null)
        if (geo) return geo
      } catch {
        // 单个 IP 查询失败回退国家库
      }
    }
  }
  const fallback = await countryReader()
  if (!fallback) return null
  try {
    const rec = fallback.get(ip) as unknown as IpLocationDbCountryRecord | null
    if (!rec?.country_code) return null
    return { countryCode: rec.country_code, city: '', state: '', location: null }
  } catch {
    return null
  }
}
