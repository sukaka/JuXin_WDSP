import { geoipApi } from '../../api/geoip'
import type { IPGeoInfo } from '../../types'
import { countryNameZh, isPublicIp, lookupGeo } from '../../utils/ipgeo'
import type { GeoPoint } from '../../utils/ipgeo'
import { cnLocationCoords } from './components/cnCoords'
import { DEMO_ATTACK_ROUTES } from './components/demoGlobe'
import { getCountryCentroids } from './components/geoData'
import type { GlobeRoute } from './components/GlobeAttackMap'

/** 一条攻击路线（来源地 → 防护目标） */
export interface AttackRoute {
  /** ISO 3166-1 alpha-2 国家代码 */
  country: string
  /** 城市名（城市级 GeoIP 命中时非空；空串表示仅定位到国家） */
  city: string
  /** 来源坐标 [经度, 纬度]：城市级为真实坐标，否则回退国家质心 */
  from: [number, number]
  /** 该来源地的攻击事件数 */
  count: number
  /** 该来源地出现过的最高严重级别（HIGH/MEDIUM/LOW/INFO） */
  severity: string
  /** 来源地展示名（城市中文名或国家中文名；线上聚合时填充） */
  name?: string
}

const SEVERITY_RANK: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 }
const GREATER_CHINA = new Set(['CN', 'HK', 'MO', 'TW'])

/** 将后端统一 GeoIP 引擎返回的 IPGeoInfo 转为大屏弧线 GeoPoint */
export function geoInfoToGeoPoint(info: IPGeoInfo | null | undefined): GeoPoint | null {
  if (!info || info.scope !== 'PUBLIC') return null
  const countryCode = (info.country_code ?? '').trim().toUpperCase()
  if (!countryCode) return null

  const province = (info.province ?? '').trim()
  const city = (info.city ?? '').trim()
  let location: [number, number] | null = null
  if (
    typeof info.longitude === 'number' &&
    typeof info.latitude === 'number' &&
    !Number.isNaN(info.longitude) &&
    !Number.isNaN(info.latitude) &&
    !(info.longitude === 0 && info.latitude === 0)
  ) {
    location = [info.longitude, info.latitude]
  } else if (GREATER_CHINA.has(countryCode)) {
    location = cnLocationCoords(province, city)
  }

  return {
    countryCode,
    city: city || (GREATER_CHINA.has(countryCode) ? province : ''),
    state: province,
    location,
  }
}

/**
 * 攻击事件 → 攻击路线聚合（纯函数，便于测试）。
 * resolve 把 IP 映射为城市级归属地（返回 null 表示内网/未识别）；
 * 无坐标的结果（库缺坐标）按国家质心回退，centroids 提供国家质心。
 */
export function aggregateAttackRoutes(
  items: { client_ip: string; severity: string }[],
  resolve: (ip: string) => GeoPoint | null,
  centroids: Map<string, [number, number]>,
): AttackRoute[] {
  const byPlace = new Map<string, { route: AttackRoute }>()
  for (const item of items) {
    const geo = resolve(item.client_ip)
    if (!geo) continue
    const from = geo.location ?? centroids.get(geo.countryCode) ?? null
    if (!from) continue
    // 有城市名按「国家+城市」聚合（同一坐标系下的不同城市分开成弧），否则按国家
    const key = geo.city ? `${geo.countryCode}:${geo.city}` : geo.countryCode
    let entry = byPlace.get(key)
    if (!entry) {
      entry = {
        route: { country: geo.countryCode, city: geo.city, from, count: 0, severity: 'INFO' },
      }
      byPlace.set(key, entry)
    }
    entry.route.count += 1
    if ((SEVERITY_RANK[item.severity] ?? 0) > (SEVERITY_RANK[entry.route.severity] ?? 0)) {
      entry.route.severity = item.severity
    }
  }
  return [...byPlace.values()].map((e) => e.route).sort((a, b) => b.count - a.count)
}

/**
 * 线上版聚合：
 * 1. 优先复用安全事件列表已携带的 client_ip_geo（零额外请求）；
 * 2. 对未附带归属地的公网 IP 统一调用后端批量 GeoIP 接口（ip2region + DB-IP/MMDB）；
 * 3. 若后端接口失败或后端未加载离线库（geo_enabled=false），自动回退浏览器端 MMDB 降级链。
 */
export async function buildAttackRoutes(
  items: { client_ip: string; severity: string; client_ip_geo?: IPGeoInfo | null }[],
): Promise<AttackRoute[]> {
  const resolved = new Map<string, GeoPoint | null>()
  const missingPublicIps: string[] = []
  const seenMissing = new Set<string>()

  for (const item of items) {
    const ip = item.client_ip?.trim()
    if (!ip) continue
    if (item.client_ip_geo && !resolved.has(ip)) {
      const pt = geoInfoToGeoPoint(item.client_ip_geo)
      if (pt || item.client_ip_geo.scope !== 'PUBLIC') {
        resolved.set(ip, pt)
        continue
      }
    }
    if (!resolved.has(ip) && !seenMissing.has(ip)) {
      if (!isPublicIp(ip)) {
        resolved.set(ip, null)
      } else {
        seenMissing.add(ip)
        missingPublicIps.push(ip)
      }
    }
  }

  let needBrowserFallbackIps: string[] = []
  if (missingPublicIps.length > 0) {
    try {
      const batch = await geoipApi.lookupBatch(missingPublicIps)
      if (batch.geo_enabled) {
        for (const ip of missingPublicIps) {
          const pt = geoInfoToGeoPoint(batch.items?.[ip])
          if (pt) {
            resolved.set(ip, pt)
          } else {
            needBrowserFallbackIps.push(ip)
          }
        }
      } else {
        needBrowserFallbackIps = missingPublicIps
      }
    } catch {
      // 后端批量查询失败时降级回退浏览器端离线 MMDB
      needBrowserFallbackIps = missingPublicIps
    }
  }

  if (needBrowserFallbackIps.length > 0) {
    await Promise.all(
      needBrowserFallbackIps.map(async (ip) => {
        resolved.set(ip, await lookupGeo(ip))
      }),
    )
  }

  return aggregateAttackRoutes(
    items,
    (ip) => resolved.get(ip?.trim()) ?? null,
    getCountryCentroids(),
  ).map((r) => ({
    ...r,
    name: r.city || countryNameZh(r.country),
  }))
}

/** 演示攻击路线（真实路线为空或过稀疏时兜底）：坐标为 Natural Earth 真实国家质心 */
export function buildDemoAttackRoutes(): GlobeRoute[] {
  const centroids = getCountryCentroids()
  return DEMO_ATTACK_ROUTES.flatMap((d) => {
    const from = centroids.get(d.country)
    return from ? [{ name: countryNameZh(d.country), from, count: d.count, color: d.color }] : []
  })
}
