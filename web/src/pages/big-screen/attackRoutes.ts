import { lookupGeo, isPublicIp } from '../../utils/ipgeo'
import type { GeoPoint } from '../../utils/ipgeo'
import { lookupGeoByQqwry, countryNameZh } from './components/qqwryGeo'
import { getCountryCentroids } from './components/geoData'
import { DEMO_ATTACK_ROUTES } from './components/demoGlobe'
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

/**
 * 攻击事件 → 攻击路线聚合（纯函数，便于测试）。
 * resolve 把 IP 映射为城市级归属地（返回 null 表示内网/未识别）；
 * 无坐标的结果（IPv6/库缺坐标）按国家质心回退，centroids 提供国家质心。
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

/** 单个 IP 解析：IPv4 优先纯真库（中国城市级准确），IPv6 走 DB-IP 城市库；均未命中回退国家库 */
async function resolveIp(ip: string): Promise<GeoPoint | null> {
  if (!isPublicIp(ip)) return null
  if (ip.includes(':')) return lookupGeo(ip)
  const geo = await lookupGeoByQqwry(ip)
  if (geo) return geo
  return lookupGeo(ip)
}

/** 线上版聚合：离线城市级 GeoIP 查询 + 国家质心回退；GeoIP 库不可用时返回空 */
export async function buildAttackRoutes(
  items: { client_ip: string; severity: string }[],
): Promise<AttackRoute[]> {
  // 预取所有 IP，第一个请求会触发各库懒加载；库缺失时 resolveIp 恒为 null
  const resolved = new Map<string, GeoPoint | null>()
  await Promise.all(
    [...new Set(items.map((i) => i.client_ip))].map(async (ip) => {
      resolved.set(ip, await resolveIp(ip))
    }),
  )
  return aggregateAttackRoutes(items, (ip) => resolved.get(ip) ?? null, getCountryCentroids()).map((r) => ({
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
