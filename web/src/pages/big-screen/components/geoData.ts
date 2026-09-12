import { feature } from 'topojson-client'
import type { Topology } from 'topojson-specification'
import { geoCentroid } from 'd3-geo'
import * as isoCountries from 'i18n-iso-countries'
import countries110m from 'world-atlas/countries-110m.json'
import type { FeatureCollection, Geometry } from 'geojson'

/**
 * 世界地图地理数据（Natural Earth 110m，公有领域；world-atlas/topojson-client/d3-geo 均为 ISC）。
 * 供攻击监控大屏的地球组件使用：底图纹理绘制 + 国家质心定位（攻击路线起点）。
 */

let featureCache: FeatureCollection<Geometry> | null = null
let centroidCache: Map<string, [number, number]> | null = null

/** 国家面要素集（GeoJSON），供 canvas 底图绘制 */
export function getCountryFeatures(): FeatureCollection<Geometry> {
  if (!featureCache) {
    const topo = countries110m as unknown as Topology
    featureCache = feature(topo, topo.objects.countries) as unknown as FeatureCollection<Geometry>
  }
  return featureCache
}

/** ISO 3166-1 alpha-2 国家代码 → 球面质心 [经度, 纬度]（world-atlas 的 id 为 ISO 数字代码） */
export function getCountryCentroids(): Map<string, [number, number]> {
  if (!centroidCache) {
    centroidCache = new Map()
    for (const f of getCountryFeatures().features) {
      const id = f.id != null ? String(f.id) : ''
      // N. Cyprus / Somaliland / Kosovo 无 ISO 数字代码，跳过（GeoIP 也不会返回这些区域）
      if (!id || id === '-99' || id === '99') continue
      const alpha2 = isoCountries.numericToAlpha2(id.padStart(3, '0'))
      if (!alpha2) continue
      centroidCache.set(alpha2, geoCentroid(f) as [number, number])
    }
  }
  return centroidCache
}
