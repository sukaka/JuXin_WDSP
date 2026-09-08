import * as isoCountries from 'i18n-iso-countries'
import zhLocale from 'i18n-iso-countries/langs/zh.json'
import { lookupQqwry } from '../../../utils/qqwry'
import type { QqwryLocation } from '../../../utils/qqwry'
import type { GeoPoint } from '../../../utils/ipgeo'
import { cnLocationCoords } from './cnCoords'

isoCountries.registerLocale(zhLocale)

/** 纯真库省级字段 → ISO 3166-1 alpha-2（港澳台单独成码） */
const CN_REGION_ALPHA2: Record<string, string> = {
  香港: 'HK',
  澳门: 'MO',
  台湾: 'TW',
}

/** 中文国家名 → alpha-2：先精确匹配 i18n-iso-countries 中文名，再退化为包含匹配 */
function zhCountryToAlpha2(name: string): string | null {
  const exact = isoCountries.getAlpha2Code(name, 'zh')
  if (exact) return exact
  const names = isoCountries.getNames('zh')
  for (const [alpha2, zhName] of Object.entries(names)) {
    if (zhName.includes(name) || name.includes(zhName)) return alpha2
  }
  return null
}

/**
 * 纯真文字地址 → GeoPoint。
 * 中国条目形如「中国–江苏–南京」：城市坐标查表，未收录回退省级坐标；
 * 国外条目取首段国家名映射 alpha-2，坐标为空（由调用方回退国家质心）。
 */
export function qqwryLocationToGeo(loc: QqwryLocation): GeoPoint | null {
  const parts = loc.country.split(/[–—-]/).map((s) => s.trim()).filter(Boolean)
  if (parts.length === 0) return null
  if (parts[0] === '中国') {
    const region = parts[1] ?? ''
    const city = parts[2] ?? ''
    const location = cnLocationCoords(region, city)
    if (!location) return null
    return {
      countryCode: CN_REGION_ALPHA2[region] ?? 'CN',
      city: city || region,
      state: region,
      location,
    }
  }
  const alpha2 = zhCountryToAlpha2(parts[0])
  if (!alpha2) return null
  // 国外城市的中文名无坐标表，交给国家质心回退
  return { countryCode: alpha2, city: '', state: parts[1] ?? '', location: null }
}

/** alpha-2 → 中文国家名（i18n-iso-countries 中文 locale，未知名返回原代码） */
export function countryNameZh(alpha2: string): string {
  return isoCountries.getName(alpha2, 'zh') ?? alpha2
}

/** 纯真库查询 IPv4 归属地（城市级）；未收录/保留地址返回 null */
export async function lookupGeoByQqwry(ip: string): Promise<GeoPoint | null> {
  const loc = await lookupQqwry(ip)
  if (!loc) return null
  return qqwryLocationToGeo(loc)
}
