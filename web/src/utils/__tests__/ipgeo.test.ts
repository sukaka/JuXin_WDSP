import { describe, expect, it } from 'vitest'
import { countryNameZh, formatGeoDisplay, mmdbRecordToGeo } from '../ipgeo'

describe('mmdbRecordToGeo', () => {
  it('兼容官方 DB-IP / MaxMind GeoIP2 嵌套记录结构', () => {
    const geo = mmdbRecordToGeo({
      country: { iso_code: 'nl', names: { en: 'Netherlands', 'zh-CN': '荷兰' } },
      subdivisions: [{ iso_code: 'NH', names: { en: 'North Holland', 'zh-CN': '北荷兰省' } }],
      city: { names: { en: 'Amsterdam', 'zh-CN': '阿姆斯特丹' } },
      location: { latitude: 52.3676, longitude: 4.9041 },
    })
    expect(geo).toEqual({
      countryCode: 'NL',
      state: '北荷兰省',
      city: '阿姆斯特丹',
      location: [4.9041, 52.3676],
    })
  })

  it('兼容 registered_country 回退与英文名称', () => {
    const geo = mmdbRecordToGeo({
      registered_country: { iso_code: 'US', names: { en: 'United States' } },
      city: { names: { en: 'Mountain View' } },
      location: { latitude: 37.4056, longitude: -122.0775 },
    })
    expect(geo).toEqual({
      countryCode: 'US',
      state: '',
      city: 'Mountain View',
      location: [-122.0775, 37.4056],
    })
  })

  it('兼容 sapics 扁平记录结构并忽略 (0,0) 坐标', () => {
    expect(
      mmdbRecordToGeo({
        country_code: 'JP',
        state1: 'Tokyo',
        city: 'Tokyo',
        latitude: 35.6762,
        longitude: 139.6503,
      }),
    ).toEqual({
      countryCode: 'JP',
      state: 'Tokyo',
      city: 'Tokyo',
      location: [139.6503, 35.6762],
    })

    expect(
      mmdbRecordToGeo({
        country_code: 'CN',
        latitude: 0,
        longitude: 0,
      }),
    ).toEqual({
      countryCode: 'CN',
      state: '',
      city: '',
      location: null,
    })
  })

  it('空记录或缺失国家码返回 null', () => {
    expect(mmdbRecordToGeo(null)).toBeNull()
    expect(mmdbRecordToGeo({})).toBeNull()
  })
})

describe('countryNameZh & formatGeoDisplay', () => {
  it('将 ISO alpha-2 映射为中文国家名', () => {
    expect(countryNameZh('CN')).toBe('中国')
    expect(countryNameZh('nl')).toBe('荷兰')
    expect(countryNameZh('US')).toBe('美国')
    expect(countryNameZh('ZZ')).toBe('ZZ')
  })

  it('格式化安全事件与访问日志归属地/运营商展示', () => {
    expect(
      formatGeoDisplay({
        ip: '202.96.128.86',
        scope: 'PUBLIC',
        country_code: 'CN',
        label: '中国 广东省 广州市',
        isp: '电信',
      }),
    ).toEqual({ location: '中国 广东省 广州市', isp: '电信' })

    expect(
      formatGeoDisplay({
        ip: '45.148.10.75',
        scope: 'PUBLIC',
        country_code: 'NL',
        label: '',
      }),
    ).toEqual({ location: '荷兰', isp: '' })

    expect(formatGeoDisplay(null)).toEqual({ location: '', isp: '' })
  })
})
