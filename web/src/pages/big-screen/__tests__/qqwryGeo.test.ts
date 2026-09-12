import { describe, expect, it } from 'vitest'
import { qqwryLocationToGeo } from '../components/qqwryGeo'
import { CN_PROVINCE_COORDS, CN_CITY_COORDS } from '../components/cnCoords'

describe('qqwryLocationToGeo', () => {
  it('中国城市级：精确到城市坐标', () => {
    const geo = qqwryLocationToGeo({ country: '中国–江苏–南京', area: '电信' })
    expect(geo).toEqual({
      countryCode: 'CN',
      city: '南京',
      state: '江苏',
      location: CN_CITY_COORDS['南京'],
    })
  })

  it('中国未收录城市回退省级坐标', () => {
    const geo = qqwryLocationToGeo({ country: '中国–江苏–某某县', area: '' })
    expect(geo?.countryCode).toBe('CN')
    expect(geo?.location).toEqual(CN_PROVINCE_COORDS['江苏'])
  })

  it('直辖市无城市段时用省级名', () => {
    const geo = qqwryLocationToGeo({ country: '中国–北京–北京', area: '联通' })
    expect(geo?.countryCode).toBe('CN')
    expect(geo?.location).toEqual(CN_PROVINCE_COORDS['北京'])
  })

  it('港澳台映射独立代码', () => {
    expect(qqwryLocationToGeo({ country: '中国–香港', area: '' })?.countryCode).toBe('HK')
    expect(qqwryLocationToGeo({ country: '中国–澳门', area: '' })?.countryCode).toBe('MO')
    expect(qqwryLocationToGeo({ country: '中国–台湾', area: '' })?.countryCode).toBe('TW')
  })

  it('国外条目映射 alpha-2、坐标留空（由国家质心回退）', () => {
    const geo = qqwryLocationToGeo({ country: '美国–加利福尼亚州–山景城', area: '谷歌' })
    expect(geo?.countryCode).toBe('US')
    expect(geo?.location).toBeNull()
    expect(qqwryLocationToGeo({ country: '澳大利亚', area: '' })?.countryCode).toBe('AU')
  })

  it('无法识别的位置返回 null', () => {
    expect(qqwryLocationToGeo({ country: '局域网', area: 'IP' })).toBeNull()
    expect(qqwryLocationToGeo({ country: '', area: '' })).toBeNull()
  })
})
